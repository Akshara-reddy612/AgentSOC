"""
perception/sse.py

Structural Simulation Engine (SSE) — a non-LLM, pure graph-traversal
feasibility checker for MITRE ATT&CK technique hypotheses.

The SSE answers: "Given account A on source host S, can technique T be
executed against target host T using the paths available in the
KnowledgeStoreGraph?"

SECURITY INVARIANT:
    The public check() method accepts ONLY plain string identifiers
    (account_id, source_host_id, target_host_id, technique_id) — NEVER
    Evidence objects or raw alert text.  An isinstance guard raises
    TypeError immediately if Evidence is detected, making the
    contamination path structurally impossible.  This mirrors the exact
    pattern in perception/derived_context_rules.py's
    _require_immutable_context guard.

Classification rules:
    - FEASIBLE: a structurally complete path match with compounded
      confidence >= 0.5
    - CONDITIONALLY_FEASIBLE: a structurally complete path match
      (correct edge types, correct order, all required hops present)
      whose compounded confidence < 0.5
    - INFEASIBLE: no structurally valid path exists — either no path
      at all, or existing paths fail to match the technique's required
      edge sequence.  Partial / malformed matches are ALWAYS INFEASIBLE
      regardless of any individual edge's confidence.
      Exception (2026-10-11, open world): when the environment profile lists
      the hosts the store learns from (observed_hosts) and the target is not
      one of them, a missing path is CONDITIONALLY_FEASIBLE, not INFEASIBLE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from itertools import product
from typing import Any

import networkx as nx

from perception.knowledge_graph import (
    AccessLevel,
    KnowledgeStoreGraph,
    account_node_id,
    host_node_id,
)
from perception.knowledge_store import KnowledgeFact
from perception.models import Evidence  # Imported ONLY for the isinstance guard


# ---------------------------------------------------------------------------
# EdgeConstraint
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EdgeConstraint:
    """
    Constraint on a single graph edge for technique matching.

    Attributes:
        edge_type:         Required edge type (e.g. "GRANTS", "MEMBER_OF")
        min_access_level:  If set, the edge's access_level must be >= this
        port:              If set, the edge's port must equal this
    """
    edge_type: str
    min_access_level: AccessLevel | None = None
    port: int | None = None

    def matches(self, edge_data: dict[str, Any]) -> bool:
        """Check if a graph edge's data satisfies this constraint."""
        if edge_data.get("edge_type") != self.edge_type:
            return False

        if self.min_access_level is not None:
            al = edge_data.get("access_level")
            if al is None:
                return False
            if isinstance(al, KnowledgeFact):
                al = al.value
            if not isinstance(al, AccessLevel):
                return False
            if al < self.min_access_level:
                return False

        if self.port is not None:
            p = edge_data.get("port")
            if p is None:
                return False
            if isinstance(p, KnowledgeFact):
                p = p.value
            if p != self.port:
                return False

        return True


# ---------------------------------------------------------------------------
# TechniqueConstraint
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TechniqueConstraint:
    """
    MITRE ATT&CK technique expressed as graph-path constraints.

    Attributes:
        technique_id:     MITRE ATT&CK ID (e.g. "T1078")
        description:      Human-readable technique name
        valid_sequences:  Tuple of alternative edge-constraint sequences.
                          Each inner tuple is a complete valid edge pattern
                          from account → target_host.  ANY one matching
                          constitutes a structural match.  Supports both
                          direct (1-edge) and group-mediated (2-edge) paths
                          within the same technique definition — no need for
                          duplicate technique entries.
        egress_ports:     If set, additionally requires EGRESS between
                          source and target zones on one of these ports.
        egress_to_any:    If True, check EGRESS from source zone to ANY
                          zone (not just the target's zone).  Used for C2
                          techniques where the target is external.
    """
    technique_id: str
    description: str
    valid_sequences: tuple[tuple[EdgeConstraint, ...], ...]
    egress_ports: tuple[int, ...] | None = None
    egress_to_any: bool = False
    # Added 2026-10-11 (design decision D6): no structural precondition the
    # graph can check (e.g. phishing, scripting).  SSE returns
    # CONDITIONALLY_FEASIBLE with a note, which routes to analyst review --
    # never ruled out structurally, never auto-approved.
    unconstrained: bool = False


# ---------------------------------------------------------------------------
# SSEVerdict & PathResult
# ---------------------------------------------------------------------------

class SSEVerdict(Enum):
    """Classification of a structural feasibility check."""
    FEASIBLE = "FEASIBLE"
    CONDITIONALLY_FEASIBLE = "CONDITIONALLY_FEASIBLE"
    INFEASIBLE = "INFEASIBLE"


@dataclass
class PathResult:
    """
    Result of a single path evaluation against a technique's constraints.

    Attributes:
        verdict:         FEASIBLE / CONDITIONALLY_FEASIBLE / INFEASIBLE
        path_confidence: Product of all traversed edges' KnowledgeFact
                         confidences.  0.0 for INFEASIBLE.
        edge_path:       Human-readable descriptions of each traversed edge.
        dependency_note: For CONDITIONALLY_FEASIBLE, names the lowest-
                         confidence edge the result hinges on.  For
                         INFEASIBLE, explains which precondition failed.
                         None for FEASIBLE.
    """
    verdict: SSEVerdict
    path_confidence: float
    edge_path: list[str]
    dependency_note: str | None
    # T1071 only (added 2026-10-10): "verified" / "unverified" destination,
    # and the destination's reputation from the synthetic network model.
    destination_status: str | None = None
    destination_reputation: str | None = None


# ---------------------------------------------------------------------------
# compute_path_confidence — independently testable helper
# ---------------------------------------------------------------------------

def compute_path_confidence(edge_confidences: list[float]) -> float:
    """
    Compute path confidence by multiplying all edge confidences.

    This is the canonical confidence compounding function — NOT average,
    NOT max, strictly multiplicative.  Each traversed edge's uncertainty
    compounds, so longer paths through low-confidence edges yield lower
    overall confidence.

    Args:
        edge_confidences: Confidence values from each traversed edge.

    Returns:
        Product of all confidences.  Returns 1.0 for an empty list
        (vacuously true — no edges = no uncertainty).
    """
    result = 1.0
    for c in edge_confidences:
        result *= c
    return result


# ---------------------------------------------------------------------------
# _edge_confidence — extract primary confidence from a graph edge
# ---------------------------------------------------------------------------

def _edge_confidence(edge_data: dict[str, Any]) -> float:
    """
    Extract the primary KnowledgeFact confidence from a graph edge.

    Each edge type has a designated primary attribute whose KnowledgeFact
    confidence represents the overall reliability of that edge:
        GRANTS           -> access_level.confidence
        HAS_PRIOR_ACCESS -> has_access.confidence
        EGRESS           -> reachable.confidence
        MEMBER_OF        -> membership_fact.confidence
        HOSTED_IN, etc.  -> 1.0 (structural, always trusted)
    """
    edge_type = edge_data.get("edge_type", "")

    if edge_type == "GRANTS":
        kf = edge_data.get("access_level")
    elif edge_type == "HAS_PRIOR_ACCESS":
        kf = edge_data.get("has_access")
    elif edge_type == "EGRESS":
        kf = edge_data.get("reachable")
    elif edge_type == "MEMBER_OF":
        kf = edge_data.get("membership_fact")
    else:
        return 1.0  # Structural edges

    if isinstance(kf, KnowledgeFact):
        return kf.confidence
    return 1.0


# ---------------------------------------------------------------------------
# Technique table — 7 real MITRE ATT&CK techniques
# ---------------------------------------------------------------------------

TECHNIQUE_TABLE: dict[str, TechniqueConstraint] = {

    # T1078 — Valid Accounts
    # Precondition: the account has existing access (prior access baseline
    # or a direct/group-mediated grant) to the target host.
    "T1078": TechniqueConstraint(
        technique_id="T1078",
        description="Valid Accounts — use of legitimate credentials",
        valid_sequences=(
            (EdgeConstraint("HAS_PRIOR_ACCESS"),),
            (EdgeConstraint("GRANTS", min_access_level=AccessLevel.READ),),
            (EdgeConstraint("MEMBER_OF"),
             EdgeConstraint("GRANTS", min_access_level=AccessLevel.READ)),
        ),
    ),

    # T1021.001 — Remote Desktop Protocol
    # Precondition: account has RDP-level access to target AND network
    # path allows port 3389 between source and target zones.
    "T1021.001": TechniqueConstraint(
        technique_id="T1021.001",
        description="Remote Desktop Protocol — RDP lateral movement",
        valid_sequences=(
            (EdgeConstraint("GRANTS", min_access_level=AccessLevel.RDP),),
            (EdgeConstraint("MEMBER_OF"),
             EdgeConstraint("GRANTS", min_access_level=AccessLevel.RDP)),
        ),
        egress_ports=(3389,),
    ),

    # T1021.002 — SMB/Windows Admin Shares
    # Precondition: account has at least READ access AND network path
    # allows port 445 between source and target zones.
    "T1021.002": TechniqueConstraint(
        technique_id="T1021.002",
        description="SMB/Windows Admin Shares — SMB lateral movement",
        valid_sequences=(
            (EdgeConstraint("GRANTS", min_access_level=AccessLevel.READ),),
            (EdgeConstraint("MEMBER_OF"),
             EdgeConstraint("GRANTS", min_access_level=AccessLevel.READ)),
        ),
        egress_ports=(445,),
    ),

    # T1550 — Use Alternate Authentication Material (Pass-the-Hash)
    # Precondition: account has ADMIN-level access to target (hash
    # reuse requires local admin to extract/inject credentials).
    # No egress check — this is a local credential abuse technique.
    "T1550": TechniqueConstraint(
        technique_id="T1550",
        description=(
            "Use Alternate Authentication Material — Pass-the-Hash / "
            "Pass-the-Ticket"
        ),
        valid_sequences=(
            (EdgeConstraint("GRANTS", min_access_level=AccessLevel.ADMIN),),
            (EdgeConstraint("MEMBER_OF"),
             EdgeConstraint("GRANTS", min_access_level=AccessLevel.ADMIN)),
        ),
    ),

    # T1484 — Domain Policy Modification
    # Precondition: account has DOMAIN_ADMIN-level access (only domain
    # admins can modify GPOs / domain-wide policies).
    "T1484": TechniqueConstraint(
        technique_id="T1484",
        description=(
            "Domain Policy Modification — requires domain admin access"
        ),
        valid_sequences=(
            (EdgeConstraint("GRANTS",
                            min_access_level=AccessLevel.DOMAIN_ADMIN),),
            (EdgeConstraint("MEMBER_OF"),
             EdgeConstraint("GRANTS",
                            min_access_level=AccessLevel.DOMAIN_ADMIN)),
        ),
    ),

    # T1071 — Application Layer Protocol (C2)
    # Precondition: source host's zone has outbound EGRESS on port 443
    # or 80 — the attacker needs a network path out.  No access-grant
    # requirement (the host is already compromised).
    "T1071": TechniqueConstraint(
        technique_id="T1071",
        description=(
            "Application Layer Protocol — C2 external communication"
        ),
        valid_sequences=(),  # No access grant required
        egress_ports=(443, 80),
        egress_to_any=True,
    ),

    # T1562 — Impair Defenses
    # Precondition: account has ADMIN-level access on the target host
    # (disabling AV / EDR requires local admin privileges).
    "T1562": TechniqueConstraint(
        technique_id="T1562",
        description=(
            "Impair Defenses — disable security tools on target host"
        ),
        valid_sequences=(
            (EdgeConstraint("GRANTS", min_access_level=AccessLevel.ADMIN),),
            (EdgeConstraint("MEMBER_OF"),
             EdgeConstraint("GRANTS", min_access_level=AccessLevel.ADMIN)),
        ),
    ),

    # --- Added 2026-10-11 (Phase 2, design decision D6): techniques host logs show ---

    # T1021.004 — Remote Services: SSH.  Account access + port 22 between zones.
    "T1021.004": TechniqueConstraint(
        technique_id="T1021.004",
        description="Remote Services: SSH — lateral movement over SSH",
        valid_sequences=(
            (EdgeConstraint("GRANTS", min_access_level=AccessLevel.READ),),
            (EdgeConstraint("MEMBER_OF"),
             EdgeConstraint("GRANTS", min_access_level=AccessLevel.READ)),
        ),
        egress_ports=(22,),
    ),

    # T1039 — Data from Network Shared Drive.  READ on the share host + SMB.
    "T1039": TechniqueConstraint(
        technique_id="T1039",
        description="Data from Network Shared Drive — collection from a file share",
        valid_sequences=(
            (EdgeConstraint("GRANTS", min_access_level=AccessLevel.READ),),
            (EdgeConstraint("MEMBER_OF"),
             EdgeConstraint("GRANTS", min_access_level=AccessLevel.READ)),
        ),
        egress_ports=(445,),
    ),

    # T1003 — OS Credential Dumping (e.g. LSASS memory).  ADMIN on the host.
    "T1003": TechniqueConstraint(
        technique_id="T1003",
        description="OS Credential Dumping — read credentials from memory or stores",
        valid_sequences=(
            (EdgeConstraint("GRANTS", min_access_level=AccessLevel.ADMIN),),
            (EdgeConstraint("MEMBER_OF"),
             EdgeConstraint("GRANTS", min_access_level=AccessLevel.ADMIN)),
        ),
    ),

    # T1210 — Exploitation of Remote Services (e.g. PrintNightmare).  A network
    # path to an exposed service; no account access is needed.
    "T1210": TechniqueConstraint(
        technique_id="T1210",
        description="Exploitation of Remote Services — exploit a service reachable on the network",
        valid_sequences=(),
        egress_ports=(445, 135, 139, 3389),
    ),

    # T1105 — Ingress Tool Transfer, T1041 — Exfiltration Over C2 Channel.
    # Need an internet route from the source host, like T1071.  (Trusted
    # destination handling and destination blocks remain T1071-only.)
    "T1105": TechniqueConstraint(
        technique_id="T1105",
        description="Ingress Tool Transfer — download tools from outside",
        valid_sequences=(),
        egress_ports=(443, 80),
        egress_to_any=True,
    ),
    "T1041": TechniqueConstraint(
        technique_id="T1041",
        description="Exfiltration Over C2 Channel — send collected data out",
        valid_sequences=(),
        egress_ports=(443, 80),
        egress_to_any=True,
    ),

    # No structural precondition the graph can check: decided on evidence,
    # routed to review (see TechniqueConstraint.unconstrained).
    "T1566": TechniqueConstraint(technique_id="T1566", description="Phishing — initial access by email",
                                 valid_sequences=(), unconstrained=True),
    "T1204": TechniqueConstraint(technique_id="T1204", description="User Execution — user opens a malicious file",
                                 valid_sequences=(), unconstrained=True),
    "T1059": TechniqueConstraint(technique_id="T1059",
                                 description="Command and Scripting Interpreter — PowerShell, cmd, scripts",
                                 valid_sequences=(), unconstrained=True),
    "T1547": TechniqueConstraint(technique_id="T1547",
                                 description="Boot or Logon Autostart Execution — persistence (e.g. Run keys)",
                                 valid_sequences=(), unconstrained=True),
    "T1005": TechniqueConstraint(technique_id="T1005", description="Data from Local System — local collection",
                                 valid_sequences=(), unconstrained=True),
}

# The vocabulary NCE was evaluated with until 2026-10-11 (corpus v2 results);
# prompts keep it unless a caller asks for the full table (design decision D6).
LEGACY_TECHNIQUES = ("T1078", "T1021.001", "T1021.002", "T1550", "T1484", "T1071", "T1562")


# ---------------------------------------------------------------------------
# StructuralSimulationEngine
# ---------------------------------------------------------------------------

class StructuralSimulationEngine:
    """
    Non-LLM graph-traversal feasibility checker for attack hypotheses.

    Given (account, source_host, target_host, technique), traverses the
    KnowledgeStoreGraph to determine whether the technique's MITRE ATT&CK
    preconditions are structurally satisfiable.

    SECURITY INVARIANT:
        check() accepts ONLY plain string identifiers.  An Evidence object
        passed as ANY argument triggers an immediate TypeError.  This is
        the load-bearing security claim — no attacker-controlled free-text
        can reach the graph traversal logic.
    """

    def __init__(self, graph_store: KnowledgeStoreGraph) -> None:
        self._graph_store = graph_store

    # ------------------------------------------------------------------
    # Security guard — mirrors _require_immutable_context exactly
    # ------------------------------------------------------------------

    @staticmethod
    def _reject_evidence(*args: Any) -> None:
        """
        SECURITY INVARIANT — Evidence objects must NEVER reach the SSE.

        The Structural Simulation Engine operates exclusively on resolved
        identifiers (plain strings: account_id, host_id, technique_id) —
        NEVER on Evidence objects containing attacker-controllable
        free-text fields.

        This guard mirrors the exact pattern in
        perception/derived_context_rules.py's _require_immutable_context:
        an explicit isinstance() check that raises TypeError immediately
        if any argument is an Evidence object, making the contamination
        path structurally impossible.

        This is the load-bearing security claim of the SSE module: because
        check() only accepts plain string identifiers and this guard
        rejects Evidence at the gate, no amount of prompt injection in
        the alert's free-text fields can influence graph traversal logic.
        """
        for i, arg in enumerate(args):
            if isinstance(arg, Evidence):
                raise TypeError(
                    f"StructuralSimulationEngine.check() argument {i} is an "
                    f"Evidence object.  SSE MUST receive only plain string "
                    f"identifiers (account_id, host_id, technique_id) — "
                    f"NEVER Evidence.  Passing Evidence into SSE is a "
                    f"security violation that would allow attacker-controlled "
                    f"data to influence graph traversal."
                )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        account_id: str,
        source_host_id: str,
        target_host_id: str,
        technique_id: str,
        trusted_destination: str | None = None,
    ) -> list[PathResult]:
        """
        Check whether ``technique_id`` is structurally feasible for
        ``account_id`` from ``source_host_id`` against ``target_host_id``.

        Returns ALL matching paths (not just the first), each classified:
            - FEASIBLE          if path_confidence >= 0.5
            - CONDITIONALLY_FEASIBLE  if path_confidence < 0.5
        If no structurally valid paths exist, returns a single INFEASIBLE
        PathResult with a populated failure reason.

        Args:
            account_id:      Plain string — the acting account.
            source_host_id:  Plain string — the host the attack originates from.
            target_host_id:  Plain string — the target host.
            technique_id:    MITRE ATT&CK ID (e.g. "T1078").
            trusted_destination: Optional destination IP/domain from TRUSTED
                             network telemetry (never from LLM output or log
                             text).  Used only by T1071.  When absent, a T1071
                             result is marked destination_status="unverified".

        Raises:
            TypeError: If any argument is an Evidence object.
        """
        # --- Security gate ---
        self._reject_evidence(
            account_id, source_host_id, target_host_id, technique_id,
            trusted_destination,
        )

        # --- Lookup technique ---
        constraint = TECHNIQUE_TABLE.get(technique_id)
        if constraint is None:
            return [PathResult(
                verdict=SSEVerdict.INFEASIBLE,
                path_confidence=0.0,
                edge_path=[],
                dependency_note=f"Unknown technique: {technique_id!r}",
            )]
        if constraint.unconstrained:
            return [PathResult(
                verdict=SSEVerdict.CONDITIONALLY_FEASIBLE,
                path_confidence=0.0,
                edge_path=[],
                dependency_note=(
                    f"{technique_id} ({constraint.description}) has no structural "
                    f"precondition the graph can check; it cannot be ruled in or "
                    f"out structurally. Requires analyst review."
                ),
            )]

        # --- Resolve nodes (lazy creation) ---
        acct_node = account_node_id(account_id)
        src_node = host_node_id(source_host_id)
        tgt_node = host_node_id(target_host_id)

        results: list[PathResult] = []

        # --- Find access paths ---
        if constraint.valid_sequences:
            access_paths = self._find_access_paths(
                acct_node, tgt_node, constraint.valid_sequences
            )

            for edge_descs, confidences in access_paths:
                # Check egress if required
                if constraint.egress_ports:
                    egress_ok, egress_conf, egress_desc = self._check_egress(
                        src_node, tgt_node,
                        constraint.egress_ports,
                        constraint.egress_to_any,
                    )
                    if not egress_ok:
                        continue
                    edge_descs = list(edge_descs) + [egress_desc]
                    confidences = list(confidences) + [egress_conf]

                path_conf = compute_path_confidence(confidences)
                results.append(self._classify_path(
                    edge_descs, path_conf, confidences
                ))

        elif constraint.egress_to_any:
            # Internet C2 (T1071): evaluated against the synthetic enterprise
            # network model (2026-10-10).  Replaces the old rule, which
            # accepted ANY outgoing 443/80 EGRESS edge (including the
            # WORKSTATION->WORKSTATION self-loop and WEB->DMZ).
            return [self._check_internet_c2(
                source_host_id, constraint, trusted_destination
            )]

        elif constraint.egress_ports:
            # Network-only technique without egress_to_any
            egress_ok, egress_conf, egress_desc = self._check_egress(
                src_node, tgt_node,
                constraint.egress_ports,
                constraint.egress_to_any,
            )
            if egress_ok:
                results.append(self._classify_path(
                    [egress_desc], egress_conf, [egress_conf]
                ))

        # --- Return results or INFEASIBLE ---
        if not results and self._target_observed(target_host_id) is False:
            # Open world (decision (a), 2026-10-11): the store has no logs from this
            # target, so a missing access path means "not known", not "impossible".
            return [PathResult(
                verdict=SSEVerdict.CONDITIONALLY_FEASIBLE,
                path_confidence=0.0,
                edge_path=[],
                dependency_note=(
                    f"{technique_id}: no access path in the store to {target_host_id!r}, but this "
                    f"environment ingests no telemetry from that host, so access cannot be ruled "
                    f"out structurally. Requires analyst review."
                ),
            )]
        if not results:
            return [PathResult(
                verdict=SSEVerdict.INFEASIBLE,
                path_confidence=0.0,
                edge_path=[],
                dependency_note=self._explain_failure(
                    acct_node, src_node, tgt_node, constraint
                ),
            )]

        return results

    def _target_observed(self, target_host_id: str) -> bool | None:
        """
        Whether the store learns from the target host's logs (the environment
        profile's observed_hosts); None when the profile does not model coverage
        (closed world).  An address is resolved to the inventory host that owns it.
        """
        profile = self._graph_store.profile
        if profile.observed_hosts is None:
            return None
        target = target_host_id.strip()
        for node, data in self._graph_store.graph.nodes(data=True):
            fact = data.get("ip_addresses")
            if isinstance(fact, KnowledgeFact) and target in fact.value:
                return profile.observes_host(str(data.get("host_id", node)))
        return profile.observes_host(target)

    # ------------------------------------------------------------------
    # Path-finding internals
    # ------------------------------------------------------------------

    def _find_access_paths(
        self,
        acct_node: str,
        tgt_node: str,
        valid_sequences: tuple[tuple[EdgeConstraint, ...], ...],
    ) -> list[tuple[list[str], list[float]]]:
        """
        Find all paths from ``acct_node`` to ``tgt_node`` that match any
        of the ``valid_sequences``.

        Returns list of (edge_descriptions, edge_confidences) tuples.
        """
        all_results: list[tuple[list[str], list[float]]] = []
        g = self._graph_store.graph

        for seq in valid_sequences:
            seq_len = len(seq)
            if seq_len == 0:
                continue

            # On a MultiDiGraph, all_simple_paths yields the same node path
            # once per parallel edge; the edge-combination product below
            # already covers parallel edges, so visit each node path once.
            # (Fixed 2026-10-10: duplicates inflated RSEM containment.)
            seen_node_paths: set[tuple[str, ...]] = set()
            try:
                for node_path in nx.all_simple_paths(
                    g, acct_node, tgt_node, cutoff=min(seq_len, 4)
                ):
                    if len(node_path) - 1 != seq_len:
                        continue  # Wrong number of edges
                    path_key = tuple(node_path)
                    if path_key in seen_node_paths:
                        continue
                    seen_node_paths.add(path_key)

                    # Collect all edge options between consecutive nodes
                    edge_options: list[list[tuple[str, dict[str, Any]]]] = []
                    for i in range(seq_len):
                        u, v = node_path[i], node_path[i + 1]
                        edges = g[u][v]  # {key: data_dict, ...}
                        edge_options.append(
                            [(k, d) for k, d in edges.items()]
                        )

                    # Try all combinations of edge choices
                    for combo in product(*edge_options):
                        matched = True
                        confidences: list[float] = []
                        edge_descs: list[str] = []

                        for idx, (key, data) in enumerate(combo):
                            if not seq[idx].matches(data):
                                matched = False
                                break
                            conf = _edge_confidence(data)
                            confidences.append(conf)
                            edge_descs.append(
                                f"{node_path[idx]} "
                                f"--[{data.get('edge_type', key)}]--> "
                                f"{node_path[idx + 1]}"
                            )

                        if matched:
                            all_results.append((edge_descs, confidences))

            except nx.NodeNotFound:
                continue

        return all_results

    def _check_egress(
        self,
        src_host_node: str,
        tgt_host_node: str,
        ports: tuple[int, ...],
        to_any: bool = False,
    ) -> tuple[bool, float, str]:
        """
        Check if EGRESS exists between source and target host zones.

        Returns (found, confidence, description).
        """
        g = self._graph_store.graph
        from perception.knowledge_graph import classify_host, _HOST_CLASS_DEFAULTS, HostClass, zone_node_id

        src_zone = self._graph_store.get_host_zone(src_host_node)
        if not src_zone:
            # Fall back to classification default without mutating the graph
            hostname = src_host_node.replace("host:", "")
            hclass, _ = classify_host(hostname)
            zstr = _HOST_CLASS_DEFAULTS.get(hclass, _HOST_CLASS_DEFAULTS[HostClass.UNKNOWN])["zone_id"]
            src_zone = zone_node_id(zstr)

        tgt_zone = self._graph_store.get_host_zone(tgt_host_node)
        if not tgt_zone:
            hostname = tgt_host_node.replace("host:", "")
            hclass, _ = classify_host(hostname)
            zstr = _HOST_CLASS_DEFAULTS.get(hclass, _HOST_CLASS_DEFAULTS[HostClass.UNKNOWN])["zone_id"]
            tgt_zone = zone_node_id(zstr)

        if not to_any and tgt_zone is None:
            return (False, 0.0, "")

        # Same zone — always reachable
        if not to_any and src_zone == tgt_zone:
            return (True, 1.0, f"Same zone: {src_zone}")

        best_conf = 0.0
        best_desc = ""
        found = False

        for u, v, data in g.out_edges(src_zone, data=True):
            if data.get("edge_type") != "EGRESS":
                continue
            if not to_any and v != tgt_zone:
                continue

            port_fact = data.get("port")
            port_val = (
                port_fact.value if isinstance(port_fact, KnowledgeFact)
                else port_fact
            )

            if port_val in ports:
                reachable = data.get("reachable")
                conf = (
                    reachable.confidence
                    if isinstance(reachable, KnowledgeFact)
                    else 1.0
                )
                if conf > best_conf:
                    best_conf = conf
                    best_desc = (
                        f"{u} --[EGRESS port={port_val}]--> {v}"
                    )
                    found = True

        return (found, best_conf, best_desc)

    # ------------------------------------------------------------------
    # Internet C2 (T1071) — synthetic enterprise network model
    # ------------------------------------------------------------------

    def _source_zone(self, source_host_id: str) -> str:
        """Zone node of the source host, without mutating the graph."""
        from perception.knowledge_graph import (
            _HOST_CLASS_DEFAULTS, HostClass, classify_host, zone_node_id,
        )
        src_node = host_node_id(source_host_id)
        zone = self._graph_store.get_host_zone(src_node) if src_node in self._graph_store.graph else None
        if zone:
            return zone
        hclass, _ = classify_host(source_host_id)
        zstr = _HOST_CLASS_DEFAULTS.get(hclass, _HOST_CLASS_DEFAULTS[HostClass.UNKNOWN])["zone_id"]
        return zone_node_id(zstr)

    def _check_internet_c2(
        self,
        source_host_id: str,
        constraint: TechniqueConstraint,
        trusted_destination: str | None,
    ) -> PathResult:
        """
        T1071 feasibility against the network model:

        1. The source host must resolve to a known zone.  An unresolvable or
           unclassifiable host (e.g. "unknown", an unmanaged asset) cannot be
           ruled in or out structurally -> CONDITIONALLY_FEASIBLE with
           confidence 0.0, flagged for analyst review (never a silent reject).
        2. A host whose internet egress was blocked (response action, on a
           graph copy) -> INFEASIBLE.
        3. The zone's egress policy must allow internet access and an EGRESS
           edge to zone:EXTERNAL on 443/80 must exist -> else INFEASIBLE.
        4. With a TRUSTED destination: internal -> INFEASIBLE; blocked by the
           zone policy (e.g. proxy denies known-bad) -> INFEASIBLE; otherwise
           FEASIBLE with the destination's reputation attached.
           Without one: FEASIBLE, destination_status="unverified".
        """
        from perception.knowledge_graph import zone_node_id
        from perception.network_model import INTERNAL, policy_permits

        g = self._graph_store.graph
        src_zone = self._source_zone(source_host_id)
        zone_id = g.nodes[src_zone].get("zone_id", src_zone.replace("zone:", "")) if src_zone in g else src_zone.replace("zone:", "")
        dest_status = "verified" if trusted_destination else "unverified"

        if zone_id == "UNKNOWN":
            return PathResult(
                verdict=SSEVerdict.CONDITIONALLY_FEASIBLE,
                path_confidence=0.0,
                edge_path=[],
                dependency_note=(
                    f"Source host {source_host_id!r} does not resolve to a known "
                    f"zone; internet reachability cannot be determined "
                    f"structurally. Requires analyst review."
                ),
                destination_status=dest_status,
            )

        src_node = host_node_id(source_host_id)
        if src_node in g and g.nodes[src_node].get("egress_blocked"):
            return PathResult(
                verdict=SSEVerdict.INFEASIBLE, path_confidence=0.0, edge_path=[],
                dependency_note=f"Internet egress blocked for {src_node} (response action).",
                destination_status=dest_status,
            )

        policy = self._graph_store.get_zone_egress_policy(src_zone)
        ext = zone_node_id("EXTERNAL")
        best_conf, best_desc = 0.0, ""
        if policy.get("mode", "none") != "none" and src_zone in g:
            for u, v, data in g.out_edges(src_zone, data=True):
                if data.get("edge_type") != "EGRESS" or v != ext:
                    continue
                port_fact = data.get("port")
                port = port_fact.value if isinstance(port_fact, KnowledgeFact) else port_fact
                if port not in (constraint.egress_ports or ()):
                    continue
                reach = data.get("reachable")
                conf = reach.confidence if isinstance(reach, KnowledgeFact) else 1.0
                if conf > best_conf:
                    best_conf, best_desc = conf, f"{u} --[EGRESS port={port}]--> {v}"
        if not best_desc:
            return PathResult(
                verdict=SSEVerdict.INFEASIBLE, path_confidence=0.0, edge_path=[],
                dependency_note=(
                    f"No internet route from {src_zone} (egress policy mode="
                    f"{policy.get('mode', 'none')!r}); C2 over 443/80 is not "
                    f"structurally possible from this host."
                ),
                destination_status=dest_status,
            )

        if trusted_destination is None:
            result = self._classify_path([best_desc], best_conf, [best_conf])
            result.destination_status = "unverified"
            result.dependency_note = (
                (result.dependency_note + " ") if result.dependency_note else ""
            ) + "Destination unverified: no trusted destination telemetry supplied."
            return result

        rep, rep_conf, rep_source = self._graph_store.get_destination_reputation(trusted_destination)
        if rep == INTERNAL:
            return PathResult(
                verdict=SSEVerdict.INFEASIBLE, path_confidence=0.0, edge_path=[best_desc],
                dependency_note=f"Destination {trusted_destination!r} is internal; not external C2.",
                destination_status="verified", destination_reputation=rep,
            )
        # The zone's policy as stored in the graph (from the environment profile),
        # the same one that allowed the internet route above.
        if rep == "blocked" or not policy_permits(policy, rep):
            return PathResult(
                verdict=SSEVerdict.INFEASIBLE, path_confidence=0.0, edge_path=[best_desc],
                dependency_note=(
                    f"Egress policy of zone {zone_id} blocks {rep} destination "
                    f"{trusted_destination!r} ({rep_source})."
                ),
                destination_status="verified", destination_reputation=rep,
            )
        dest_desc = f"{ext} --[destination {rep} ({rep_source})]--> {trusted_destination}"
        confs = [best_conf, rep_conf]
        result = self._classify_path([best_desc, dest_desc], compute_path_confidence(confs), confs)
        result.destination_status = "verified"
        result.destination_reputation = rep
        return result

    # ------------------------------------------------------------------
    # Classification helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_path(
        edge_descs: list[str],
        path_conf: float,
        confidences: list[float],
    ) -> PathResult:
        """Classify a structurally valid path by its compounded confidence."""
        if path_conf >= 0.5:
            return PathResult(
                verdict=SSEVerdict.FEASIBLE,
                path_confidence=path_conf,
                edge_path=list(edge_descs),
                dependency_note=None,
            )
        else:
            # Find the lowest-confidence edge
            min_idx = confidences.index(min(confidences))
            dep_note = (
                f"Low-confidence edge "
                f"(confidence={confidences[min_idx]:.2f}): "
                f"{edge_descs[min_idx]}"
            )
            return PathResult(
                verdict=SSEVerdict.CONDITIONALLY_FEASIBLE,
                path_confidence=path_conf,
                edge_path=list(edge_descs),
                dependency_note=dep_note,
            )

    def _explain_failure(
        self,
        acct_node: str,
        src_node: str,
        tgt_node: str,
        constraint: TechniqueConstraint,
    ) -> str:
        """Generate a descriptive failure reason for INFEASIBLE results."""
        g = self._graph_store.graph

        if not list(g.out_edges(acct_node)):
            return (
                f"No outgoing edges from {acct_node} — account has no "
                f"access grants or group memberships"
            )

        try:
            has_path = nx.has_path(g, acct_node, tgt_node)
        except nx.NodeNotFound:
            return f"Node not found in graph"

        if not has_path and not constraint.valid_sequences:
            # Network-only technique
            return (
                f"Network egress on required ports {constraint.egress_ports} "
                f"is blocked from source host's zone"
            )

        if not has_path:
            return (
                f"No graph path exists from {acct_node} to {tgt_node} — "
                f"no access relationship connects this account to the "
                f"target host"
            )

        # Path exists but constraints not met — check if egress blocked
        if constraint.valid_sequences:
            access_paths = self._find_access_paths(
                acct_node, tgt_node, constraint.valid_sequences
            )
            if access_paths and constraint.egress_ports:
                return (
                    f"Access path exists from {acct_node} to {tgt_node} "
                    f"but network egress on required ports "
                    f"{constraint.egress_ports} is blocked between source "
                    f"and target zones"
                )

        return (
            f"Paths exist from {acct_node} to {tgt_node} but none match "
            f"technique {constraint.technique_id} "
            f"({constraint.description}) required edge constraints "
            f"(edge types, access levels, or protocol requirements)"
        )
