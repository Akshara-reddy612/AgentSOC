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
}


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

        Raises:
            TypeError: If any argument is an Evidence object.
        """
        # --- Security gate ---
        self._reject_evidence(
            account_id, source_host_id, target_host_id, technique_id
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

        # --- Resolve nodes (lazy creation) ---
        acct_node = self._graph_store.get_or_create_account_node(account_id)
        src_node = self._graph_store.get_or_create_host_node(source_host_id)
        tgt_node = self._graph_store.get_or_create_host_node(target_host_id)

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

        elif constraint.egress_ports:
            # Network-only technique (e.g. T1071 C2)
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

            try:
                for node_path in nx.all_simple_paths(
                    g, acct_node, tgt_node, cutoff=min(seq_len, 4)
                ):
                    if len(node_path) - 1 != seq_len:
                        continue  # Wrong number of edges

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
        src_zone = self._graph_store.get_host_zone(src_host_node)
        tgt_zone = self._graph_store.get_host_zone(tgt_host_node)

        if src_zone is None:
            return (False, 0.0, "")

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
