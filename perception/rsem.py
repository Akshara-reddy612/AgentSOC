"""
perception/rsem.py

Risk Scoring and Evaluation Module (RSEM).

Implements the paper's formula:
    Composite Score = (α × Containment) − (β × Business Impact)

Containment is measured by simulating a proposed action's effect on a
COPY of the knowledge graph and measuring how many SSE-feasible attack
paths are cut.  Business impact is derived from the target host's
criticality tier and the blast radius of dependent services.

CRITICAL: compute_containment NEVER mutates the live graph.  It always
operates on a deep copy (graph_store.graph.copy()).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from perception.knowledge_graph import (
    KnowledgeStoreGraph,
    account_node_id,
    host_node_id,
)
from perception.knowledge_store import KnowledgeFact
from perception.sse import (
    SSEVerdict,
    StructuralSimulationEngine,
    TECHNIQUE_TABLE,
)

if TYPE_CHECKING:
    from perception.nce_contract import NCEHypothesis


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MFA_CONFIDENCE_MULTIPLIER = 0.5
"""
When ENABLE_MFA is applied, GRANTS edge confidences involving the target
account are multiplied by this factor.  MFA doesn't eliminate access — it
adds friction, reducing confidence that the access path is exploitable.
A value of 0.5 means a formerly high-confidence edge has its exploitability
halved, potentially shifting the SSE verdict from FEASIBLE to
CONDITIONALLY_FEASIBLE without removing the edge.
"""

# Criticality tier → business impact base score.
# Higher tier = more critical = higher business impact.
#
# NOTE: The original spec described "tier 0 = crown jewel" but the existing
# data model uses tier 3 = "critical" (server-dc01) and tier 0 = "low"
# (workstation-01).  This mapping matches the ACTUAL data model and the
# test assertions (server-dc01 must score higher than workstation-01).
#
# Formula: impact_base = 0.25 + (criticality_tier / 3.0) * 0.75
_CRITICALITY_IMPACT: dict[int, float] = {
    0: 0.25,    # low
    1: 0.50,    # medium
    2: 0.75,    # high
    3: 1.00,    # critical / crown jewel
}

# Service dependency blast-radius contribution.
# Each dependent service adds _DEPENDENT_WEIGHT to the base impact,
# capped at _DEPENDENT_MAX total.  This is a designed heuristic, not
# a physical law — the intuition is that taking down a host with many
# service dependents has proportionally higher blast radius.
_DEPENDENT_WEIGHT = 0.1  # Per dependent service
_DEPENDENT_MAX = 0.3     # Maximum blast-radius contribution


# ---------------------------------------------------------------------------
# ActionType
# ---------------------------------------------------------------------------

class ActionType(Enum):
    """Action primitives matching the paper's response taxonomy."""
    REVOKE_SESSION = "REVOKE_SESSION"
    RESTRICT_PRIVILEGES = "RESTRICT_PRIVILEGES"
    ENABLE_MFA = "ENABLE_MFA"
    QUARANTINE_ACCESS = "QUARANTINE_ACCESS"
    MONITOR_ONLY = "MONITOR_ONLY"


# ---------------------------------------------------------------------------
# ProposedAction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProposedAction:
    """
    A candidate response action to evaluate.

    At least one of target_account_id or target_host_id must be set —
    an action that targets neither is meaningless.
    """
    action_type: ActionType
    target_account_id: str | None = None
    target_host_id: str | None = None

    def __post_init__(self) -> None:
        if self.target_account_id is None and self.target_host_id is None:
            raise ValueError(
                "ProposedAction must have at least one of "
                "target_account_id or target_host_id set"
            )


# ---------------------------------------------------------------------------
# RiskWeights
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RiskWeights:
    """
    Tunable weights for the RSEM composite score formula.

    Composite Score = (alpha × containment) − (beta × business_impact)

    Both must be > 0.
    """
    alpha: float = 1.0
    beta: float = 1.0

    def __post_init__(self) -> None:
        if self.alpha <= 0:
            raise ValueError(f"alpha must be > 0, got {self.alpha!r}")
        if self.beta <= 0:
            raise ValueError(f"beta must be > 0, got {self.beta!r}")


# Named presets
RISK_AVERSE = RiskWeights(alpha=0.7, beta=1.3)
"""Penalizes business disruption more heavily — conservative responses."""

AGGRESSIVE_CONTAINMENT = RiskWeights(alpha=1.3, beta=0.7)
"""Rewards containment more heavily — favors decisive action."""


# ---------------------------------------------------------------------------
# ScoredAction
# ---------------------------------------------------------------------------

@dataclass
class ScoredAction:
    """
    A fully evaluated response action with decomposed scoring.

    Fields expose the reasoning behind the composite score so analysts
    can audit why a particular action was ranked higher or lower.
    """
    action: ProposedAction
    containment: float
    business_impact: float
    composite_score: float
    paths_cut: int
    paths_total_before: int


# ---------------------------------------------------------------------------
# compute_containment
# ---------------------------------------------------------------------------

def compute_containment(
    graph_store: KnowledgeStoreGraph,
    sse: StructuralSimulationEngine,
    action: ProposedAction,
    hypotheses: list[NCEHypothesis],
) -> tuple[float, int, int]:
    """
    Simulate the action's effect on a COPY of the knowledge graph and
    measure how many SSE-feasible attack paths are cut.

    Returns (containment, paths_cut, paths_total_before) where:
    - containment = paths_cut / paths_total_before (0.0 if none existed)
    - paths_cut = feasible_before - feasible_after
    - paths_total_before = feasible_before

    CRITICAL: the live graph (graph_store.graph) is NEVER mutated.
    """
    # Count feasible paths BEFORE action
    feasible_before = _count_feasible_paths(sse, hypotheses)

    # MONITOR_ONLY: no graph changes, containment = 0
    if action.action_type == ActionType.MONITOR_ONLY:
        return (0.0, 0, feasible_before)

    # Make a deep copy of the graph — NEVER modify the live graph
    modified_graph = graph_store.graph.copy()

    # Apply action to the copy
    _apply_action(modified_graph, action)

    # Create SSE against the modified graph via from_graph wrapper
    modified_store = KnowledgeStoreGraph.from_graph(modified_graph)
    modified_sse = StructuralSimulationEngine(modified_store)

    # Count feasible paths AFTER action
    feasible_after = _count_feasible_paths(modified_sse, hypotheses)

    paths_cut = feasible_before - feasible_after

    if feasible_before == 0:
        return (0.0, 0, 0)

    containment = paths_cut / feasible_before
    return (containment, paths_cut, feasible_before)


def _count_feasible_paths(
    sse: StructuralSimulationEngine,
    hypotheses: list[NCEHypothesis],
) -> int:
    """Count total non-INFEASIBLE verdicts across all hypotheses."""
    count = 0
    for hyp in hypotheses:
        results = sse.check(
            hyp.source_account,
            hyp.source_host,
            hyp.target_host,
            hyp.technique_id,
        )
        for r in results:
            if r.verdict != SSEVerdict.INFEASIBLE:
                count += 1
    return count


def _apply_action(graph: "nx.MultiDiGraph", action: ProposedAction) -> None:
    """
    Apply a ProposedAction's effect to a graph (mutates in place).

    This should only be called on a COPY — never the live graph.

    Each action type targets a semantically distinct set of edge types:
    - REVOKE_SESSION:       HAS_PRIOR_ACCESS only (session invalidation —
                            standing grants and group membership survive)
    - RESTRICT_PRIVILEGES:  GRANTS + MEMBER_OF (privilege downgrade — cuts
                            both direct and group-mediated access, but
                            HAS_PRIOR_ACCESS baseline survives)
    - QUARANTINE_ACCESS:    GRANTS + HAS_PRIOR_ACCESS + MEMBER_OF (full
                            host isolation — most aggressive response)
    - ENABLE_MFA:           Reduces confidence on GRANTS edges (friction)
    - MONITOR_ONLY:         No graph changes
    """
    import networkx as nx  # noqa: F811 — local import to avoid top-level dep

    if action.action_type == ActionType.MONITOR_ONLY:
        return  # No changes

    if action.action_type == ActionType.REVOKE_SESSION:
        _remove_edges_by_type(graph, action, {"HAS_PRIOR_ACCESS"})

    elif action.action_type == ActionType.RESTRICT_PRIVILEGES:
        _remove_edges_by_type(graph, action, {"GRANTS", "MEMBER_OF"})

    elif action.action_type == ActionType.QUARANTINE_ACCESS:
        _remove_edges_by_type(
            graph, action, {"GRANTS", "HAS_PRIOR_ACCESS", "MEMBER_OF"}
        )

    elif action.action_type == ActionType.ENABLE_MFA:
        _reduce_grants_confidence(graph, action)


def _remove_edges_by_type(
    graph: "nx.MultiDiGraph",
    action: ProposedAction,
    edge_types: set[str],
) -> None:
    """Remove edges of the specified types, filtered by the action's targets.

    MEMBER_OF edges receive special handling: they point from account → group
    (never to a host), so the host filter is not applied to them.  When
    target_account_id is set, MEMBER_OF edges from that account are removed
    regardless of target_host_id.  When only target_host_id is set (e.g.
    QUARANTINE_ACCESS on a host), MEMBER_OF edges are not removed — the host
    is isolated by removing GRANTS/HAS_PRIOR_ACCESS edges that point to it,
    which is sufficient to cut group-mediated paths at the GRANTS hop.
    """
    edges_to_remove: list[tuple[str, str, str]] = []

    for u, v, key, data in graph.edges(keys=True, data=True):
        et = data.get("edge_type", "")
        if et not in edge_types:
            continue

        if et == "MEMBER_OF":
            # MEMBER_OF edges go account → group, never to a host.
            # Only remove when targeting a specific account.
            if action.target_account_id:
                acct = account_node_id(action.target_account_id)
                if u == acct:
                    edges_to_remove.append((u, v, key))
        else:
            # Standard filtering for GRANTS, HAS_PRIOR_ACCESS
            if action.target_account_id:
                acct = account_node_id(action.target_account_id)
                if u == acct:
                    if action.target_host_id:
                        h = host_node_id(action.target_host_id)
                        if v == h:
                            edges_to_remove.append((u, v, key))
                    else:
                        edges_to_remove.append((u, v, key))

            elif action.target_host_id:
                h = host_node_id(action.target_host_id)
                if v == h:
                    edges_to_remove.append((u, v, key))

    for u, v, key in edges_to_remove:
        graph.remove_edge(u, v, key=key)


def _reduce_grants_confidence(
    graph: "nx.MultiDiGraph", action: ProposedAction
) -> None:
    """
    Reduce confidence on GRANTS edges involving the target account
    by MFA_CONFIDENCE_MULTIPLIER.

    MFA doesn't eliminate access — it adds friction.  A formerly
    high-confidence GRANTS edge has its exploitability reduced,
    potentially shifting the SSE verdict.
    """
    for u, v, key, data in graph.edges(keys=True, data=True):
        if data.get("edge_type") != "GRANTS":
            continue

        match = False
        if action.target_account_id:
            acct = account_node_id(action.target_account_id)
            if u == acct:
                match = True
        if action.target_host_id:
            h = host_node_id(action.target_host_id)
            if v == h:
                match = True

        if match:
            al = data.get("access_level")
            if isinstance(al, KnowledgeFact):
                new_conf = al.confidence * MFA_CONFIDENCE_MULTIPLIER
                # Replace the KnowledgeFact with a lower-confidence copy
                data["access_level"] = KnowledgeFact(
                    value=al.value,
                    version=al.version,
                    confidence=new_conf,
                    source=al.source,
                    timestamp=al.timestamp,
                )


# ---------------------------------------------------------------------------
# compute_business_impact
# ---------------------------------------------------------------------------

def compute_business_impact(
    graph_store: KnowledgeStoreGraph,
    action: ProposedAction,
) -> float:
    """
    Assess the business impact of applying the proposed action.

    Formula:
        impact_base = 0.25 + (criticality_tier / 3.0) * 0.75
            tier 0 (low)      → 0.25
            tier 1 (medium)   → 0.50
            tier 2 (high)     → 0.75
            tier 3 (critical) → 1.00

        blast_radius = min(count(service_dependents) * 0.1, 0.3)

        business_impact = clamp(impact_base + blast_radius, 0.0, 1.0)
    """
    # Resolve target host
    target_host = None
    if action.target_host_id:
        target_host = host_node_id(action.target_host_id)
    elif action.target_account_id:
        acct = account_node_id(action.target_account_id)
        if acct in graph_store.graph:
            home = graph_store.graph.nodes[acct].get("home_host_id")
            if home:
                target_host = host_node_id(home)

    if target_host is None or target_host not in graph_store.graph:
        return 0.0

    # Get criticality tier from node data
    node_data = graph_store.graph.nodes[target_host]
    crit_fact = node_data.get("criticality_tier")
    if isinstance(crit_fact, KnowledgeFact):
        crit_tier = crit_fact.value
    elif isinstance(crit_fact, (int, float)):
        crit_tier = int(crit_fact)
    else:
        crit_tier = 0

    # Base impact from criticality
    impact_base = _CRITICALITY_IMPACT.get(
        crit_tier, 0.25 + (crit_tier / 3.0) * 0.75
    )

    # Blast radius from service dependents
    services = graph_store.get_services_on_host(target_host)
    total_dependents = 0
    for svc_node in services:
        svc_data = graph_store.graph.nodes.get(svc_node, {})
        svc_id = svc_data.get("service_id", svc_node)
        dependents = graph_store.get_service_dependents(svc_id)
        total_dependents += len(dependents)

    blast_radius = min(total_dependents * _DEPENDENT_WEIGHT, _DEPENDENT_MAX)

    return min(max(impact_base + blast_radius, 0.0), 1.0)


# ---------------------------------------------------------------------------
# score_action / rank_actions
# ---------------------------------------------------------------------------

def score_action(
    graph_store: KnowledgeStoreGraph,
    sse: StructuralSimulationEngine,
    action: ProposedAction,
    hypotheses: list[NCEHypothesis],
    weights: RiskWeights = RiskWeights(),
) -> ScoredAction:
    """Score a single proposed action against the composite formula."""
    containment, paths_cut, paths_total = compute_containment(
        graph_store, sse, action, hypotheses
    )
    impact = compute_business_impact(graph_store, action)
    composite = (weights.alpha * containment) - (weights.beta * impact)

    return ScoredAction(
        action=action,
        containment=containment,
        business_impact=impact,
        composite_score=composite,
        paths_cut=paths_cut,
        paths_total_before=paths_total,
    )


def rank_actions(
    graph_store: KnowledgeStoreGraph,
    sse: StructuralSimulationEngine,
    candidate_actions: list[ProposedAction],
    hypotheses: list[NCEHypothesis],
    weights: RiskWeights = RiskWeights(),
) -> list[ScoredAction]:
    """
    Score all candidate actions and return sorted descending by
    composite_score (highest score = best action to take).
    """
    scored = [
        score_action(graph_store, sse, action, hypotheses, weights)
        for action in candidate_actions
    ]
    scored.sort(key=lambda s: s.composite_score, reverse=True)
    return scored
