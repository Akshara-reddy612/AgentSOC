"""
perception/nce_rsem_integration.py

Phase NCE-6 integration layer: completes the full NCE → SSE → RSEM defended
pipeline for the first time.

Takes SSE-validated hypotheses (from validate_nce_output()), filters to
FEASIBLE-only for RSEM ranking, ranks defensive actions per hypothesis,
updates hypothesis lifecycle status to RSEM_RANKED, and produces a complete
pipeline result with full audit trail — including infeasible hypotheses
that were explicitly excluded from RSEM ranking.

DESIGN DECISIONS:

1.  RSEM only ranks FEASIBLE hypotheses.  An INFEASIBLE hypothesis has
    zero structurally valid attack paths, so computing containment
    (paths_cut / paths_before) yields 0/0 = 0.0 — not wrong, but
    semantically meaningless.  More importantly, ranking defensive actions
    against a structurally impossible attack is wasted computation that
    could distort the analyst's decision surface.  The filtering happens
    BEFORE RSEM sees the hypothesis, not inside RSEM (which is unchanged).

2.  Infeasible hypotheses are NEVER deleted.  They are preserved in a
    separate ``sse_rejected`` list in the PipelineResult with their full
    ValidatedHypothesis data intact.  "SSE rejected this" is itself
    valuable audit data.

3.  Status lifecycle transitions:
    - FEASIBLE → RSEM_RANKED (after RSEM scores and ranks actions)
    - INFEASIBLE stays INFEASIBLE (never reaches RSEM)
    - SELECTED / REJECTED are available for a future selection layer

4.  CRITICAL INVARIANT (unchanged): nce_confidence is never used as a
    scoring input to RSEM.  RSEM's score_action() computes containment
    from graph topology and business_impact from criticality/blast-radius.
    nce_confidence exists only as an advisory diagnostic, preserved in
    ValidatedHypothesis.hypothesis.nce_confidence for the confidence_gap
    metric.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import HypothesisStatus, NCEHypothesis
from perception.nce_sse_integration import ValidatedHypothesis
from perception.rsem import (
    ProposedAction,
    RiskWeights,
    ScoredAction,
    StructuralSimulationEngine,
    rank_actions,
)


# ---------------------------------------------------------------------------
# RankedHypothesisResult — per-hypothesis RSEM output
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RankedHypothesisResult:
    """
    A single FEASIBLE hypothesis after RSEM ranking.

    Attributes:
        validated:      The ValidatedHypothesis (with status updated to
                        RSEM_RANKED via with_status()).
        ranked_actions: Defensive actions ranked by composite score
                        (descending — best action first).
    """
    validated: ValidatedHypothesis
    ranked_actions: list[ScoredAction]


# ---------------------------------------------------------------------------
# PipelineResult — the complete NCE → SSE → RSEM output
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PipelineResult:
    """
    Complete output of the defended NCE → SSE → RSEM pipeline.

    Contains:
        ranked:       FEASIBLE hypotheses that reached RSEM ranking, each
                      with their ranked defensive actions.  Status is
                      RSEM_RANKED.
        sse_rejected: INFEASIBLE hypotheses that were excluded from RSEM
                      ranking — retained with full audit data, never deleted.
                      Status remains INFEASIBLE.

    The total count (len(ranked) + len(sse_rejected)) always equals the
    original NCEOutput hypothesis count — nothing is silently dropped.
    """
    ranked: list[RankedHypothesisResult]
    sse_rejected: list[ValidatedHypothesis]


# ---------------------------------------------------------------------------
# rank_validated_hypotheses — the Phase NCE-6 integration point
# ---------------------------------------------------------------------------

def rank_validated_hypotheses(
    validated: list[ValidatedHypothesis],
    graph_store: KnowledgeStoreGraph,
    sse: StructuralSimulationEngine,
    candidate_actions: list[ProposedAction],
    weights: RiskWeights = RiskWeights(),
) -> PipelineResult:
    """
    Complete the NCE → SSE → RSEM pipeline.

    For each FEASIBLE hypothesis:
        1. Extract the hypothesis's NCEHypothesis (already FEASIBLE status)
        2. Run RSEM's rank_actions() to score and rank candidate actions
        3. Update status to RSEM_RANKED via with_status()
        4. Wrap in RankedHypothesisResult

    INFEASIBLE hypotheses are placed in sse_rejected without modification
    — they never reach RSEM.

    CRITICAL: RSEM's score_action() never reads nce_confidence.  It computes
    containment from graph topology (re-running SSE.check() on graph copies)
    and business_impact from criticality/blast-radius.  This invariant is
    maintained by not modifying RSEM's internals.

    Args:
        validated:         SSE-validated hypotheses (from validate_nce_output).
        graph_store:       The KnowledgeStoreGraph.
        sse:               The StructuralSimulationEngine.
        candidate_actions: Defensive actions to evaluate for each hypothesis.
        weights:           Risk weight tuning (default: balanced).

    Returns:
        PipelineResult with ranked (FEASIBLE → RSEM_RANKED) and
        sse_rejected (INFEASIBLE, unchanged) lists.
    """
    ranked_results: list[RankedHypothesisResult] = []
    sse_rejected: list[ValidatedHypothesis] = []

    for vh in validated:
        if vh.hypothesis.status == HypothesisStatus.FEASIBLE:
            # --- RSEM ranking ---
            # rank_actions expects list[NCEHypothesis], pass a single-element
            # list for per-hypothesis ranking.
            scored = rank_actions(
                graph_store,
                sse,
                candidate_actions,
                [vh.hypothesis],
                weights,
            )

            # Update status: FEASIBLE → RSEM_RANKED
            ranked_hypothesis = vh.hypothesis.with_status(
                HypothesisStatus.RSEM_RANKED
            )

            # Build a new ValidatedHypothesis with the updated hypothesis
            updated_vh = ValidatedHypothesis(
                hypothesis=ranked_hypothesis,
                sse_results=vh.sse_results,
                best_sse_verdict=vh.best_sse_verdict,
                best_path_confidence=vh.best_path_confidence,
                confidence_gap=vh.confidence_gap,
            )

            ranked_results.append(RankedHypothesisResult(
                validated=updated_vh,
                ranked_actions=scored,
            ))
        else:
            # INFEASIBLE — explicitly excluded from RSEM ranking,
            # retained for audit purposes.
            sse_rejected.append(vh)

    return PipelineResult(
        ranked=ranked_results,
        sse_rejected=sse_rejected,
    )
