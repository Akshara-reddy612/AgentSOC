"""
perception/nce_sse_integration.py

Phase NCE-5 integration layer: wires NCE's real output into SSE for the
first time.

Takes an NCEOutput (1-3 NCEHypothesis objects), runs
StructuralSimulationEngine.check() against every hypothesis, updates each
hypothesis's status through the GENERATED → FEASIBLE/INFEASIBLE transition,
and produces a combined result structure preserving both NCE's and SSE's
confidence values SEPARATELY.

CRITICAL DESIGN INVARIANT (locked from NCE-2/3/4):
    NCEHypothesis.nce_confidence is advisory/display-only.  It must NEVER
    be blended (averaged, summed, multiplied, or otherwise combined) with
    SSE's path_confidence for any security-relevant decision.  Both are
    preserved independently in ValidatedHypothesis so a confidence_gap
    diagnostic metric can be computed.  confidence_gap is a SIMPLE
    SUBTRACTION (nce_confidence - best_path_confidence) — nothing more
    complex.

CONDITIONALLY_FEASIBLE mapping decision (confirmed with user):
    SSE's CONDITIONALLY_FEASIBLE verdict (structurally valid path with
    path_confidence < 0.5) maps to HypothesisStatus.FEASIBLE.  Both
    FEASIBLE and CONDITIONALLY_FEASIBLE prove the attack path structurally
    exists — they differ only in edge confidence.  RSEM can differentiate
    using best_path_confidence and best_sse_verdict, which are preserved
    as separate fields in ValidatedHypothesis.

INFEASIBLE retention (locked design):
    Infeasible hypotheses are NEVER deleted/discarded.  Every hypothesis
    NCE generates is retained with its final status for audit purposes.
    "SSE rejected this" is itself valuable data.
"""

from __future__ import annotations

from dataclasses import dataclass

from perception.nce_contract import (
    HypothesisStatus,
    NCEHypothesis,
    NCEOutput,
)
from perception.sse import (
    PathResult,
    SSEVerdict,
    StructuralSimulationEngine,
)


# ---------------------------------------------------------------------------
# Verdict ordering — used to pick the "best" (most favorable) SSE verdict
# ---------------------------------------------------------------------------

_VERDICT_RANK: dict[SSEVerdict, int] = {
    SSEVerdict.FEASIBLE: 2,
    SSEVerdict.CONDITIONALLY_FEASIBLE: 1,
    SSEVerdict.INFEASIBLE: 0,
}


# ---------------------------------------------------------------------------
# ValidatedHypothesis — result wrapper keeping NCE and SSE outputs separate
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ValidatedHypothesis:
    """
    A single hypothesis after SSE structural validation.

    Keeps NCE and SSE outputs cleanly separated — NEVER blended:

    Attributes:
        hypothesis:           The original NCEHypothesis with status updated
                              to FEASIBLE or INFEASIBLE (via with_status()).
        sse_results:          ALL PathResult objects SSE returned for this
                              hypothesis (could be multiple — a technique
                              might be satisfiable via more than one path).
        best_sse_verdict:     The most favorable SSEVerdict among sse_results,
                              or INFEASIBLE if sse_results is empty.
                              Ordering: FEASIBLE > CONDITIONALLY_FEASIBLE >
                              INFEASIBLE.
        best_path_confidence: The path_confidence corresponding to
                              best_sse_verdict.
        confidence_gap:       hypothesis.nce_confidence - best_path_confidence.
                              This is a SIMPLE SUBTRACTION — never clamped,
                              never combined with any other value.  Negative
                              values are meaningful (SSE is more confident
                              than NCE) and must be preserved.
    """
    hypothesis: NCEHypothesis
    sse_results: list[PathResult]
    best_sse_verdict: SSEVerdict
    best_path_confidence: float
    confidence_gap: float


# ---------------------------------------------------------------------------
# validate_hypothesis_with_sse — single-hypothesis validation
# ---------------------------------------------------------------------------

def validate_hypothesis_with_sse(
    hypothesis: NCEHypothesis,
    sse: StructuralSimulationEngine,
) -> ValidatedHypothesis:
    """
    Run SSE.check() against a single NCEHypothesis and return a
    ValidatedHypothesis with the hypothesis's status updated.

    The hypothesis must be in GENERATED status (this is the entry point
    for the GENERATED → FEASIBLE/INFEASIBLE lifecycle transition).

    Status mapping:
        - best_sse_verdict is FEASIBLE or CONDITIONALLY_FEASIBLE
          → HypothesisStatus.FEASIBLE
        - best_sse_verdict is INFEASIBLE
          → HypothesisStatus.INFEASIBLE

    CONDITIONALLY_FEASIBLE maps to FEASIBLE because both prove the attack
    path structurally exists.  RSEM differentiates using
    best_path_confidence and best_sse_verdict.

    Args:
        hypothesis: An NCEHypothesis (typically in GENERATED status).
        sse:        The StructuralSimulationEngine to check against.

    Returns:
        A ValidatedHypothesis with a NEW NCEHypothesis instance (status
        updated via with_status() — never mutated in place).
    """
    # --- Call SSE ---
    sse_results: list[PathResult] = sse.check(
        account_id=hypothesis.source_account,
        source_host_id=hypothesis.source_host,
        target_host_id=hypothesis.target_host,
        technique_id=hypothesis.technique_id,
    )

    # --- Determine best verdict ---
    # Pick the most favorable verdict among all returned paths.
    # If sse_results is empty (shouldn't happen with current SSE — it
    # always returns at least one INFEASIBLE PathResult), default to
    # INFEASIBLE with path_confidence=0.0.
    best_verdict = SSEVerdict.INFEASIBLE
    best_confidence = 0.0

    for result in sse_results:
        if _VERDICT_RANK[result.verdict] > _VERDICT_RANK[best_verdict]:
            best_verdict = result.verdict
            best_confidence = result.path_confidence
        elif (
            _VERDICT_RANK[result.verdict] == _VERDICT_RANK[best_verdict]
            and result.path_confidence > best_confidence
        ):
            # Same verdict tier, pick the higher confidence path
            best_confidence = result.path_confidence

    # --- Map SSE verdict to HypothesisStatus ---
    if best_verdict in (SSEVerdict.FEASIBLE, SSEVerdict.CONDITIONALLY_FEASIBLE):
        new_status = HypothesisStatus.FEASIBLE
    else:
        new_status = HypothesisStatus.INFEASIBLE

    # --- Compute confidence_gap ---
    # SIMPLE SUBTRACTION only.  Not clamped, not combined with anything.
    confidence_gap = hypothesis.nce_confidence - best_confidence

    # --- Build result ---
    updated_hypothesis = hypothesis.with_status(new_status)

    return ValidatedHypothesis(
        hypothesis=updated_hypothesis,
        sse_results=sse_results,
        best_sse_verdict=best_verdict,
        best_path_confidence=best_confidence,
        confidence_gap=confidence_gap,
    )


# ---------------------------------------------------------------------------
# validate_nce_output — batch validation (the Phase NCE-5 integration point)
# ---------------------------------------------------------------------------

def validate_nce_output(
    nce_output: NCEOutput,
    sse: StructuralSimulationEngine,
) -> list[ValidatedHypothesis]:
    """
    Validate every hypothesis in an NCEOutput against the SSE.

    This is the actual Phase NCE-5 integration point: NCEOutput in, a
    fully SSE-validated set out.  NOTHING IS DISCARDED — infeasible
    hypotheses are included in the output, not filtered out, per the
    locked "never delete" design.

    Args:
        nce_output: A validated NCEOutput containing 1-3 hypotheses.
        sse:        The StructuralSimulationEngine to check against.

    Returns:
        A list of ValidatedHypothesis objects — one for every hypothesis
        in nce_output.hypotheses, regardless of verdict.  The list length
        always equals len(nce_output.hypotheses).
    """
    return [
        validate_hypothesis_with_sse(hypothesis, sse)
        for hypothesis in nce_output.hypotheses
    ]
