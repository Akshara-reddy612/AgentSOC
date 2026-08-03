"""
risk_assessment/orchestrator.py

Risk Assessment Orchestrator for Evidence Risk Assessment (ERA).

Public API
----------
    from risk_assessment.orchestrator import assess

    bundle: RiskAssessmentBundle = assess(evidence)

The orchestrator:
1. Normalizes each evidence field.
2. Runs all FieldDetectors on each field, collecting DetectorResults.
3. Fuses field-level detector scores with the Weighted Risk Fusion +
   Ceiling Rule (see below) to produce a per-field RiskAssessmentResult.
4. Runs all IncidentDetectors across ALL fields simultaneously to produce
   an incident-level RiskAssessmentResult.
5. Returns a RiskAssessmentBundle — it does NOT mutate the Evidence object.

Zero imports of perception.models
----------------------------------
This module is deliberately decoupled from Phase 1's domain model.
`assess()` accepts an Evidence object, but it is typed as `Any` at runtime
to avoid the import.  The integration adapter (integration.py) is the ONLY
module allowed to bridge Phase 1 and Phase 2.

Weighted Risk Fusion + Ceiling Rule
------------------------------------
For each evidence field, the orchestrator calls each registered FieldDetector
and SplitFieldDetector (via the incident-level path for split-field) and then
combines their scores with:

    base_score = (REGEX_WEIGHT * regex_score
                  + SEMANTIC_WEIGHT * semantic_score
                  + SPLIT_FIELD_WEIGHT * split_field_score)

The ceiling rule prevents a confident single detector from being diluted by
quieter detectors:

    IF any single detector score >= SINGLE_DETECTOR_CEILING_THRESHOLD:
        overall_score = max(base_score, max_single_detector_score)
    ELSE:
        overall_score = base_score

Rationale: if RegexDetector reports 0.95 (it matched 3 distinct injection
phrases — definitively malicious), but SemanticDetector reports 0.30 (the
paraphrase distance is moderate), the weighted average alone would yield
~0.55 — HIGH by threshold, but uncomfortably close to the boundary.  The
ceiling rule instead sets overall_score = max(0.55, 0.95) = 0.95, accurately
representing that one detector is extremely confident.  This rule applies
symmetrically to all three detector families.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from risk_assessment.config import (
    REGEX_WEIGHT,
    SEMANTIC_WEIGHT,
    SINGLE_DETECTOR_CEILING_THRESHOLD,
    SPLIT_FIELD_WEIGHT,
)
from risk_assessment.normalization import normalize_text
from risk_assessment.registry import FIELD_DETECTORS, INCIDENT_DETECTORS
from risk_assessment.results import (
    DetectorResult,
    NormalizationResult,
    RiskAssessmentBundle,
    RiskAssessmentResult,
)

if TYPE_CHECKING:
    pass  # No perception.models imports — decoupled from Phase 1


# ---------------------------------------------------------------------------
# Evidence field names that the orchestrator knows how to extract.
# Matches the attributes defined on perception.models.Evidence.
# ---------------------------------------------------------------------------

_EVIDENCE_FIELDS: tuple[str, ...] = (
    "process_name",
    "command_line",
    "registry_key",
    "parent_process",
    "file_path",
    "raw_log_line",
)


def _extract_field_value(evidence: Any, field_name: str) -> str | None:
    """
    Extract the string value of an Evidence field, returning None if absent.

    Handles the TrustedField wrapper: each Evidence field is either None or a
    TrustedField whose `.value` attribute holds the actual string content.
    No perception.models import required — we access `.value` via attribute
    lookup (duck typing).
    """
    trusted_field = getattr(evidence, field_name, None)
    if trusted_field is None:
        return None
    value = getattr(trusted_field, "value", None)
    if not isinstance(value, str):
        return None
    return value


def _fuse_scores(
    detector_results: list[DetectorResult],
    weights: dict[str, float],
) -> float:
    """
    Apply Weighted Risk Fusion + Ceiling Rule to a list of DetectorResults.

    Parameters
    ----------
    detector_results : list[DetectorResult]
        Results from detectors that ran on this field/incident.
    weights : dict[str, float]
        Maps detector name → weight.  Detectors not in this dict default
        to 0.0 contribution (they still appear in the result but don't
        affect the fused score).

    Returns
    -------
    float
        The fused overall_score, clamped to [0.0, 1.0].

    Ceiling Rule
    ------------
    If any single detector's score >= SINGLE_DETECTOR_CEILING_THRESHOLD,
    override the base weighted average with max(base, that score).
    This prevents a very confident single detector (e.g. regex score 0.95)
    from being diluted below its own confidence by quieter detectors.
    """
    base_score: float = 0.0
    max_single: float = 0.0

    for dr in detector_results:
        w = weights.get(dr.detector, 0.0)
        base_score += w * dr.score
        if dr.score > max_single:
            max_single = dr.score

    # Ceiling rule: a single very confident detector must not be diluted.
    if max_single >= SINGLE_DETECTOR_CEILING_THRESHOLD:
        # The overall score is at least as high as the most confident detector.
        overall = max(base_score, max_single)
    else:
        overall = base_score

    # Clamp to [0.0, 1.0] — floating-point addition can very slightly exceed.
    return min(1.0, max(0.0, overall))


# Weights for the three detector families used in field-level fusion.
# The split-field weight applies when the incident-level SplitFieldDetector
# result is merged into per-field scores (see note in assess()).
_FIELD_WEIGHTS: dict[str, float] = {
    "RegexDetector": REGEX_WEIGHT,
    "SemanticDetector": SEMANTIC_WEIGHT,
    "SplitFieldDetector": SPLIT_FIELD_WEIGHT,
}


def assess(evidence: Any) -> RiskAssessmentBundle:
    """
    Run the full ERA pipeline on one Evidence object.

    Parameters
    ----------
    evidence : Evidence  (typed as Any to avoid perception.models import)
        An Evidence dataclass instance with TrustedField attributes.
        This function is PURE — it never modifies the Evidence object.

    Returns
    -------
    RiskAssessmentBundle
        Contains:
        - ``field_results``: one RiskAssessmentResult per non-empty Evidence
          field.
        - ``incident_result``: a single RiskAssessmentResult from running all
          IncidentDetectors across all fields combined.

    Notes
    -----
    Design invariants:
    - The Evidence object is never mutated.
    - No perception.models symbols are imported; duck typing is used instead.
    - Deterministic: identical Evidence inputs produce identical bundles.
    """
    # -----------------------------------------------------------------------
    # Step 1: Normalize each evidence field.
    # -----------------------------------------------------------------------
    # Build a mapping of field_name → (raw_value, NormalizationResult).
    # Only fields with non-None string values are included.
    field_norms: dict[str, NormalizationResult] = {}
    raw_values: dict[str, str] = {}

    for field_name in _EVIDENCE_FIELDS:
        raw_value = _extract_field_value(evidence, field_name)
        if raw_value is None:
            continue
        norm_result = normalize_text(raw_value)
        field_norms[field_name] = norm_result
        raw_values[field_name] = raw_value

    # -----------------------------------------------------------------------
    # Step 2: Run IncidentDetectors across ALL fields (split-field detection).
    # We run this BEFORE the per-field loop so the split-field score is
    # available when fusing per-field scores.
    # -----------------------------------------------------------------------
    # Collect incident-level DetectorResults from all registered IncidentDetectors.
    incident_detector_results: list[DetectorResult] = []
    for inc_detector in INCIDENT_DETECTORS:
        inc_result = inc_detector.detect(all_fields=field_norms)
        incident_detector_results.append(inc_result)

    # Derive the split-field score from the SplitFieldDetector result
    # (the only IncidentDetector currently registered).
    # If multiple IncidentDetectors are registered in future, take the max.
    split_field_score: float = max(
        (dr.score for dr in incident_detector_results), default=0.0
    )
    split_field_detector_result = DetectorResult(
        detector="SplitFieldDetector",
        score=round(split_field_score, 6),
        matches=incident_detector_results[0].matches if incident_detector_results else [],
        confidence=(
            incident_detector_results[0].confidence if incident_detector_results else 0.0
        ),
        explanation=(
            incident_detector_results[0].explanation if incident_detector_results else []
        ),
    )

    # -----------------------------------------------------------------------
    # Step 3: Per-field risk assessment.
    # For each evidence field: run FieldDetectors, then fuse with the
    # incident-level split-field score.
    # -----------------------------------------------------------------------
    field_results: dict[str, RiskAssessmentResult] = {}

    for field_name, norm_result in field_norms.items():
        # 3a. Run all registered FieldDetectors on this field.
        field_detector_results: list[DetectorResult] = []
        for fd in FIELD_DETECTORS:
            dr = fd.detect(
                normalized_text=norm_result.normalized_text,
                decoded_candidates=list(norm_result.decoded_candidates),
            )
            field_detector_results.append(dr)

        # 3b. Include the split-field result as a pseudo field-level score.
        # Rationale: the split-field detector operates on ALL fields, so its
        # score is informative for each individual field that contributed.
        # Including it here lets the ceiling rule enforce HIGH on a per-field
        # result when the cross-field combined score is very high.
        all_results_for_field = field_detector_results + [split_field_detector_result]

        # 3c. Fuse scores with Weighted Risk Fusion + Ceiling Rule.
        overall_score = _fuse_scores(all_results_for_field, _FIELD_WEIGHTS)

        # 3d. Assemble per-field summary sentences.
        summary: list[str] = []
        for dr in all_results_for_field:
            summary.extend(dr.explanation)

        # 3e. Construct the per-field RiskAssessmentResult.
        field_result = RiskAssessmentResult(
            evidence_field_name=field_name,
            detector_results=all_results_for_field,
            overall_score=overall_score,
            summary=summary,
        )
        field_results[field_name] = field_result

    # -----------------------------------------------------------------------
    # Step 4: Incident-level RiskAssessmentResult.
    # Represents the cross-field, whole-incident view.  Fuses all
    # IncidentDetector results; if field_results is empty (no evidence fields),
    # produce a zero-score incident result.
    # -----------------------------------------------------------------------
    if incident_detector_results:
        # Incident-level fusion uses only the IncidentDetector weight.
        # For a single SplitFieldDetector, score IS split_field_score.
        # For multiple future IncidentDetectors, use max-of-all (same ceiling).
        incident_weights = {"SplitFieldDetector": 1.0}
        # Normalise if multiple incident detectors are registered:
        if len(incident_detector_results) > 1:
            incident_weights = {
                dr.detector: 1.0 / len(incident_detector_results)
                for dr in incident_detector_results
            }

        incident_overall = _fuse_scores(incident_detector_results, incident_weights)
        incident_summary: list[str] = []
        for dr in incident_detector_results:
            incident_summary.extend(dr.explanation)

        incident_result = RiskAssessmentResult(
            evidence_field_name="__incident__",
            detector_results=incident_detector_results,
            overall_score=incident_overall,
            summary=incident_summary,
        )
    else:
        # No evidence fields at all → zero-score incident result.
        incident_result = RiskAssessmentResult(
            evidence_field_name="__incident__",
            detector_results=[],
            overall_score=0.0,
            summary=["No evidence fields found; incident-level score is 0.0."],
        )

    return RiskAssessmentBundle(
        field_results=field_results,
        incident_result=incident_result,
    )
