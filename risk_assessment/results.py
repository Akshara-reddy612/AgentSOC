"""
risk_assessment/results.py

Shared result types for Evidence Risk Assessment (ERA).

These dataclasses are the SINGLE vocabulary used by every detector, the
orchestrator (Session 2), and the integration adapter (Session 2).  No
raw dicts are passed between ERA components — only these typed objects.

Type hierarchy
--------------
NormalizationResult   — output of the normalization pipeline
DetectorResult        — output of a single detector run
RiskAssessmentResult  — aggregated result for one evidence field
RiskAssessmentBundle  — full result for one incident (all fields + incident-level)

The `RiskAssessmentResult.to_dict()` method is the SINGLE place where the
dict shape that populates `Evidence.risk_metadata` is defined.  The Session 2
integration adapter calls this method — the two representations are therefore
guaranteed never to drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from risk_assessment.config import HIGH_RISK_THRESHOLD, LOW_RISK_THRESHOLD

if TYPE_CHECKING:
    pass  # avoid circular imports


# ---------------------------------------------------------------------------
# NormalizationResult
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NormalizationResult:
    """
    The output of `normalize_text()` in normalization.py.

    Attributes
    ----------
    normalized_text : str
        The fully normalized version of the original text, produced by
        applying the normalization pipeline in order:
        1. Unicode NFKC
        2. Homoglyph normalization
        3. Whitespace normalization
        The original raw string is NEVER modified.

    decoded_candidates : list[str]
        Zero or more strings produced by decoding obfuscated encodings found
        in the original text (e.g. base64 substrings).  Each candidate is
        itself normalized before being added.  Detectors run against both
        `normalized_text` AND these candidates.

    steps_applied : list[str]
        Human-readable log of every normalization step that produced a
        change.  Useful for debugging and for the `explanation` field in
        DetectorResult.  Steps are appended in execution order.
    """

    normalized_text: str
    decoded_candidates: list[str] = field(default_factory=list)
    steps_applied: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# DetectorResult
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DetectorResult:
    """
    The output of a single detector run (FieldDetector or IncidentDetector).

    Attributes
    ----------
    detector : str
        The canonical name of the detector that produced this result
        (e.g. "RegexDetector", "SemanticDetector", "SplitFieldDetector").

    score : float
        Suspicion score in [0.0, 1.0].  0.0 = definitively clean;
        1.0 = maximum confidence of injection.

    matches : list[str]
        The specific strings or phrases that triggered a hit (for regex: the
        matched pattern; for semantic: the closest exemplar phrase).
        Empty list if score == 0.0.

    confidence : float
        The detector's confidence in its own score, in [0.0, 1.0].
        For regex this is typically 1.0 (deterministic); for semantic it
        reflects the cosine similarity magnitude.

    explanation : list[str]
        Human-readable sentences explaining why this score was produced.
        Consumed by RiskAssessmentResult.summary and displayed to analysts.
    """

    detector: str
    score: float
    matches: list[str] = field(default_factory=list)
    confidence: float = 1.0
    explanation: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 1.0):
            raise ValueError(
                f"DetectorResult.score must be in [0.0, 1.0], got {self.score}"
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"DetectorResult.confidence must be in [0.0, 1.0], got {self.confidence}"
            )


# ---------------------------------------------------------------------------
# RiskAssessmentResult
# ---------------------------------------------------------------------------

def _derive_risk_level(overall_score: float) -> str:
    """
    Map a numeric score to a risk level string using config thresholds.

    Thresholds (from config.py):
        score >= HIGH_RISK_THRESHOLD  → "HIGH"
        score >= LOW_RISK_THRESHOLD   → "MEDIUM"
        otherwise                     → "LOW"
    """
    if overall_score >= HIGH_RISK_THRESHOLD:
        return "HIGH"
    if overall_score >= LOW_RISK_THRESHOLD:
        return "MEDIUM"
    return "LOW"


@dataclass
class RiskAssessmentResult:
    """
    Aggregated risk assessment for a single evidence field.

    Attributes
    ----------
    evidence_field_name : str
        The name of the Evidence field this result covers (e.g. "command_line").

    detector_results : list[DetectorResult]
        One DetectorResult per detector that ran on this field.

    overall_score : float
        Weighted combination of detector scores (computed by the orchestrator
        in Session 2, or set directly in tests).

    risk_level : str
        "LOW", "MEDIUM", or "HIGH" — derived from `overall_score` via
        `_derive_risk_level()`.  Set at construction time.

    summary : list[str]
        Human-readable summary sentences aggregated from all detector
        explanations.
    """

    evidence_field_name: str
    detector_results: list[DetectorResult]
    overall_score: float
    risk_level: str = field(init=False)
    summary: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not (0.0 <= self.overall_score <= 1.0):
            raise ValueError(
                f"RiskAssessmentResult.overall_score must be in [0.0, 1.0], "
                f"got {self.overall_score}"
            )
        self.risk_level = _derive_risk_level(self.overall_score)

    def to_dict(self) -> dict:
        """
        Produce the canonical dict shape used to populate
        ``Evidence.risk_metadata``.

        This is the SINGLE definition of that dict shape.  The Session 2
        integration adapter calls this method; the two representations are
        guaranteed to stay in sync because the dict is built here, not in
        the adapter.

        Returns
        -------
        dict with keys:
            evidence_field_name : str
            overall_score       : float
            risk_level          : str  ("LOW" / "MEDIUM" / "HIGH")
            summary             : list[str]
            detectors           : list[dict]
                Each item has: detector, score, confidence, matches,
                explanation.
        """
        return {
            "evidence_field_name": self.evidence_field_name,
            "overall_score": round(self.overall_score, 6),
            "risk_level": self.risk_level,
            "summary": list(self.summary),
            "detectors": [
                {
                    "detector": dr.detector,
                    "score": round(dr.score, 6),
                    "confidence": round(dr.confidence, 6),
                    "matches": list(dr.matches),
                    "explanation": list(dr.explanation),
                }
                for dr in self.detector_results
            ],
        }


# ---------------------------------------------------------------------------
# RiskAssessmentBundle
# ---------------------------------------------------------------------------

@dataclass
class RiskAssessmentBundle:
    """
    The complete risk assessment for a single incident (all evidence fields
    plus an incident-level result from the cross-field detector).

    Attributes
    ----------
    field_results : dict[str, RiskAssessmentResult]
        Keyed by evidence field name.  One entry per field that was assessed.

    incident_result : RiskAssessmentResult | None
        The result of the IncidentDetector (SplitFieldDetector) which
        analyses all fields together.  Set to None until Session 2 builds
        the orchestrator that populates it.
    """

    field_results: dict[str, RiskAssessmentResult] = field(default_factory=dict)
    incident_result: RiskAssessmentResult | None = None

    def to_dict(self) -> dict:
        """Serialise the full bundle for logging or storage."""
        return {
            "field_results": {
                k: v.to_dict() for k, v in self.field_results.items()
            },
            "incident_result": (
                self.incident_result.to_dict()
                if self.incident_result is not None
                else None
            ),
        }
