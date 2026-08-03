"""
risk_assessment/detectors/split_field_detector.py

IncidentDetector that catches prompt-injection phrases deliberately split
across multiple evidence fields.

Attack model
------------
An attacker who knows the pipeline inspects individual fields may try to evade
detection by making each field innocuous in isolation:
    process_name  = "ignore previous"
    command_line  = "instructions and do something malicious"

Neither RegexDetector nor SemanticDetector catches this because each runs on
exactly one field.  SplitFieldDetector concatenates ALL fields with visible
boundary markers, then re-runs the existing detector logic on the combined
string.  The assembled text exposes the cross-field injection phrase as a
contiguous match.

Design principles
-----------------
- Re-uses RegexDetector and SemanticDetector — does NOT duplicate their logic.
- Boundaries: ``[FIELD:name]`` markers appear before each field's text so that
  if a match spans a boundary, analysts can identify which fields contributed.
- Only non-empty, non-whitespace fields are concatenated; missing fields are
  omitted from the combined string entirely (cleaner signal, fewer false hits
  from joining empty strings with punctuation).
- Returns a single DetectorResult representing the combined-field finding.
  The score is the higher of the regex and semantic scores on the combined text,
  because either detector independently catching the cross-field phrase
  constitutes a confirmed hit.

Relationship to FieldDetectors
-------------------------------
SplitFieldDetector implements IncidentDetector, not FieldDetector.  It
receives ``dict[str, NormalizationResult]`` (all fields), not a single field.
The orchestrator calls it once per incident, AFTER running FieldDetectors on
each individual field.
"""

from __future__ import annotations

from risk_assessment.detectors.base import IncidentDetector
from risk_assessment.detectors.regex_detector import RegexDetector
from risk_assessment.detectors.semantic_detector import SemanticDetector
from risk_assessment.results import DetectorResult, NormalizationResult

# Module-level detector instances — re-used, not re-created per call.
# This mirrors the registry pattern: shared singleton detectors.
_REGEX: RegexDetector = RegexDetector()
_SEMANTIC: SemanticDetector = SemanticDetector()

# Separator placed between field blocks in the concatenated string.
# Chosen to be human-readable and not a valid injection phrase itself.
_FIELD_SEPARATOR: str = " "


def _build_combined_text(all_fields: dict[str, NormalizationResult]) -> str:
    """
    Concatenate all normalized field texts into a single candidate string.

    Each field is preceded by a ``[FIELD:<name>]`` boundary marker so that:
    1. Analysts can identify which fields contributed to a cross-field hit.
    2. The separator itself is not an injection-triggering substring.

    Only fields whose normalized_text (or any decoded_candidate) is non-empty
    after stripping are included.  This avoids false positive signals from
    empty-field separators.
    """
    parts: list[str] = []
    for field_name, norm_result in all_fields.items():
        # Include normalized text if non-empty
        text = norm_result.normalized_text.strip()
        candidates = [c.strip() for c in norm_result.decoded_candidates if c.strip()]
        if not text and not candidates:
            continue  # skip entirely-empty fields

        # Combine the normalized text + any decoded candidates for this field
        field_content_parts = []
        if text:
            field_content_parts.append(text)
        field_content_parts.extend(candidates)
        field_content = " ".join(field_content_parts)

        parts.append(f"[FIELD:{field_name}] {field_content}")

    return _FIELD_SEPARATOR.join(parts)


class SplitFieldDetector(IncidentDetector):
    """
    IncidentDetector that detects injection phrases split across multiple fields.

    Concatenates all evidence fields with boundary markers, then runs the
    existing RegexDetector and SemanticDetector on the merged string.  Returns
    the higher of the two detector scores as the overall split-field score.

    Why take the maximum rather than weighted average?
    --------------------------------------------------
    This detector's purpose is to surface cross-field signal that neither
    individual detector caught in isolation.  If either detector fires on the
    combined text, that is meaningful evidence of a split injection — the score
    should reflect the best evidence, not an average that dilutes a clear hit.
    The orchestrator's ceiling rule handles further aggregation with field-level
    scores.
    """

    @property
    def name(self) -> str:
        return "SplitFieldDetector"

    def detect(
        self,
        all_fields: dict[str, NormalizationResult],
    ) -> DetectorResult:
        """
        Concatenate all evidence fields and run regex + semantic detection.

        Parameters
        ----------
        all_fields : dict[str, NormalizationResult]
            Keys = evidence field names; values = their NormalizationResults.
            All values are read-only; this method does not mutate them.

        Returns
        -------
        DetectorResult
            score = max(regex_score, semantic_score) on the combined text.
            score = 0.0 if no fields have content or no hit is detected.
        """
        if not all_fields:
            return DetectorResult(
                detector=self.name,
                score=0.0,
                matches=[],
                confidence=0.0,
                explanation=["No evidence fields provided to SplitFieldDetector."],
            )

        combined_text = _build_combined_text(all_fields)

        if not combined_text.strip():
            return DetectorResult(
                detector=self.name,
                score=0.0,
                matches=[],
                confidence=0.0,
                explanation=["All evidence fields were empty; no cross-field analysis performed."],
            )

        # Run existing detectors on the combined text.
        # decoded_candidates=[] because the combined text already incorporates
        # any decoded candidates from each field's NormalizationResult.
        regex_result: DetectorResult = _REGEX.detect(
            normalized_text=combined_text,
            decoded_candidates=[],
        )
        semantic_result: DetectorResult = _SEMANTIC.detect(
            normalized_text=combined_text,
            decoded_candidates=[],
        )

        # Score = maximum of the two detector scores on the combined text.
        # Either detector independently catching the cross-field phrase is
        # sufficient evidence of a split injection.
        best_score = max(regex_result.score, semantic_result.score)
        best_confidence = max(regex_result.confidence, semantic_result.confidence)

        # Aggregate matches and explanations from both sub-detectors
        all_matches: list[str] = []
        all_explanations: list[str] = []

        if regex_result.score > 0.0:
            all_matches.extend(regex_result.matches)
            all_explanations.extend([
                f"[RegexDetector on combined text] {exp}"
                for exp in regex_result.explanation
            ])
        if semantic_result.score > 0.0:
            all_matches.extend(semantic_result.matches)
            all_explanations.extend([
                f"[SemanticDetector on combined text] {exp}"
                for exp in semantic_result.explanation
            ])

        if best_score == 0.0:
            return DetectorResult(
                detector=self.name,
                score=0.0,
                matches=[],
                confidence=0.0,
                explanation=[
                    "No injection phrases detected in combined cross-field text. "
                    f"Fields combined: {list(all_fields.keys())}."
                ],
            )

        all_explanations.append(
            f"Cross-field analysis combined {len(all_fields)} field(s): "
            f"{list(all_fields.keys())}. "
            "An injection phrase that spans multiple individual fields was detected."
        )

        return DetectorResult(
            detector=self.name,
            score=round(best_score, 6),
            matches=list(dict.fromkeys(all_matches)),  # deduplicate, preserve order
            confidence=round(best_confidence, 6),
            explanation=all_explanations,
        )
