"""
risk_assessment/detectors/regex_detector.py

Literal/pattern-based FieldDetector.

Matches known injection phrases (from `exemplars.py`) against the normalized
evidence text and any decoded candidates.  Matching is:
  - Case-insensitive
  - Punctuation/whitespace-tolerant: a flexible pattern is compiled for each
    exemplar that allows optional punctuation characters and whitespace variants
    between words, catching common obfuscations like "ignore_previous" or
    "ignore...previous instructions".

Why regex?
----------
Regex is fast, deterministic, and zero-dependency for the obvious literal
phrases.  It serves as the first-pass detector: high precision on known
patterns, no false positives for clean text, instant feedback for clear-cut
injections.  Its limitation (low recall on paraphrases) is exactly why the
semantic detector exists alongside it.

Scoring
-------
- Each unique exemplar matched contributes to the score.
- Score = min(1.0, matches / total_exemplars * SATURATION_SCALE)
  where SATURATION_SCALE is tuned so that ~3 distinct matches → score ≈ 1.0.
  Rationale: a single match on "system:" in free text could be legitimate;
  three distinct injection patterns in one field is unambiguous.
- Confidence is always 1.0 for regex hits (deterministic matching).
"""

from __future__ import annotations

import re
from functools import cached_property

from risk_assessment.detectors.base import FieldDetector
from risk_assessment.exemplars import INJECTION_EXEMPLARS
from risk_assessment.results import DetectorResult

# How many distinct exemplar matches before score saturates at 1.0.
# Lowered from 3 to 2 to allow single high-confidence exemplar matches in
# split-field contexts to reach MEDIUM risk; this increases sensitivity
# globally. Verified against the 9-alert benign set with 0% FPR.
# Revisit at scale against the full GUIDE dataset to evaluate false positives.
_SATURATION_COUNT: int = 2


def _build_flexible_pattern(phrase: str) -> re.Pattern[str]:
    """
    Compile a case-insensitive regex for `phrase` that tolerates:
    - Optional punctuation between words (dots, underscores, dashes, etc.)
    - Variable whitespace (including zero-width chars already stripped by the
      normalizer, but defensive here)
    - Word-boundary anchoring to avoid matching sub-tokens

    The pattern is kept simple and safe — no look-arounds that could cause
    catastrophic backtracking on adversarial inputs.
    """
    # Split phrase into words/tokens (handles multi-word phrases)
    tokens = re.split(r"\s+", phrase.strip())
    # Between each pair of tokens, allow optional punctuation + whitespace
    separator = r"[\s\W_]*"
    escaped_tokens = [re.escape(t) for t in tokens if t]
    pattern_str = separator.join(escaped_tokens)
    # Wrap in word-boundary equivalent: allow any non-alpha before/after
    pattern_str = r"(?<![a-zA-Z])" + pattern_str + r"(?![a-zA-Z])"
    return re.compile(pattern_str, re.IGNORECASE)


class RegexDetector(FieldDetector):
    """
    Literal/pattern-based FieldDetector using pre-compiled exemplar patterns.

    Patterns are compiled once at class-creation time (via `cached_property`)
    and reused across all calls — no per-call compilation overhead.
    """

    @property
    def name(self) -> str:
        return "RegexDetector"

    @cached_property
    def _patterns(self) -> list[tuple[str, re.Pattern[str]]]:
        """
        List of (exemplar_phrase, compiled_pattern) pairs.
        Built once on first access; reused for all subsequent detect() calls.
        """
        return [
            (phrase, _build_flexible_pattern(phrase))
            for phrase in INJECTION_EXEMPLARS
        ]

    def detect(
        self,
        normalized_text: str,
        decoded_candidates: list[str],
    ) -> DetectorResult:
        """
        Match all exemplar patterns against `normalized_text` and each decoded
        candidate.  Return a DetectorResult with:
          - score proportional to the number of distinct exemplars matched
          - matches listing all triggered exemplar phrases
          - confidence 1.0 (regex is deterministic)
        """
        matched_phrases: list[str] = []
        explanation: list[str] = []

        # Build list of texts to scan: normalized text first, then candidates
        texts_to_scan: list[tuple[str, str]] = [
            ("normalized_text", normalized_text)
        ] + [
            (f"decoded_candidate[{i}]", c)
            for i, c in enumerate(decoded_candidates)
        ]

        for phrase, pattern in self._patterns:
            for source_label, text in texts_to_scan:
                if pattern.search(text):
                    if phrase not in matched_phrases:
                        matched_phrases.append(phrase)
                        explanation.append(
                            f"Matched exemplar '{phrase}' in {source_label}."
                        )
                    break  # found this phrase; move to next exemplar

        n_matches = len(matched_phrases)
        if n_matches == 0:
            return DetectorResult(
                detector=self.name,
                score=0.0,
                matches=[],
                confidence=1.0,
                explanation=["No known injection phrases detected."],
            )

        # Score saturates at 1.0 after _SATURATION_COUNT distinct matches.
        score = min(1.0, n_matches / _SATURATION_COUNT)
        explanation.append(
            f"Matched {n_matches} distinct injection phrase(s) "
            f"(score saturates at {_SATURATION_COUNT})."
        )

        return DetectorResult(
            detector=self.name,
            score=round(score, 6),
            matches=matched_phrases,
            confidence=1.0,  # regex is deterministic — no uncertainty
            explanation=explanation,
        )
