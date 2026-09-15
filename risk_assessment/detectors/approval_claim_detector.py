"""
risk_assessment/detectors/approval_claim_detector.py

Structural signature detector for fabricated evidence and false approval claims.

Detects co-occurrence of:
1. Reference/ticket-ID-shaped tokens (e.g. SEC-TICKET#7821, INC-884721, WL-30294, TI-2025-1847, CHG-88421)
2. Disposition and approval claims (e.g. approved, whitelist, closed, resolved, verified, false positive)

Scoring logic (v2 — structural gating):
- Ticket + disposition co-occur INSIDE a field-assignment (key="value") span
  -> this is the injection shape seen in every real fabricated_evidence attack sample
  -> score = 0.90 (triggers SINGLE_DETECTOR_CEILING_THRESHOLD override)
    - UNLESS a distancing keyword appears within PROXIMITY_WINDOW_CHARS of the
      matched span -> suppressed to 0.20
- Ticket + disposition co-occur but NOT inside a field-assignment span
  -> this is the narrative/prose shape (e.g. "policy rule WL-30294 approved and
     whitelisted"), which legitimate operational logs also produce
  -> score = 0.40 (elevated signal, but below HIGH ceiling; does not alone
     trigger ceiling override)
- Single signal only -> score = 0.20
- Neither signal -> score = 0.00

Rationale: the earlier version suppressed/fired based on whole-text-blob
co-occurrence, which produced both a false negative (a real attack containing
an unrelated distancing word anywhere in a long log line) and a false positive
(a legitimate prose sentence that happens to contain both a ticket-shaped
token and a disposition word, with no injection structure at all). Both fixes
are narrowly scoped to structural/positional signal rather than new keyword
lists, so they should not need to be retuned every time a new phrasing shows
up.
"""

from __future__ import annotations

import re
from functools import cached_property

from risk_assessment.detectors.base import FieldDetector
from risk_assessment.results import DetectorResult

# Regex matching ticket, change-request, whitelist, and incident reference ID formats
_TICKET_PATTERN: re.Pattern[str] = re.compile(
    r"\b[A-Z]{2,16}(?:[-_][A-Za-z0-9]+)*[-#]\d{3,}(?:[-_][A-Za-z0-9]+)*\b"
)

# Field-assignment shape used by every observed fabricated_evidence attack sample:
# audit_annotation="WHITELIST-ENTRY#WL-30294...", annotation_ref="SEC-TICKET#7821..."
# Captures the quoted value so we can test whether ticket/keyword matches fall inside it.
_FIELD_ASSIGNMENT_PATTERN: re.Pattern[str] = re.compile(
    r'\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*"([^"]*)"'
)

# Attack payloads observed in the corpus use a malformed nested-quote shape:
# OUTER_KEY="inner_key=VALUE_WITH_TICKET_AND_DISPOSITION"" (note trailing "")
# The original single-level pattern stops at the first inner quote and misses
# this entirely. This pattern specifically targets that nested shape.
_NESTED_FIELD_ASSIGNMENT_PATTERN: re.Pattern[str] = re.compile(
    r'\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*"\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*"(.*?)""'
)

# Generic disposition, approval, and verification terms asserting security verdict overrides
_DISPOSITION_KEYWORDS: tuple[str, ...] = (
    "disposition=",
    "classification=trusted",
    "false positive",
    "false-positive",
    "closed as fp",      # NEW — matches "closed as FP" phrasing seen in corpus
    "benign-fp",
    "no further action",
    "closed-resolved",
    "authorized-admin-triage",
    "whitelist",
    "whitelisted",
    "cleared",
    "security sign-off",
    "security signoff",
    "security exemption",
    "pre-approved",
    "preapproved",
)

# Distancing language indicating historical references rather than current claims
_DISTANCING_KEYWORDS: tuple[str, ...] = (
    "prior",
    "previous",
    "last quarter",
    "last year",
    "historical",
    "unrelated to",
    "earlier",
    "in the past",
)

# How close (in characters) a distancing keyword must be to a ticket/disposition
# match to suppress it. Narrow on purpose: this should catch "prior finding
# INC-4471" (Legit-1) style adjacency, not an unrelated distancing word
# anywhere in a long log line (the 1013612281869 false-negative case).
_PROXIMITY_WINDOW_CHARS: int = 80

# Score for field-injection-shaped co-occurrence (the real attack pattern).
_SCORE_FIELD_INJECTION: float = 0.90
# Score for narrative/prose-shaped co-occurrence (e.g. Legit-3) — elevated but
# below the HIGH ceiling so it doesn't alone force a ceiling override.
_SCORE_NARRATIVE_COOCCURRENCE: float = 0.40
# Score for suppressed or single-signal-only matches.
_SCORE_LOW: float = 0.20


class ApprovalClaimDetector(FieldDetector):
    """
    FieldDetector that detects structural signatures of fabricated evidence attacks.

    Fabricated evidence attacks inject pseudo-authoritative claims (such as fake ticket
    closures, whitelist entries, and pre-approval annotations) into untrusted telemetry
    to trick agentic SOC analyzers into classifying malicious activity as benign.

    v2: distinguishes field-injection-shaped co-occurrence (key="value" spans,
    matching the actual attack mechanism) from narrative-prose co-occurrence
    (legitimate logs describing a real action in sentence form), and scopes
    distancing-language suppression to proximity of the match rather than
    whole-text presence.
    """

    @property
    def name(self) -> str:
        return "ApprovalClaimDetector"

    @cached_property
    def _keyword_patterns(self) -> list[tuple[str, re.Pattern[str]]]:
        """Pre-compile patterns for each disposition keyword with appropriate boundaries."""
        return [
            (
                kw,
                re.compile(
                    (r"\b" if kw[0].isalnum() else "") +
                    re.escape(kw) +
                    (r"\b" if kw[-1].isalnum() else ""),
                    re.IGNORECASE,
                ),
            )
            for kw in _DISPOSITION_KEYWORDS
        ]

    @cached_property
    def _distancing_patterns(self) -> list[tuple[str, re.Pattern[str]]]:
        """Pre-compile patterns for distancing keywords."""
        return [
            (
                dk,
                re.compile(
                    (r"\b" if dk[0].isalnum() else "") +
                    re.escape(dk) +
                    (r"\b" if dk[-1].isalnum() else ""),
                    re.IGNORECASE,
                ),
            )
            for dk in _DISTANCING_KEYWORDS
        ]

    @staticmethod
    def _find_ticket_spans(text: str) -> list[tuple[str, int, int]]:
        """Return (matched_text, start, end) for every ticket-shaped token."""
        return [(m.group(0), m.start(), m.end()) for m in _TICKET_PATTERN.finditer(text)]

    def _find_keyword_spans(self, text: str) -> list[tuple[str, int, int]]:
        """Return (keyword, start, end) for every disposition keyword match."""
        spans: list[tuple[str, int, int]] = []
        for kw, pattern in self._keyword_patterns:
            for m in pattern.finditer(text):
                spans.append((kw, m.start(), m.end()))
        return spans

    def _find_distancing_spans(self, text: str) -> list[tuple[str, int, int]]:
        """Return (keyword, start, end) for every distancing keyword match."""
        spans: list[tuple[str, int, int]] = []
        for dk, pattern in self._distancing_patterns:
            for m in pattern.finditer(text):
                spans.append((dk, m.start(), m.end()))
        return spans

    @staticmethod
    def _find_field_assignment_spans(text: str) -> list[tuple[int, int]]:
        """Return (start, end) of each field-assignment value span found in text.
        Covers both single-level key="value" and the malformed nested
        key="inner_key=value"" shape seen in real fabricated_evidence attacks."""
        spans: list[tuple[int, int]] = []
        for m in _NESTED_FIELD_ASSIGNMENT_PATTERN.finditer(text):
            spans.append(m.span(1))
        for m in _FIELD_ASSIGNMENT_PATTERN.finditer(text):
            span = m.span(1)
            # Skip spans already covered by a nested match to avoid double-processing
            if not any(ns <= span[0] and span[1] <= ne for ns, ne in spans):
                spans.append(span)
        return spans

    @staticmethod
    def _span_within_any(span: tuple[int, int], containers: list[tuple[int, int]]) -> bool:
        s, e = span
        return any(cs <= s and e <= ce for cs, ce in containers)

    @staticmethod
    def _min_distance(span_a: tuple[int, int], span_b: tuple[int, int]) -> int:
        """Character distance between two spans (0 if overlapping)."""
        a_start, a_end = span_a
        b_start, b_end = span_b
        if a_end <= b_start:
            return b_start - a_end
        if b_end <= a_start:
            return a_start - b_end
        return 0

    def detect(
        self,
        normalized_text: str,
        decoded_candidates: list[str],
    ) -> DetectorResult:
        """
        Scan normalized_text and decoded candidates for ticket IDs and disposition keywords,
        gating severity on whether the co-occurrence is field-injection-shaped or
        narrative-prose-shaped, and scoping distancing-language suppression to proximity.
        """
        texts_to_scan: list[tuple[str, str]] = [
            ("normalized_text", normalized_text)
        ] + [
            (f"decoded_candidate[{i}]", c)
            for i, c in enumerate(decoded_candidates)
        ]

        all_ticket_matches: list[str] = []
        all_keyword_matches: list[str] = []
        all_suppression_matches: list[str] = []

        best_tier = "none"  # "none" | "low" | "suppressed" | "narrative" | "field_injection"

        for source_label, text in texts_to_scan:
            if not text.strip():
                continue

            ticket_spans = self._find_ticket_spans(text)
            keyword_spans = self._find_keyword_spans(text)
            distancing_spans = self._find_distancing_spans(text)
            field_spans = self._find_field_assignment_spans(text)

            for t, _, _ in ticket_spans:
                if t not in all_ticket_matches:
                    all_ticket_matches.append(t)
            for kw, _, _ in keyword_spans:
                if kw not in all_keyword_matches:
                    all_keyword_matches.append(kw)

            if not ticket_spans or not keyword_spans:
                if (ticket_spans or keyword_spans) and best_tier == "none":
                    best_tier = "low"
                continue

            # Examine every ticket/keyword pair in this text for co-occurrence shape.
            for t_text, t_start, t_end in ticket_spans:
                for kw, k_start, k_end in keyword_spans:
                    t_span = (t_start, t_end)
                    k_span = (k_start, k_end)

                    both_in_field = self._span_within_any(
                        t_span, field_spans
                    ) and self._span_within_any(k_span, field_spans)

                    # Nearest distancing keyword to this specific pair, for
                    # proximity-scoped suppression.
                    nearby_distancing = [
                        dk
                        for dk, d_start, d_end in distancing_spans
                        if min(
                            self._min_distance(t_span, (d_start, d_end)),
                            self._min_distance(k_span, (d_start, d_end)),
                        )
                        <= _PROXIMITY_WINDOW_CHARS
                    ]
                    for dk in nearby_distancing:
                        if dk not in all_suppression_matches:
                            all_suppression_matches.append(dk)

                    if both_in_field:
                        if nearby_distancing:
                            tier = "suppressed"
                        else:
                            tier = "field_injection"
                    else:
                        # Narrative-shaped co-occurrence. Distancing language
                        # nearby still suppresses (e.g. "prior finding
                        # INC-4471" narrative style, Legit-1).
                        tier = "suppressed" if nearby_distancing else "narrative"

                    # Rank: field_injection > narrative > suppressed > low > none
                    tier_rank = {
                        "none": 0,
                        "low": 1,
                        "suppressed": 2,
                        "narrative": 3,
                        "field_injection": 4,
                    }
                    if tier_rank[tier] > tier_rank[best_tier]:
                        best_tier = tier

        if best_tier == "field_injection":
            all_matches = [f"ticket:{t}" for t in all_ticket_matches] + [
                f"disposition:{k}" for k in all_keyword_matches
            ]
            return DetectorResult(
                detector=self.name,
                score=_SCORE_FIELD_INJECTION,
                matches=all_matches,
                confidence=1.0,
                explanation=[
                    f"Detected reference/ticket ID ({all_ticket_matches}) and disposition "
                    f"claim ({all_keyword_matches}) co-occurring inside a field-assignment "
                    f"(key=\"value\") span, matching the injection shape observed in known "
                    f"fabricated_evidence attacks.",
                    "No suppressing distancing language found within proximity of the match.",
                ],
            )

        if best_tier == "narrative":
            all_matches = [f"ticket:{t}" for t in all_ticket_matches] + [
                f"disposition:{k}" for k in all_keyword_matches
            ]
            return DetectorResult(
                detector=self.name,
                score=_SCORE_NARRATIVE_COOCCURRENCE,
                matches=all_matches,
                confidence=0.7,
                explanation=[
                    f"Detected reference/ticket ID ({all_ticket_matches}) and disposition "
                    f"claim ({all_keyword_matches}) co-occurring, but NOT inside a "
                    f"field-assignment span — narrative/prose shape, consistent with a "
                    f"legitimate log describing a real action rather than an injected field.",
                    "Scored below the ceiling-override threshold on structural grounds alone.",
                ],
            )

        if best_tier == "suppressed":
            all_matches = (
                [f"ticket:{t}" for t in all_ticket_matches]
                + [f"disposition:{k}" for k in all_keyword_matches]
                + [f"suppression:{s}" for s in all_suppression_matches]
            )
            return DetectorResult(
                detector=self.name,
                score=_SCORE_LOW,
                matches=all_matches,
                confidence=0.5,
                explanation=[
                    f"Detected co-occurrence of reference/ticket ID ({all_ticket_matches}) "
                    f"and disposition claim ({all_keyword_matches}) BUT it was suppressed by "
                    f"nearby distancing language ({all_suppression_matches}) within "
                    f"{_PROXIMITY_WINDOW_CHARS} characters of the match.",
                ],
            )

        if best_tier == "low":
            has_tickets = len(all_ticket_matches) > 0
            partial_matches = (
                [f"ticket:{t}" for t in all_ticket_matches]
                if has_tickets
                else [f"disposition:{k}" for k in all_keyword_matches]
            )
            return DetectorResult(
                detector=self.name,
                score=_SCORE_LOW,
                matches=partial_matches,
                confidence=0.5,
                explanation=[
                    f"Single-component match detected "
                    f"({'ticket IDs only' if has_tickets else 'disposition keywords only'}): "
                    f"{all_ticket_matches if has_tickets else all_keyword_matches}. "
                    "No co-occurrence detected.",
                ],
            )

        return DetectorResult(
            detector=self.name,
            score=0.0,
            matches=[],
            confidence=1.0,
            explanation=["No approval claims or reference IDs detected."],
        )