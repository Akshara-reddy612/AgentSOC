"""
risk_assessment/detectors/approval_claim_detector.py

Structural signature detector for fabricated evidence and false approval claims.

Detects co-occurrence of:
1. Reference/ticket-ID-shaped tokens (e.g. SEC-TICKET#7821, INC-884721, WL-30294, TI-2025-1847, CHG-88421)
2. Disposition and approval claims (e.g. approved, whitelist, closed, resolved, verified, false positive)

Scoring logic:
- Co-occurrence of BOTH signals -> score = 0.90 (triggers SINGLE_DETECTOR_CEILING_THRESHOLD override)
- Single signal only -> score = 0.20 (low confidence, does not trigger ceiling override)
- Neither signal -> score = 0.00
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

# Generic disposition, approval, and verification terms asserting security verdict overrides
_DISPOSITION_KEYWORDS: tuple[str, ...] = (
    "disposition=",
    "classification=trusted",
    "false positive",
    "false-positive",
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


class ApprovalClaimDetector(FieldDetector):
    """
    FieldDetector that detects structural signatures of fabricated evidence attacks.

    Fabricated evidence attacks inject pseudo-authoritative claims (such as fake ticket
    closures, whitelist entries, and pre-approval annotations) into untrusted telemetry
    to trick agentic SOC analyzers into classifying malicious activity as benign.
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

    def detect(
        self,
        normalized_text: str,
        decoded_candidates: list[str],
    ) -> DetectorResult:
        """
        Scan normalized_text and decoded candidates for ticket IDs and disposition keywords.
        """
        texts_to_scan: list[tuple[str, str]] = [
            ("normalized_text", normalized_text)
        ] + [
            (f"decoded_candidate[{i}]", c)
            for i, c in enumerate(decoded_candidates)
        ]

        ticket_matches: list[str] = []
        keyword_matches: list[str] = []
        suppression_matches: list[str] = []
        explanation: list[str] = []

        has_unsuppressed_cooccurrence = False
        has_suppressed_cooccurrence = False

        for source_label, text in texts_to_scan:
            if not text.strip():
                continue

            # 1. Scan for ticket/reference ID tokens
            tickets_found = _TICKET_PATTERN.findall(text)
            
            # 2. Scan for disposition keywords
            keywords_found: list[str] = []
            for kw, pattern in self._keyword_patterns:
                if pattern.search(text):
                    keywords_found.append(kw)

            # Accumulate matches for metadata/matches field
            for t in tickets_found:
                if t not in ticket_matches:
                    ticket_matches.append(t)
            for kw in keywords_found:
                if kw not in keyword_matches:
                    keyword_matches.append(kw)

            # Check if both exist in this specific text (co-occurrence)
            if len(tickets_found) > 0 and len(keywords_found) > 0:
                # Check for distancing language in this specific text
                distancing_found: list[str] = []
                for dk, pattern in self._distancing_patterns:
                    if pattern.search(text):
                        distancing_found.append(dk)
                        if dk not in suppression_matches:
                            suppression_matches.append(dk)

                if len(distancing_found) > 0:
                    has_suppressed_cooccurrence = True
                else:
                    has_unsuppressed_cooccurrence = True

        # Case 1: Active/unsuppressed co-occurrence -> High confidence hit (0.90)
        if has_unsuppressed_cooccurrence:
            score = 0.90
            all_matches = [f"ticket:{t}" for t in ticket_matches] + [
                f"disposition:{k}" for k in keyword_matches
            ]
            explanation.append(
                f"Detected active/unsuppressed co-occurrence of reference/ticket ID ({ticket_matches}) "
                f"and disposition claim ({keyword_matches})."
            )
            explanation.append(
                "Structural signature indicates fabricated evidence / false approval claim."
            )
            return DetectorResult(
                detector=self.name,
                score=score,
                matches=all_matches,
                confidence=1.0,
                explanation=explanation,
            )

        # Case 2: Co-occurrence detected but suppressed by distancing language -> Low confidence (0.20)
        if has_suppressed_cooccurrence:
            score = 0.20
            all_matches = [f"ticket:{t}" for t in ticket_matches] + [
                f"disposition:{k}" for k in keyword_matches
            ] + [f"suppression:{s}" for s in suppression_matches]
            explanation.append(
                f"Detected co-occurrence of reference/ticket ID ({ticket_matches}) "
                f"and disposition claim ({keyword_matches}) BUT it was suppressed "
                f"by distancing language ({suppression_matches})."
            )
            return DetectorResult(
                detector=self.name,
                score=score,
                matches=all_matches,
                confidence=0.5,
                explanation=explanation,
            )

        # Case 3: Partial match (only ticket ID or only keyword) -> Low confidence (0.20)
        has_tickets = len(ticket_matches) > 0
        has_keywords = len(keyword_matches) > 0
        if has_tickets or has_keywords:
            score = 0.20
            partial_matches = (
                [f"ticket:{t}" for t in ticket_matches]
                if has_tickets
                else [f"disposition:{k}" for k in keyword_matches]
            )
            explanation.append(
                f"Single-component match detected ({'ticket IDs only' if has_tickets else 'disposition keywords only'}): "
                f"{ticket_matches if has_tickets else keyword_matches}. "
                "No co-occurrence detected."
            )
            return DetectorResult(
                detector=self.name,
                score=score,
                matches=partial_matches,
                confidence=0.5,
                explanation=explanation,
            )

        # Case 4: Clean (0.00)
        return DetectorResult(
            detector=self.name,
            score=0.0,
            matches=[],
            confidence=1.0,
            explanation=["No approval claims or reference IDs detected."],
        )

