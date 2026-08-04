"""
risk_assessment/config.py

Central configuration for Evidence Risk Assessment (ERA) and Safe Prompt
Construction (SPC).  ALL tunable constants live here; no module in the
risk_assessment package hard-codes numeric values.

Import-time validation: REGEX_WEIGHT + SEMANTIC_WEIGHT + SPLIT_FIELD_WEIGHT
must sum to exactly 1.0 (to within floating-point tolerance).  This is
checked when this module is first imported so mis-configuration fails loudly
at startup rather than silently producing wrong scores at runtime.

Weight-choice rationale
-----------------------
Semantic gets the highest weight (0.40) because it is the only detector that
catches paraphrased injections — the hardest-to-detect category.
Split-field gets 0.35 because cross-field injection is a structurally distinct
and realistic attack vector that neither regex nor semantic covers well.
Regex gets 0.25: it is fast and precise for known literal phrases but adds
lower marginal value once semantic is in play.  These numbers are a reasoned
starting point; tune empirically once a labelled evaluation set exists.
"""

from __future__ import annotations

import math

# ---------------------------------------------------------------------------
# Detector weights
# Must sum to 1.0; enforced below.
# ---------------------------------------------------------------------------

# Literal/pattern-based detector.
# Lower weight than semantic — regex is high-precision but low-recall on
# paraphrases.  Reasonable starting point; tune empirically.
REGEX_WEIGHT: float = 0.25

# Embedding-based detector (all-MiniLM-L6-v2 cosine similarity).
# Highest weight: catches novel paraphrases that share little vocabulary
# with known exemplars — exactly what regex misses.
SEMANTIC_WEIGHT: float = 0.40

# Cross-field split-injection detector (built in Session 2).
# Defined here now so all config lives in one place from the start.
# Weight reflects that split-field attacks are realistic and distinct; set
# above regex because the cross-field signal is structurally harder for
# simpler detectors to catch.
SPLIT_FIELD_WEIGHT: float = 0.35

# Validate at import time — loud failure beats silent mis-scoring.
_WEIGHT_SUM = REGEX_WEIGHT + SEMANTIC_WEIGHT + SPLIT_FIELD_WEIGHT
if not math.isclose(_WEIGHT_SUM, 1.0, abs_tol=1e-9):
    raise ImportError(
        f"risk_assessment.config: REGEX_WEIGHT + SEMANTIC_WEIGHT + "
        f"SPLIT_FIELD_WEIGHT must sum to 1.0, got {_WEIGHT_SUM:.10f}.  "
        f"Adjust the weights in config.py before importing this module."
    )

# ---------------------------------------------------------------------------
# Semantic detector threshold
# ---------------------------------------------------------------------------

# Cosine similarity above which the semantic detector treats a match as a hit.
# 0.65 is deliberately chosen to be permissive enough to catch paraphrases
# while rejecting incidental semantic similarity.  The MiniLM model's cosine
# space is empirically tighter than raw TF-IDF cosine, so 0.65 maps to a
# meaningful surface-level match.  Tune downward for higher recall, upward
# for higher precision.
SEMANTIC_THRESHOLD: float = 0.65

# ---------------------------------------------------------------------------
# Orchestrator: single-detector ceiling
# ---------------------------------------------------------------------------

# If one detector's score exceeds this threshold, the orchestrator (Session 2)
# should not let a weighted average dilute it below HIGH.  Concretely: a
# single very confident detector should dominate the final risk level.
# 0.9 is chosen as a high-confidence bar — at this score the detector is
# effectively certain, so averaging with lower-scoring detectors would be
# misleading.
SINGLE_DETECTOR_CEILING_THRESHOLD: float = 0.90

# ---------------------------------------------------------------------------
# Risk level thresholds (applied to the weighted-average overall score)
# ---------------------------------------------------------------------------

# Stricter thresholds chosen deliberately: we prefer false positives (analyst
# review of a benign alert) over false negatives (missed injection attacks).
# LOW_RISK_THRESHOLD is the boundary above which a score is no longer ignored.
# MEDIUM / HIGH partition the remaining range.

# Score < LOW_RISK_THRESHOLD → LOW (likely benign, no immediate action)
LOW_RISK_THRESHOLD: float = 0.35

# LOW_RISK_THRESHOLD <= score < HIGH_RISK_THRESHOLD → MEDIUM (flag for review)
MEDIUM_RISK_THRESHOLD: float = 0.40

# score >= HIGH_RISK_THRESHOLD → HIGH (escalate / block)
HIGH_RISK_THRESHOLD: float = 0.70

# Readable note: the tier logic is
#   score < 0.35             → LOW
#   0.35 <= score < 0.70     → MEDIUM
#   score >= 0.70            → HIGH
# This means anything over 0.70 is HIGH — aggressive, intentional.

# ---------------------------------------------------------------------------
# Prompt construction limits (used by Session 2's safe prompt builder)
# ---------------------------------------------------------------------------

# Maximum characters to include from a single evidence field value in a prompt.
# Chosen to allow a realistic command line (~500 chars) while preventing prompt
# stuffing via extremely long evidence strings.  Tune based on LLM context
# window size and token budget.
MAX_PROMPT_FIELD_LENGTH: int = 512

# Maximum total characters for the evidence section of the assembled prompt.
# Prevents a prompt-injection attack from consuming the entire context window
# even if field-level truncation is bypassed somehow.  Provisional; tune
# empirically against the target model's context budget.
MAX_TOTAL_PROMPT_LENGTH: int = 2048
