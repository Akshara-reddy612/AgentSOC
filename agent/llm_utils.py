"""
agent/llm_utils.py

Shared LLM-calling utilities used by baseline_agent.py, defended_agent.py,
and perception/nce_engine.py.

Extracted from baseline_agent.py (Phase NCE-4) to eliminate cross-module
imports of private (underscore-prefixed) names.  All symbols here are the
canonical public implementations — callers should import from this module.

Contents
--------
- RATE_LIMIT_KEYWORDS — tuple of substrings that signal a rate-limit error
- RETRY_DELAYS — list of back-off durations in seconds
- is_rate_limit_error(exc) — checks whether an exception is rate-limit-related
- strip_code_fence(text) — removes markdown ```json fences from LLM output
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Rate-limit detection
# ---------------------------------------------------------------------------

RATE_LIMIT_KEYWORDS: tuple[str, ...] = (
    "429",
    "rateLimitExceeded",
    "RESOURCE_EXHAUSTED",
    "quota",
    "rate limit",
    "too many requests",
    "503",
    "unavailable",
)

RETRY_DELAYS: list[int] = [2, 5]  # seconds; up to 2 retries


def is_rate_limit_error(exc: Exception) -> bool:
    """Return True if the exception message contains rate-limit keywords."""
    msg = str(exc).lower()
    return any(k.lower() in msg for k in RATE_LIMIT_KEYWORDS)


# ---------------------------------------------------------------------------
# Response cleanup
# ---------------------------------------------------------------------------

def strip_code_fence(text: str) -> str:
    """Remove markdown ```json ... ``` fences if the model added them."""
    text = text.strip()
    if text.startswith("```"):
        # Drop the first line (```json or ```) and the closing ```
        lines = text.splitlines()
        # Remove leading fence line
        lines = lines[1:]
        # Remove trailing fence line if present
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text
