"""
risk_assessment/normalization.py

Text normalization pipeline for Evidence Risk Assessment.

Given a raw evidence string, `normalize_text()` returns a `NormalizationResult`
containing the normalized text, any decoded candidates (e.g. from base64
substrings), and a log of steps that changed the input.

IMPORTANT: the original raw string is NEVER modified.  Every step produces a
new string.  The `NormalizationResult` is a snapshot of the pipeline's output;
the caller's `raw_text` argument is untouched.

Pipeline steps (applied in order)
----------------------------------
1. Unicode NFKC normalization
   - Converts compatibility characters (e.g. fullwidth ASCII, ligatures,
     superscripts) to their canonical equivalents.
   - Handles a broad class of homoglyphs that decompose under NFKC.
   - Implemented via `unicodedata.normalize("NFKC", text)`.

2. Homoglyph normalization
   - Catches visually-similar characters NOT handled by NFKC — primarily
     Cyrillic, Greek, and Armenian lookalikes that are separate Unicode
     code points and do not decompose.
   - Uses the `confusables` library (pip install confusables), which
     implements the Unicode Confusables standard (UTR #39).
   - Falls back gracefully if `confusables` is not installed (steps_applied
     will note "confusables library unavailable — skipped").

3. Whitespace normalization
   - Collapses any run of whitespace (including unusual Unicode whitespace)
     to a single ASCII space.
   - Strips leading/trailing whitespace.
   - Removes zero-width characters (U+200B, U+200C, U+200D, U+FEFF, etc.)
     which are invisible but can split keywords to defeat regex matching.

4. Base64 decoding
   - Scans the normalized text for substrings that look like base64-encoded
     data (≥16 chars of base64 alphabet, optionally padded).
   - Attempts to decode each candidate; if successful and the result is
     printable UTF-8, normalizes the decoded string and adds it to
     `decoded_candidates`.
   - Does NOT alter `normalized_text` — the decoded strings are additional
     candidates for detectors to inspect.

Extensibility
-------------
New steps (URL decoding, HTML entity decoding, hex decoding, ROT13, etc.)
can be added by inserting a step function into `_PIPELINE` below.  The
`normalize_text()` function's external API and return type are unchanged.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from typing import Callable

from risk_assessment.results import NormalizationResult

# ---------------------------------------------------------------------------
# Zero-width / invisible characters to strip
# ---------------------------------------------------------------------------
_ZERO_WIDTH_CHARS: frozenset[str] = frozenset(
    "\u200b"  # ZERO WIDTH SPACE
    "\u200c"  # ZERO WIDTH NON-JOINER
    "\u200d"  # ZERO WIDTH JOINER
    "\u200e"  # LEFT-TO-RIGHT MARK
    "\u200f"  # RIGHT-TO-LEFT MARK
    "\u2060"  # WORD JOINER
    "\u2061"  # FUNCTION APPLICATION
    "\u2062"  # INVISIBLE TIMES
    "\u2063"  # INVISIBLE SEPARATOR
    "\u2064"  # INVISIBLE PLUS
    "\ufeff"  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "\u00ad"  # SOFT HYPHEN
)
_ZERO_WIDTH_PATTERN = re.compile(
    "[" + re.escape("".join(_ZERO_WIDTH_CHARS)) + "]"
)

# ---------------------------------------------------------------------------
# Base64 detection pattern
# Matches strings of ≥16 base64 characters (URL-safe or standard alphabet)
# with optional padding.  The 16-char minimum avoids false positives on
# short alphanumeric tokens.
# ---------------------------------------------------------------------------
_BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/=_-])"  # negative lookbehind — not mid-token
    r"([A-Za-z0-9+/]{16,}={0,2}"  # standard base64
    r"|[A-Za-z0-9_-]{16,}={0,2})"  # URL-safe base64
    r"(?![A-Za-z0-9+/=_-])"        # negative lookahead
)


# ---------------------------------------------------------------------------
# Step 1: Unicode NFKC
# ---------------------------------------------------------------------------

def _step_unicode_nfkc(text: str) -> tuple[str, list[str]]:
    """Apply NFKC normalization.  Returns (result, steps_applied)."""
    result = unicodedata.normalize("NFKC", text)
    if result != text:
        return result, ["unicode_nfkc: converted compatibility/composed characters"]
    return result, []


# ---------------------------------------------------------------------------
# Step 2: Homoglyph normalization via confusables
# ---------------------------------------------------------------------------

def _step_homoglyph(text: str) -> tuple[str, list[str]]:
    """
    Normalize visually-similar characters to their ASCII or Latin canonical
    form using the Unicode Confusables standard.

    Uses the `confusables` library if available.  Falls back to a minimal
    hand-crafted table for the most common Cyrillic/Greek lookalikes if the
    library is missing.
    """
    try:
        import confusables  # type: ignore[import]
        # confusables.normalize returns a list of possible normalized forms;
        # we take the first (most canonical) result.
        candidates = confusables.normalize(text, prioritize="latin")
        result = candidates[0] if candidates else text
        # confusables may return None or unchanged
        if result is None:
            result = text
        if result != text:
            return result, ["homoglyph_confusables: normalized confusable characters"]
        return result, []
    except ImportError:
        pass
    except Exception:
        # confusables raised an unexpected error — fall through to minimal table
        pass

    # Minimal fallback table: most common Cyrillic/Greek homoglyphs not caught
    # by NFKC.  Covers the most common prompt-injection obfuscation characters.
    _FALLBACK_TABLE: dict[str, str] = {
        "\u0430": "a",  # Cyrillic а → Latin a
        "\u0435": "e",  # Cyrillic е → Latin e
        "\u043e": "o",  # Cyrillic о → Latin o
        "\u0440": "p",  # Cyrillic р → Latin p
        "\u0441": "c",  # Cyrillic с → Latin c
        "\u0445": "x",  # Cyrillic х → Latin x
        "\u0456": "i",  # Cyrillic і → Latin i
        "\u04cf": "l",  # Cyrillic ӏ → Latin l
        "\u03b1": "a",  # Greek α → Latin a
        "\u03b5": "e",  # Greek ε → Latin e
        "\u03bf": "o",  # Greek ο → Latin o
        "\u0399": "I",  # Greek Ι → Latin I
        "\u03bd": "v",  # Greek ν → Latin v
        "\u03c5": "u",  # Greek υ → Latin u
    }
    result = text.translate(str.maketrans(_FALLBACK_TABLE))
    if result != text:
        return result, ["homoglyph_fallback_table: normalized common homoglyphs"]
    return result, []


# ---------------------------------------------------------------------------
# Step 3: Whitespace normalization
# ---------------------------------------------------------------------------

def _step_whitespace(text: str) -> tuple[str, list[str]]:
    """
    Remove zero-width characters, collapse unusual whitespace to single
    ASCII spaces, and strip leading/trailing whitespace.
    """
    steps: list[str] = []

    # Remove zero-width / invisible chars
    cleaned = _ZERO_WIDTH_PATTERN.sub("", text)
    if cleaned != text:
        steps.append("whitespace_norm: removed zero-width/invisible characters")

    # Collapse any whitespace sequence (including \t, \r, \n, non-breaking
    # space U+00A0, ideographic space U+3000, etc.) to a single ASCII space.
    collapsed = re.sub(r"[^\S\n]+", " ", cleaned)  # preserve newlines
    collapsed = re.sub(r"\n+", "\n", collapsed)    # collapse multiple newlines
    collapsed = collapsed.strip()
    if collapsed != cleaned:
        steps.append("whitespace_norm: collapsed unusual whitespace")

    return collapsed, steps


# ---------------------------------------------------------------------------
# Step 4: Base64 decoding (adds decoded candidates, does NOT change text)
# ---------------------------------------------------------------------------

def _step_base64_decode(
    text: str,
    existing_candidates: list[str],
) -> tuple[str, list[str], list[str]]:
    """
    Scan `text` for base64-like substrings, attempt to decode each, and
    return any successfully decoded printable strings as additional candidates.

    Returns (text_unchanged, new_candidates, steps_applied).
    `text` is returned unchanged — base64 decoding produces *additional*
    candidates, it never replaces the normalized text.
    """
    new_candidates: list[str] = []
    steps: list[str] = []

    for match in _BASE64_PATTERN.finditer(text):
        candidate_encoded = match.group(0)
        # Pad to multiple of 4 for standard base64
        padded = candidate_encoded + "=" * (-len(candidate_encoded) % 4)
        for variant in (padded, padded.replace("+", "-").replace("/", "_")):
            try:
                decoded_bytes = base64.b64decode(variant, validate=True)
                decoded_str = decoded_bytes.decode("utf-8")
                if decoded_str.isprintable() and len(decoded_str) >= 4:
                    # Normalize the decoded string too (steps 1-3 only, not base64)
                    normalized_decoded, _ = _apply_pre_base64_steps(decoded_str)
                    if normalized_decoded not in existing_candidates + new_candidates:
                        new_candidates.append(normalized_decoded)
                        steps.append(
                            f"base64_decode: decoded '{candidate_encoded[:20]}...' "
                            f"→ '{normalized_decoded[:40]}'"
                        )
                break  # successfully decoded
            except Exception:
                continue

    return text, new_candidates, steps


def _apply_pre_base64_steps(text: str) -> tuple[str, list[str]]:
    """Apply steps 1-3 only (unicode, homoglyph, whitespace) without base64."""
    steps: list[str] = []
    text, s = _step_unicode_nfkc(text)
    steps.extend(s)
    text, s = _step_homoglyph(text)
    steps.extend(s)
    text, s = _step_whitespace(text)
    steps.extend(s)
    return text, steps


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_text(raw_text: str) -> NormalizationResult:
    """
    Run the normalization pipeline on `raw_text` and return a
    `NormalizationResult`.

    The `raw_text` argument is NEVER modified.  The pipeline:
      1. Unicode NFKC normalization
      2. Homoglyph normalization (confusables library or fallback table)
      3. Whitespace normalization (zero-width char removal + collapse)
      4. Base64 decoding of substrings (adds decoded_candidates)

    Parameters
    ----------
    raw_text : str
        The original evidence string to normalize.

    Returns
    -------
    NormalizationResult
        normalized_text      : result of steps 1–3
        decoded_candidates   : strings decoded from base64 substrings (step 4)
        steps_applied        : log of each step that produced a change

    Extending the pipeline
    ----------------------
    To add a new normalization step (e.g. URL decoding), add a step function
    following the same pattern and insert it into the pipeline in this
    function.  The public API signature and return type are unchanged.
    """
    if not isinstance(raw_text, str):
        raise TypeError(f"normalize_text expects str, got {type(raw_text)!r}")

    all_steps: list[str] = []
    text = raw_text  # working copy; raw_text is never touched

    # Step 1: Unicode NFKC
    text, steps = _step_unicode_nfkc(text)
    all_steps.extend(steps)

    # Step 2: Homoglyph normalization
    text, steps = _step_homoglyph(text)
    all_steps.extend(steps)

    # Step 3: Whitespace normalization
    text, steps = _step_whitespace(text)
    all_steps.extend(steps)

    # Step 4: Base64 decoding (does NOT alter text)
    decoded_candidates: list[str] = []
    _, new_candidates, steps = _step_base64_decode(text, decoded_candidates)
    decoded_candidates.extend(new_candidates)
    all_steps.extend(steps)

    return NormalizationResult(
        normalized_text=text,
        decoded_candidates=decoded_candidates,
        steps_applied=all_steps,
    )
