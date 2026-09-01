"""
perception/nce_engine.py

Narrative Counterfactual Engine (NCE) — real LLM-calling adapter.

Takes a validated NCEInput, builds the prompt via the prompt_construction
pipeline, calls Gemini in strict JSON mode, parses the response into
validated NCEHypothesis objects, and returns a structured NCECallResult.

This is Phase NCE-3: the first point in the NCE pipeline where a real
network call happens.

Design decisions
----------------
1. Per-hypothesis filtering: if a hypothesis element fails validation
   (bad technique_id, confidence out of range, ANY invalid flag in
   missing_context_flags), that element is DROPPED with a logged reason —
   NOT a fatal failure for the whole call.  Invalid flags reject the
   ENTIRE hypothesis (not silently stripped), matching the principle that
   the closed vocabulary must be enforced strictly.
   Only if zero valid hypotheses survive does the call fail.  This matches
   the Phase NCE-1 design comment: "Schema validation of raw LLM JSON
   happens at the JSON-parsing layer, where a malformed hypothesis can be
   filtered BEFORE constructing NCEHypothesis objects."

2. >3 hypotheses: if the model returns more than 3 valid hypotheses
   (ignoring the prompt's cap), we truncate to the top 3 by nce_confidence
   and log a warning.  This preserves the most useful output and avoids
   wasting the API call.  NCEOutput's 1-3 cap exists to bound downstream
   SSE/RSEM computation cost, and taking the top-3 achieves that bound.

3. JSON response shape: the prompt asks for "a JSON array of 1 to 3
   hypothesis objects."  The parser accepts exactly two shapes:
   (a) a bare JSON array [...], or (b) a dict with a "hypotheses" key
   whose value is a list.  Any other dict shape is rejected — we do NOT
   scan for arbitrary list-valued keys, because that could silently
   select the wrong data.

4. Retry logic: only JSON parse failures (malformed response) trigger
   retries.  A successful JSON parse with some invalid hypotheses filtered
   out is normal operation, not retry-worthy.

5. SMOKE_TEST_ONLY gate: defaults to True, matching the project convention
   established in run_defended_recovery_eval.py and similar scripts.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any

from perception.nce_contract import (
    HypothesisStatus,
    MissingContextFlag,
    NCEHypothesis,
    NCEInput,
    NCEOutput,
)
from prompt_construction.nce_prompt_builder import build_nce_prompt_package
from prompt_construction.serializers import serialize_nce_xml

# ---------------------------------------------------------------------------
# Module-level configuration
# ---------------------------------------------------------------------------

# Safety gate — defaults to True (smoke-test mode: single real API call to
# prove the pipeline works end-to-end).  Set to False only when deliberately
# running batch evaluation.  Matches the project convention in
# run_defended_recovery_eval.py, run_baseline_eval.py, etc.
SMOKE_TEST_ONLY: bool = True

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# NCECallResult — explicit result wrapper
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NCECallResult:
    """
    Explicit result wrapper for generate_hypotheses().

    Callers should never have to guess whether a call succeeded or why it
    failed — success/error/raw_response/api_call_count make every outcome
    inspectable and auditable.
    """

    success: bool
    output: NCEOutput | None
    raw_response: str | None  # raw LLM text, preserved even on failure
    error: str | None  # human-readable failure reason
    api_call_count: int  # how many actual network calls were made


# ---------------------------------------------------------------------------
# Internal helpers — parsing and validation
# ---------------------------------------------------------------------------

# The valid MissingContextFlag values by their string representation,
# for converting LLM-generated strings to enum members.
_FLAG_LOOKUP: dict[str, MissingContextFlag] = {
    f.value: f for f in MissingContextFlag
}


def _extract_hypotheses_array(parsed: Any) -> list[dict]:
    """
    Extract the hypotheses array from the parsed JSON response.

    Accepts exactly two shapes:
    1. A bare JSON array at the top level: [...]
    2. A JSON object with a "hypotheses" key whose value is a list:
       {"hypotheses": [...]}

    Any other shape is rejected with a clear error.  This is deliberately
    strict — we do NOT scan for arbitrary list-valued keys, because that
    could silently select the wrong data (e.g. a "metadata" key that
    happens to contain a list).

    Raises ValueError if neither accepted shape matches.
    """
    if isinstance(parsed, list):
        return parsed

    if isinstance(parsed, dict):
        if "hypotheses" in parsed and isinstance(parsed["hypotheses"], list):
            return parsed["hypotheses"]
        raise ValueError(
            f"Parsed JSON is a dict but has no 'hypotheses' key with a list "
            f"value. Keys present: {sorted(parsed.keys())}. "
            f"Expected a bare JSON array or {{\"hypotheses\": [...]}}."
        )

    raise ValueError(
        f"Parsed JSON is neither a list nor a dict, got {type(parsed).__name__}"
    )


def _parse_single_hypothesis(
    raw: dict,
    incident_id: str,
) -> NCEHypothesis:
    """
    Construct an NCEHypothesis from a single LLM-generated dict.

    - Extracts the 7 LLM-generated fields
    - Converts missing_context_flags strings → MissingContextFlag enum members.
      If ANY flag string is invalid, the ENTIRE hypothesis is rejected (raised
      as ValueError) — not silently repaired by dropping the bad flag.  An
      empty list or missing field is fine; only reject when a flag VALUE
      present in the list is invalid.
    - Stamps incident_id and status=GENERATED (not generated by the model)
    - Raises ValueError on any construction failure (caller catches per-hypothesis)
    """
    # --- Extract required fields ---
    technique_id = str(raw.get("technique_id", ""))
    source_account = str(raw.get("source_account", ""))
    source_host = str(raw.get("source_host", ""))
    target_host = str(raw.get("target_host", ""))

    # --- nce_confidence: coerce to float ---
    raw_confidence = raw.get("nce_confidence")
    if raw_confidence is None:
        raise ValueError("Missing required field 'nce_confidence'")
    try:
        nce_confidence = float(raw_confidence)
    except (TypeError, ValueError) as e:
        raise ValueError(f"nce_confidence is not a valid number: {e}") from e

    # --- supporting_evidence_refs: must be a list of strings ---
    raw_refs = raw.get("supporting_evidence_refs", [])
    if not isinstance(raw_refs, list):
        raise ValueError(
            f"supporting_evidence_refs is not a list, got {type(raw_refs).__name__}"
        )
    supporting_evidence_refs = [str(r) for r in raw_refs]

    # --- missing_context_flags: convert strings → enum members ---
    # If ANY flag string is invalid, the ENTIRE hypothesis is rejected.
    # An empty list or missing field is fine — only reject when a flag
    # VALUE present in the list is invalid.
    raw_flags = raw.get("missing_context_flags", [])
    if not isinstance(raw_flags, list):
        raw_flags = []
    missing_context_flags: list[MissingContextFlag] = []
    for flag_str in raw_flags:
        flag_str = str(flag_str)
        enum_member = _FLAG_LOOKUP.get(flag_str)
        if enum_member is not None:
            missing_context_flags.append(enum_member)
        else:
            raise ValueError(
                f"Invalid missing_context_flag {flag_str!r} in hypothesis "
                f"(technique_id={technique_id}). "
                f"Valid flags: {sorted(_FLAG_LOOKUP.keys())}"
            )

    # --- Construct NCEHypothesis (validation in __post_init__) ---
    return NCEHypothesis(
        technique_id=technique_id,
        source_account=source_account,
        source_host=source_host,
        target_host=target_host,
        nce_confidence=nce_confidence,
        supporting_evidence_refs=supporting_evidence_refs,
        missing_context_flags=missing_context_flags,
        status=HypothesisStatus.GENERATED,
        incident_id=incident_id,
    )


# ---------------------------------------------------------------------------
# LLM call — Gemini with key rotation and JSON mode
# ---------------------------------------------------------------------------

def _call_gemini_nce(
    prompt: str,
    model: str,
) -> dict[str, Any]:
    """
    Call Gemini with key-pool rotation and JSON mode.

    Matches the existing project conventions:
    - Key rotation via agent.key_pool.load_gemini_pool()
    - JSON mode via GenerateContentConfig(response_mime_type="application/json")
    - Retry on rate-limit errors via _is_rate_limit_error / _RETRY_DELAYS
    - _strip_code_fence for safety

    Returns a dict with keys: raw_response, parsed, parse_error.
    """
    from google import genai
    from google.genai import types as genai_types

    from agent.key_pool import load_gemini_pool
    from agent.llm_utils import (
        RETRY_DELAYS as _RETRY_DELAYS,
        is_rate_limit_error as _is_rate_limit_error,
        strip_code_fence as _strip_code_fence,
    )

    pool = load_gemini_pool()

    if not pool.keys:
        return {
            "raw_response": None,
            "parsed": None,
            "parse_error": "API_ERROR: KeyPool is empty — no GEMINI_API_KEY(S) set",
        }

    config = genai_types.GenerateContentConfig(
        response_mime_type="application/json",
    )

    last_exc: Exception | None = None

    for attempt, delay in enumerate([0] + list(_RETRY_DELAYS)):
        if delay:
            logger.info(
                "[NCE] All Gemini keys exhausted. Sleeping %ds before retry...",
                delay,
            )
            time.sleep(delay)

        pool.reset_tried()

        for _ in range(len(pool.keys)):
            current_key = pool.current()
            current_idx = pool.current_index()
            logger.debug("[NCE] Using Gemini key at index %d", current_idx)

            try:
                client = genai.Client(api_key=current_key)
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=config,
                )
                raw = response.text if response.text else ""
                cleaned = _strip_code_fence(raw)

                try:
                    parsed = json.loads(cleaned)
                except json.JSONDecodeError as je:
                    return {
                        "raw_response": raw,
                        "parsed": None,
                        "parse_error": f"JSON_PARSE_ERROR: {je}",
                    }

                pool.reset_tried()
                return {
                    "raw_response": raw,
                    "parsed": parsed,
                    "parse_error": None,
                }

            except Exception as exc:
                last_exc = exc
                if _is_rate_limit_error(exc):
                    logger.info(
                        "[NCE] Gemini key index %d rate limited. Rotating...",
                        current_idx,
                    )
                    pool.rotate()
                    continue
                # Non-rate-limit error — bail
                break

        if last_exc and not _is_rate_limit_error(last_exc):
            break

    return {
        "raw_response": None,
        "parsed": None,
        "parse_error": f"API_ERROR: {type(last_exc).__name__}: {last_exc}",
    }


# ---------------------------------------------------------------------------
# Public API — generate_hypotheses
# ---------------------------------------------------------------------------

def generate_hypotheses(
    nce_input: NCEInput,
    model: str = "gemini-3.1-flash-lite",
    max_retries: int = 1,
) -> NCECallResult:
    """
    Generate competing attack-narrative hypotheses for an incident.

    Full pipeline: NCEInput → build prompt → call Gemini → parse response
    → filter/validate hypotheses → return NCECallResult.

    Parameters
    ----------
    nce_input : NCEInput
        Validated evidence-only input (no trusted context).
    model : str
        Gemini model identifier. Default: gemini-3.1-flash-lite.
    max_retries : int
        How many times to retry on JSON parse failure (not on schema
        validation failures — those are normal operation where invalid
        hypotheses get filtered out). Default: 1 (so 2 total attempts).

    Returns
    -------
    NCECallResult
        success=True with a validated NCEOutput, or success=False with
        a clear error message and the raw_response preserved for debugging.
    """
    # --- Step 1: Build the prompt ---
    try:
        pkg = build_nce_prompt_package(nce_input)
        prompt = serialize_nce_xml(pkg)
    except Exception as exc:
        return NCECallResult(
            success=False,
            output=None,
            raw_response=None,
            error=f"Prompt construction failed: {exc}",
            api_call_count=0,
        )

    # --- Step 2: Call the LLM with retry on JSON parse failure ---
    api_call_count = 0
    last_raw_response: str | None = None
    last_parse_error: str | None = None
    parsed: Any = None

    for attempt in range(1 + max_retries):
        api_call_count += 1
        result = _call_gemini_nce(prompt, model=model)

        last_raw_response = result.get("raw_response")
        parse_error = result.get("parse_error")

        if parse_error is None:
            # Successful JSON parse
            parsed = result["parsed"]
            break

        # Check if this is a JSON parse error (retry-worthy) or an API error (not retry-worthy)
        last_parse_error = parse_error
        if parse_error.startswith("API_ERROR:"):
            # API errors are not retry-worthy via this mechanism
            # (rate-limit retries happen inside _call_gemini_nce already)
            break

        # JSON_PARSE_ERROR — retry if we have retries left
        if attempt < max_retries:
            logger.warning(
                "[NCE] JSON parse failed (attempt %d/%d): %s. Retrying...",
                attempt + 1,
                1 + max_retries,
                parse_error,
            )
            continue
        else:
            logger.error(
                "[NCE] JSON parse failed after all %d attempts: %s",
                1 + max_retries,
                parse_error,
            )

    # If we never got a successful parse, fail
    if parsed is None:
        return NCECallResult(
            success=False,
            output=None,
            raw_response=last_raw_response,
            error=last_parse_error or "Unknown parse failure",
            api_call_count=api_call_count,
        )

    # --- Step 3: Extract hypotheses array ---
    try:
        hypotheses_raw = _extract_hypotheses_array(parsed)
    except ValueError as exc:
        return NCECallResult(
            success=False,
            output=None,
            raw_response=last_raw_response,
            error=f"Failed to extract hypotheses array: {exc}",
            api_call_count=api_call_count,
        )

    # --- Step 4: Parse and validate each hypothesis ---
    valid_hypotheses: list[NCEHypothesis] = []
    drop_reasons: list[str] = []

    for i, raw_hyp in enumerate(hypotheses_raw):
        if not isinstance(raw_hyp, dict):
            drop_reasons.append(
                f"Hypothesis [{i}]: not a dict (got {type(raw_hyp).__name__})"
            )
            continue

        try:
            hypothesis = _parse_single_hypothesis(raw_hyp, nce_input.incident_id)
            valid_hypotheses.append(hypothesis)
        except (ValueError, TypeError) as exc:
            drop_reasons.append(f"Hypothesis [{i}]: {exc}")
            logger.warning("[NCE] Dropping hypothesis [%d]: %s", i, exc)

    # Log any dropped hypotheses
    if drop_reasons:
        logger.info(
            "[NCE] Dropped %d hypothesis(es) from LLM response: %s",
            len(drop_reasons),
            "; ".join(drop_reasons),
        )

    # --- Step 5: Handle zero valid hypotheses ---
    if not valid_hypotheses:
        return NCECallResult(
            success=False,
            output=None,
            raw_response=last_raw_response,
            error=(
                f"All {len(hypotheses_raw)} hypotheses from LLM response "
                f"failed validation. Drop reasons: {'; '.join(drop_reasons)}"
            ),
            api_call_count=api_call_count,
        )

    # --- Step 6: Handle >3 valid hypotheses (truncate to top 3) ---
    if len(valid_hypotheses) > 3:
        logger.warning(
            "[NCE] Model returned %d valid hypotheses (cap is 3). "
            "Truncating to top 3 by nce_confidence.",
            len(valid_hypotheses),
        )
        valid_hypotheses.sort(key=lambda h: h.nce_confidence, reverse=True)
        valid_hypotheses = valid_hypotheses[:3]

    # --- Step 7: Construct NCEOutput ---
    try:
        nce_output = NCEOutput(
            incident_id=nce_input.incident_id,
            hypotheses=tuple(valid_hypotheses),
        )
    except ValueError as exc:
        return NCECallResult(
            success=False,
            output=None,
            raw_response=last_raw_response,
            error=f"NCEOutput construction failed: {exc}",
            api_call_count=api_call_count,
        )

    return NCECallResult(
        success=True,
        output=nce_output,
        raw_response=last_raw_response,
        error=None,
        api_call_count=api_call_count,
    )


# ---------------------------------------------------------------------------
# Alert-to-NCEInput adapter
# ---------------------------------------------------------------------------

# Evidence field names — matches _EVIDENCE_FIELD_NAMES in
# prompt_construction/safe_prompt_builder.py and the Evidence dataclass in
# perception/models.py.  These are the 6 fields classified as FREE_TEXT
# (attacker-controllable).
#
# Deliberately EXCLUDES source_user, source_host, target_host — those are
# STRUCTURED trust level in ImmutableContext, not evidence.
_NCE_EVIDENCE_FIELD_NAMES: tuple[str, ...] = (
    "process_name",
    "command_line",
    "registry_key",
    "parent_process",
    "file_path",
    "raw_log_line",
)


def alert_to_nce_input(alert: dict) -> NCEInput:
    """
    Convert an alert dict from the GUIDE dataset JSON format to NCEInput.

    Maps the 6 Evidence-class FREE_TEXT fields into evidence_fields,
    skipping any that are None/missing.  Uses alert_id as incident_id.

    Parameters
    ----------
    alert : dict
        An alert from guide_*_alerts.json with keys like alert_id,
        process_name, command_line, etc.

    Returns
    -------
    NCEInput
        Ready for generate_hypotheses().

    Raises
    ------
    ValueError
        If alert_id is missing or no evidence fields have values.
    """
    from datetime import datetime, timezone

    alert_id = alert.get("alert_id")
    if not alert_id:
        raise ValueError("Alert has no 'alert_id' field")

    evidence_fields: dict[str, str] = {}
    for field_name in _NCE_EVIDENCE_FIELD_NAMES:
        value = alert.get(field_name)
        if value is not None:
            evidence_fields[field_name] = str(value)

    if not evidence_fields:
        raise ValueError(
            f"Alert {alert_id} has no non-None evidence fields among "
            f"{_NCE_EVIDENCE_FIELD_NAMES}"
        )

    # Use alert timestamp if available, otherwise use current time
    ts_str = alert.get("timestamp")
    if ts_str:
        try:
            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            timestamp = datetime.now(timezone.utc)
    else:
        timestamp = datetime.now(timezone.utc)

    return NCEInput(
        incident_id=str(alert_id),
        evidence_fields=evidence_fields,
        timestamp=timestamp,
    )
