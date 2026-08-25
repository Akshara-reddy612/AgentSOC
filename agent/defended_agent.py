"""
agent/defended_agent.py

Phase 3 — Defended Agent
=========================
Applies three layers of defense against prompt-injection attacks:

  Defense 1 — ERA (Evidence Risk Assessment)
      orchestrator.assess() runs RegexDetector + SemanticDetector +
      SplitFieldDetector on every evidence field, producing a
      RiskAssessmentBundle that scores and labels each field as
      LOW / MEDIUM / HIGH risk.

  Defense 2 — SPC (Safe Prompt Construction)
      PerceptionPipeline → EnrichedIncident → attach_risk_metadata()
      → build_prompt_package() → serialize_xml()

      All untrusted evidence is XML-escaped and placed in a clearly
      labelled <untrusted_evidence> block, separated from the
      system-authored <trusted_context>. The risk bundle is embedded
      in per-field <risk_metadata> elements so the LLM can see the
      ERA scores inline.

  Defense 3 — Schema Validation Gate
      validate_output_schema() checks the LLM's JSON response for
      structural completeness and value-set compliance before the
      result is passed to any downstream system. Invalid responses
      are replaced by SAFE_FALLBACK.

Public API
----------
    from agent.defended_agent import (
        VERDICT_VALUES,
        ACTION_VALUES,
        SAFE_FALLBACK,
        build_defended_prompt,
        validate_output_schema,
        call_defended_agent,
    )

Note: VERDICT_VALUES and ACTION_VALUES are imported from
baseline_agent.py — they are NOT redefined here.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path setup — ensure project root is importable
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Re-export from baseline_agent — do NOT redefine these constants.
# ---------------------------------------------------------------------------

from agent.baseline_agent import (  # noqa: E402
    VERDICT_VALUES,
    ACTION_VALUES,
    call_agent,
    call_agent_groq,
)

# ---------------------------------------------------------------------------
# Phase 1 — Perception pipeline
# ---------------------------------------------------------------------------

from perception.pipeline import PerceptionPipeline  # noqa: E402

# ---------------------------------------------------------------------------
# Phase 2 — Risk Assessment
# ---------------------------------------------------------------------------

from risk_assessment.orchestrator import assess  # noqa: E402
from risk_assessment.integration import attach_risk_metadata  # noqa: E402

# ---------------------------------------------------------------------------
# Phase 2 — Safe Prompt Construction
# ---------------------------------------------------------------------------

from prompt_construction.safe_prompt_builder import build_prompt_package  # noqa: E402
from prompt_construction.serializers import serialize_xml  # noqa: E402

# ---------------------------------------------------------------------------
# JSON output format contract — appended after the XML body
# ---------------------------------------------------------------------------
# This suffix is system-authored (trusted) and mirrors the baseline_agent's
# SYSTEM_PREAMBLE format contract exactly.  It is appended AFTER the XML
# block so the model sees the output requirement as the final instruction,
# outside the <untrusted_evidence> zone.

_JSON_FORMAT_SUFFIX: str = (
    "\n\nRespond with ONLY a JSON object with keys: "
    "verdict (malicious/benign/needs_review), "
    "action (escalate/abort/monitor/none), "
    "confidence (0.0-1.0), "
    "reasoning (short string). "
    "No other text."
)

# ---------------------------------------------------------------------------
# Ground-truth keys — same set as run_baseline_eval.py
# ---------------------------------------------------------------------------

_GROUND_TRUTH_KEYS: frozenset[str] = frozenset({
    "_ground_truth_is_contaminated",
    "_ground_truth_injection_category",
    "_source_incident_grade",
})

# ---------------------------------------------------------------------------
# Defense Stage 3 — Safe fallback constant
# ---------------------------------------------------------------------------

SAFE_FALLBACK: dict = {
    "verdict": "needs_review",
    "action": "monitor",
    "confidence": 0.0,
    "reasoning": (
        "Schema validation failed; defaulting to safe fallback "
        "pending manual review."
    ),
}

# ---------------------------------------------------------------------------
# Shared pipeline instance (stateless — safe to reuse across calls)
# ---------------------------------------------------------------------------

_pipeline = PerceptionPipeline(emit_logs=False)


# ---------------------------------------------------------------------------
# Defense Stage 1 + 2 — build_defended_prompt
# ---------------------------------------------------------------------------

def build_defended_prompt(alert: dict) -> tuple[str, dict]:
    """
    Build the defended XML prompt for one alert dict.

    Runs the full Phase 1 + Phase 2 pipeline:
        alert dict
            → PerceptionPipeline.run() → EnrichedIncident
            → orchestrator.assess()    → RiskAssessmentBundle
            → attach_risk_metadata()   (populates Evidence.risk_metadata)
            → build_prompt_package()   → PromptPackage
            → serialize_xml()          → XML prompt string

    Parameters
    ----------
    alert : dict
        A raw alert dict with ground-truth keys already stripped
        (same convention as baseline_agent.build_undefended_prompt()).
        Keys _ground_truth_* and _source_incident_grade must NOT be
        present — call strip_ground_truth() before passing in.

    Returns
    -------
    (prompt_string, risk_bundle_dict)
        prompt_string    : str  — XML-escaped prompt ready for the LLM.
        risk_bundle_dict : dict — bundle.to_dict() output for logging;
                                  contains field_results and incident_result.

    Raises
    ------
    RuntimeError
        If the PerceptionPipeline rejects or fails to process the alert
        (e.g. schema validation failure).  The caller should handle this
        and return an API_ERROR result rather than calling the LLM.
    """
    # ── Stage 1: Perception pipeline ─────────────────────────────────────────
    # run() expects a list; we pass a single-element list.
    pipeline_result = _pipeline.run([alert])

    # Surface pipeline failures as RuntimeError so callers can catch and log.
    if pipeline_result.normalization_errors:
        raw_err, msg = pipeline_result.normalization_errors[0]
        raise RuntimeError(f"PerceptionPipeline normalization error: {msg}")

    if pipeline_result.validation_rejections:
        aid, vr = pipeline_result.validation_rejections[0]
        codes = [e.code for e in vr.errors]
        raise RuntimeError(
            f"PerceptionPipeline validation rejection for {aid}: {codes}"
        )

    if not pipeline_result.clusters:
        raise RuntimeError(
            "PerceptionPipeline produced no clusters — alert may have been "
            "dropped by noise reduction."
        )

    # Take the representative incident from the first (and only) cluster.
    incident = pipeline_result.clusters[0].representative

    # ── Stage 2a: Evidence Risk Assessment ───────────────────────────────────
    # assess() is pure — it never mutates the Evidence object.
    # Confirmed public API: assess(evidence: Any) -> RiskAssessmentBundle
    bundle = assess(incident.evidence)

    # ── Stage 2b: Attach risk metadata to the incident ───────────────────────
    # attach_risk_metadata() is the ONLY function that writes to
    # Evidence.risk_metadata and EnrichedIncident.era_metadata.
    attach_risk_metadata(bundle, incident)

    # ── Stage 2c: Safe Prompt Construction ───────────────────────────────────
    # build_prompt_package() reads Evidence.risk_metadata (now populated).
    # serialize_xml() XML-escapes all untrusted values.
    pkg = build_prompt_package(incident)
    prompt_string = serialize_xml(pkg)

    # ── Append explicit JSON output contract (system-authored, trusted) ───────
    # Placed AFTER the closing </prompt> tag so it is unambiguously outside
    # the <untrusted_evidence> zone and cannot be confused with evidence data.
    prompt_string = prompt_string + _JSON_FORMAT_SUFFIX

    # Capture the serialized bundle for return (logging / smoke-test display).
    risk_bundle_dict = bundle.to_dict()

    return prompt_string, risk_bundle_dict


# ---------------------------------------------------------------------------
# Defense Stage 3 — Schema validation gate
# ---------------------------------------------------------------------------

def validate_output_schema(
    parsed: dict | None,
) -> tuple[bool, list[str]]:
    """
    Validate the LLM's parsed JSON response against the required schema.

    This is Defense Stage 3: a strict gate that ensures the response
    is structurally complete and value-set compliant before it is
    passed to any downstream system.

    Parameters
    ----------
    parsed : dict | None
        The JSON-parsed response dict from call_agent() / call_agent_groq(),
        or None if parsing failed.

    Returns
    -------
    (is_valid, violations)
        is_valid   : bool        — True iff the response passes all checks.
        violations : list[str]   — Specific human-readable violation strings.
                                   Empty when is_valid is True.

    Validation rules (all must pass)
    ---------------------------------
    1. parsed is not None.
    2. All four required keys are present: verdict, action, confidence,
       reasoning.
    3. verdict is a member of VERDICT_VALUES.
    4. action is a member of ACTION_VALUES.
    5. confidence is a number (int or float) in the closed interval [0.0, 1.0].
    """
    violations: list[str] = []

    # Rule 1 — not None
    if parsed is None:
        violations.append("parsed response is None (JSON parsing failed)")
        return False, violations

    # Rule 2 — required keys present
    required_keys = {"verdict", "action", "confidence", "reasoning"}
    missing = required_keys - set(parsed.keys())
    if missing:
        violations.append(f"missing required keys: {sorted(missing)}")

    # Rule 3 — verdict in allowed set
    verdict = parsed.get("verdict")
    if verdict not in VERDICT_VALUES:
        violations.append(
            f"verdict {verdict!r} not in allowed set {sorted(VERDICT_VALUES)}"
        )

    # Rule 4 — action in allowed set
    action = parsed.get("action")
    if action not in ACTION_VALUES:
        violations.append(
            f"action {action!r} not in allowed set {sorted(ACTION_VALUES)}"
        )

    # Rule 5 — confidence is a number in [0.0, 1.0]
    confidence = parsed.get("confidence")
    if not isinstance(confidence, (int, float)):
        violations.append(
            f"confidence {confidence!r} is not a number (got {type(confidence).__name__})"
        )
    elif not (0.0 <= float(confidence) <= 1.0):
        violations.append(
            f"confidence {confidence!r} is outside [0.0, 1.0]"
        )

    is_valid = len(violations) == 0
    return is_valid, violations


# ---------------------------------------------------------------------------
# JSON-mode LLM wrappers (defended path only)
# ---------------------------------------------------------------------------
# These thin wrappers call the same underlying SDK functions as
# call_agent() / call_agent_groq() in baseline_agent.py but add
# native JSON-mode parameters as a structural backstop so format
# compliance does not depend solely on instruction-following.
#
# Gemini: config=types.GenerateContentConfig(response_mime_type="application/json")
#   Forces the model to emit valid JSON.  Supported on Gemini 1.5+ / 3.x.
#
# Groq (OpenAI-compatible): response_format={"type": "json_object"}
#   Groq's API mirrors the OpenAI JSON-mode parameter exactly.
#
# baseline_agent.py is NOT modified — these wrappers are local to the
# defended pipeline only.

import json as _json
import time as _time
from typing import Optional as _Optional

# Import retry config from baseline (reuse, don't redefine)
from agent.baseline_agent import (
    _RETRY_DELAYS,          # noqa: F401  (private but stable — same module)
    _is_rate_limit_error,   # noqa: F401
    _strip_code_fence,      # noqa: F401
)


def _call_gemini_json(prompt: str, client: Any, model: str) -> dict:
    """
    Call the Gemini API with response_mime_type="application/json".

    Identical retry/error logic to baseline_agent.call_agent() but adds
    GenerateContentConfig so the model is structurally forced to emit JSON,
    not just instructed to do so in the prompt text.

    Returns a dict with keys: raw_response, parsed, parse_error.
    """
    from google.genai import types as _genai_types  # lazy import — not at module level

    _config = _genai_types.GenerateContentConfig(
        response_mime_type="application/json",
    )

    last_exc: _Optional[Exception] = None

    for attempt, delay in enumerate([0] + list(_RETRY_DELAYS)):
        if delay:
            _time.sleep(delay)
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=_config,
            )
            raw = response.text if response.text else ""
            cleaned = _strip_code_fence(raw)
            try:
                parsed = _json.loads(cleaned)
            except _json.JSONDecodeError as je:
                return {
                    "raw_response": raw,
                    "parsed": None,
                    "parse_error": f"JSON_PARSE_ERROR: {je}",
                }
            return {"raw_response": raw, "parsed": parsed, "parse_error": None}
        except Exception as exc:
            last_exc = exc
            if _is_rate_limit_error(exc) and attempt < len(_RETRY_DELAYS):
                continue
            break

    return {
        "raw_response": None,
        "parsed": None,
        "parse_error": f"API_ERROR: {type(last_exc).__name__}: {last_exc}",
    }


def _call_groq_json(prompt: str, groq_client: Any, model: str) -> dict:
    """
    Call the Groq API with response_format={"type": "json_object"}.

    Identical retry/error logic to baseline_agent.call_agent_groq() but adds
    the OpenAI-compatible JSON-mode parameter.  Groq documents this parameter
    and guarantees valid JSON output when it is set.

    Returns a dict with keys: raw_response, parsed, parse_error.
    """
    last_exc: _Optional[Exception] = None

    for attempt, delay in enumerate([0] + list(_RETRY_DELAYS)):
        if delay:
            _time.sleep(delay)
        try:
            response = groq_client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
            )
            raw = (
                response.choices[0].message.content
                if response.choices[0].message.content
                else ""
            )
            cleaned = _strip_code_fence(raw)
            try:
                parsed = _json.loads(cleaned)
            except _json.JSONDecodeError as je:
                return {
                    "raw_response": raw,
                    "parsed": None,
                    "parse_error": f"JSON_PARSE_ERROR: {je}",
                }
            return {"raw_response": raw, "parsed": parsed, "parse_error": None}
        except Exception as exc:
            last_exc = exc
            if _is_rate_limit_error(exc) and attempt < len(_RETRY_DELAYS):
                continue
            break

    return {
        "raw_response": None,
        "parsed": None,
        "parse_error": f"API_ERROR: {type(last_exc).__name__}: {last_exc}",
    }


# ---------------------------------------------------------------------------
# Full defended call — orchestrates all three defense stages
# ---------------------------------------------------------------------------

def call_defended_agent(
    alert: dict,
    client: Any,
    model: str,
    provider: str,
) -> dict:
    """
    Run the full three-stage defended pipeline on one alert dict.

    Stages
    ------
    1. build_defended_prompt()    — ERA + SPC → XML prompt (with JSON suffix)
                                    + risk bundle dict
    2. _call_gemini_json() / _call_groq_json()  — LLM inference (one API call)
                                    with native JSON-mode param as backstop
    3. validate_output_schema()   — schema gate; invalid → SAFE_FALLBACK

    Parameters
    ----------
    alert : dict
        Raw alert dict with ground-truth keys already stripped.
    client : genai.Client | openai.OpenAI
        Authenticated API client instance.
    model : str
        Model identifier string (e.g. "gemini-3.1-flash-lite").
    provider : str
        One of "gemini_flash_lite", "gemini", or "groq".
        "gemini_flash_lite" and "gemini" → _call_gemini_json() with
          response_mime_type="application/json".
        "groq" → _call_groq_json() with
          response_format={"type": "json_object"}.

    Returns
    -------
    dict with keys:
        risk_bundle      : dict       — bundle.to_dict() from ERA
        raw_llm_result   : dict       — result dict with keys
                                        raw_response, parsed, parse_error
        schema_valid     : bool       — True if schema gate passed
        schema_violations: list[str]  — violation strings (empty if valid)
        final_verdict    : dict       — LLM's parsed dict if valid,
                                        else SAFE_FALLBACK
    """
    # ── Stage 1: Build defended prompt ───────────────────────────────────────
    try:
        prompt_string, risk_bundle_dict = build_defended_prompt(alert)
    except RuntimeError as exc:
        # Pipeline failure — cannot call LLM; return structured error.
        return {
            "risk_bundle": None,
            "raw_llm_result": {
                "raw_response": None,
                "parsed": None,
                "parse_error": f"PIPELINE_ERROR: {exc}",
            },
            "schema_valid": False,
            "schema_violations": [f"Pipeline failed: {exc}"],
            "final_verdict": SAFE_FALLBACK,
        }

    # ── Stage 2: LLM call (JSON-mode enforced) ───────────────────────────────
    if provider == "groq":
        # Groq path: OpenAI-compatible response_format={"type": "json_object"}
        raw_llm_result = _call_groq_json(prompt_string, client, model=model)
    else:
        # Gemini path ("gemini", "gemini_flash_lite", or any other provider):
        # GenerateContentConfig(response_mime_type="application/json")
        raw_llm_result = _call_gemini_json(prompt_string, client, model=model)

    # ── Stage 3: Schema validation gate ──────────────────────────────────────
    parsed = raw_llm_result.get("parsed")
    schema_valid, schema_violations = validate_output_schema(parsed)

    if schema_valid:
        final_verdict = parsed
    else:
        final_verdict = SAFE_FALLBACK

    return {
        "risk_bundle": risk_bundle_dict,
        "raw_llm_result": raw_llm_result,
        "schema_valid": schema_valid,
        "schema_violations": schema_violations,
        "final_verdict": final_verdict,
    }
