"""
agent/measure_clean_confidence.py

Measures clean confidence for 25 sampled alerts from guide_sample_500_alerts.json.
Runs a smoke test first when SMOKE_TEST_ONLY = True.
"""
from __future__ import annotations

import copy
import json
import os
import random
import sys
import time
from pathlib import Path
import pandas as pd

# ── Force unbuffered UTF-8 stdout (Windows-safe) ────────────────────────────
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def p(*args, **kwargs):
    """Flushing print — ensures live line-by-line output on Windows."""
    print(*args, **kwargs, flush=True)


from dotenv import load_dotenv

load_dotenv()

from google import genai

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "GUIDE_Dataset" / "processed"))

# Import reusable logic
from agent.baseline_agent import (
    build_undefended_prompt,
    call_agent,
)
from agent.run_baseline_eval import (
    strip_ground_truth,
)
from synth_fields import synthesize_row, build_raw_log_text

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ALERTS_JSON = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_sample_500_alerts.json"
RAW_CSV_PATH = PROJECT_ROOT / "GUIDE_Dataset" / "raw" / "guide_sample_500" / "guide_sample_500.csv"
RESULTS_JSON = PROJECT_ROOT / "agent" / "clean_confidence_measurements.json"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SMOKE_TEST_ONLY = False

PROVIDER = "gemini_flash_lite"
MODEL = "gemini-3.1-flash-lite"

INTER_CALL_SLEEP = 1.0  # seconds between API calls

SEP = "-" * 90


# ---------------------------------------------------------------------------
# Load raw CSV once for deterministic reconstruction
# ---------------------------------------------------------------------------
try:
    RAW_DF = pd.read_csv(RAW_CSV_PATH)
except FileNotFoundError:
    p(f"ERROR: Could not find raw CSV at {RAW_CSV_PATH}")
    sys.exit(1)


def reconstruct_clean_alert(alert: dict) -> dict:
    """
    Derive the 'clean' version of a contaminated alert.
    """
    clean = copy.deepcopy(alert)
    cat = alert.get("_ground_truth_injection_category")

    if cat == "multi_source_corroboration":
        alert_id = int(clean["alert_id"])
        row = RAW_DF[RAW_DF["Id"] == alert_id].iloc[0]
        synth = synthesize_row(row)
        row_combined = pd.concat([row, pd.Series(synth)])
        clean_raw_log = build_raw_log_text(row_combined)

        clean["registry_key"] = synth["synth_registry_key"]
        clean["parent_process"] = None
        clean["raw_log_line"] = clean_raw_log
    else:
        raw = clean.get("raw_log_line") or ""
        marker = ' | INJECTED_FIELD_VALUE="'
        idx = raw.find(marker)
        if idx != -1:
            clean["raw_log_line"] = raw[:idx]

    return clean


# ---------------------------------------------------------------------------
# Helpers: smoke tests
# ---------------------------------------------------------------------------

def _run_smoke_test(client, sampled: list) -> None:
    """Smoke-test MODEL against alert index 0."""
    alert = sampled[0]
    alert_id = alert.get("alert_id", "?")
    grade = alert.get("_source_incident_grade", "?")

    clean_alert = reconstruct_clean_alert(alert)
    agent_alert, _ = strip_ground_truth(clean_alert)
    prompt = build_undefended_prompt(agent_alert)

    p(f"SMOKE TEST  (provider={PROVIDER}, model={MODEL})")
    p(f"Alert: {alert_id}  |  Incident Grade: {grade}")
    p("Running ONE clean call.")
    p("="  * 90)

    result = call_agent(prompt, client, model=MODEL)

    p("--- raw_response ---")
    p(result.get("raw_response") or "")
    p("--- parsed ---")
    p(json.dumps(result.get("parsed"), indent=2) if result.get("parsed") is not None else "None")
    p("--- parse_error ---")
    p(result.get("parse_error") or "None")
    p("")

    err = result.get("parse_error") or ""
    if err.startswith("API_ERROR") and ("404" in err or "NOT_FOUND" in err):
        p("SMOKE TEST FAILED: model name is invalid or unavailable — do not proceed.")
        sys.exit(1)
    if err.startswith("API_ERROR") and ("429" in err or "RESOURCE_EXHAUSTED" in err or "quota" in err.lower()):
        p("SMOKE TEST INCONCLUSIVE — quota exhausted, retry after reset. Do not proceed.")
        sys.exit(1)

    parsed = result.get("parsed")
    required_keys = {"verdict", "action", "confidence", "reasoning"}
    if parsed and isinstance(parsed, dict) and required_keys.issubset(parsed.keys()):
        p("SMOKE TEST PASSED — model responding correctly. Set SMOKE_TEST_ONLY = False to run the full batch.")
        sys.exit(0)
    else:
        p("SMOKE TEST FAILED: response keys are invalid or parsing failed.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main measurement loop
# ---------------------------------------------------------------------------

def main() -> None:
    p(f"\nPhase 3 -- Clean Confidence Measurement")
    p(SEP)
    p(f"Loading alerts from: {ALERTS_JSON}")

    with open(ALERTS_JSON, encoding="utf-8") as f:
        all_alerts = json.load(f)

    p(f"Total alerts loaded: {len(all_alerts)}")

    # Sample 25 candidate alerts from the full pool
    rng = random.Random(47)
    sampled = rng.sample(all_alerts, 25)
    p(f"Sampled 25 alerts using seed=47.")

    # ── API client ───────────────────────────────────────────────────────────
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        p("FAIL: GEMINI_API_KEY not set. Check .env at project root.")
        sys.exit(1)
    client = genai.Client(api_key=api_key)

    if SMOKE_TEST_ONLY:
        _run_smoke_test(client, sampled)
        return

    # ── Full batch measurement ──────────────────────────────────────────────
    p(f"")
    p(f"=== Full measurement run: {PROVIDER} / {MODEL} ===")
    p(f"{'#':<4} {'Alert ID':<20} {'Grade':<20} {'Confidence':<12}")
    p("-" * 60)

    results = []

    for i, alert in enumerate(sampled, start=1):
        alert_id = alert.get("alert_id", "?")
        grade = alert.get("_source_incident_grade", "?")

        clean_alert = reconstruct_clean_alert(alert)
        agent_alert, _ = strip_ground_truth(clean_alert)
        prompt = build_undefended_prompt(agent_alert)

        result = call_agent(prompt, client, model=MODEL)
        
        parsed = result.get("parsed") or {}
        confidence = parsed.get("confidence")
        if confidence is None:
            # Fallback if parsing failed
            confidence = 0.0

        p(f"{i:<4} {alert_id:<20} {grade:<20} {confidence:<12}")

        results.append({
            "alert_id": alert_id,
            "injection_category": "none",
            "_source_incident_grade": grade,
            "confidence": confidence,
            "raw_result": result
        })

        if i < len(sampled):
            time.sleep(INTER_CALL_SLEEP)

    # Sort results ascending by confidence
    sorted_results = sorted(results, key=lambda x: x["confidence"])

    # Print summary table
    p("\n" + "=" * 60)
    p("Clean Confidence Measurements (Sorted Ascending)")
    p("=" * 60)
    p(f"{'Alert ID':<20} {'Grade':<20} {'Confidence':<12}")
    p("-" * 60)
    for r in sorted_results:
        p(f"{r['alert_id']:<20} {r['_source_incident_grade']:<20} {r['confidence']:<12}")

    # Save to file
    p(f"\nSaving measurements to: {RESULTS_JSON}")
    with open(RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    p("Measurements saved successfully.")


if __name__ == "__main__":
    main()
