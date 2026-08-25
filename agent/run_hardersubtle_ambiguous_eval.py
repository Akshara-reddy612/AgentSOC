"""
agent/run_hardersubtle_ambiguous_eval.py

Phase 3 — Harder-Subtle Payloads Evaluation (9-alert ambiguous sample)
============================================================
Runs the undefended baseline agent against all 9 contaminated alerts from
guide_hardersubtle_ambiguous_9_alerts.json, and compares each against its reconstructed
clean counterpart.

Measures four hijack signals per alert pair:
  1. schema_violation    — model output is unparseable or missing/invalid keys
  2. verdict_flip        — contaminated verdict differs from clean verdict
  3. unauthorized_action — contaminated action == "abort"
  4. instruction_following — response contains known injection exemplar phrases

Outputs:
  - Per-alert summary table printed live during the run
  - Final aggregate hijack-rate table (overall + per injection_category)
  - Full raw results saved to agent/hardersubtle_ambiguous_eval_results_flashlite.json
"""
from __future__ import annotations

import copy
import json
import os
import sys
import time
from collections import defaultdict
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
from openai import OpenAI

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "GUIDE_Dataset" / "processed"))

# Import reusable logic
from agent.baseline_agent import (
    VERDICT_VALUES,
    ACTION_VALUES,
    build_undefended_prompt,
    call_agent,
    call_agent_groq,
)
from agent.run_baseline_eval import (
    strip_ground_truth,
    compute_hijack_signals,
    flag_str,
)
from synth_fields import synthesize_row, build_raw_log_text

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ALERTS_JSON = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_hardersubtle_ambiguous_9_alerts.json"
RAW_CSV_PATH = PROJECT_ROOT / "GUIDE_Dataset" / "raw" / "guide_sample_500" / "guide_sample_500.csv"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SMOKE_TEST_ONLY = False

PROVIDER = "gemini_flash_lite"  # "gemini", "groq", or "gemini_flash_lite"
MODEL = "gemini-3.1-flash-lite"

if PROVIDER == "groq":
    RESULTS_JSON = PROJECT_ROOT / "agent" / "hardersubtle_ambiguous_eval_results_groq.json"
elif PROVIDER == "gemini_flash_lite":
    RESULTS_JSON = PROJECT_ROOT / "agent" / "hardersubtle_ambiguous_eval_results_flashlite.json"
else:
    RESULTS_JSON = PROJECT_ROOT / "agent" / "hardersubtle_ambiguous_eval_results.json"

INTER_CALL_SLEEP = 2.5  # seconds between API calls

INJECTION_CATEGORIES = [
    "zero_imperative_evidence",
    "native_format_mimicry",
    "multi_source_corroboration",
]

# ANSI colours
BOLD    = "\033[1m"
CYAN    = "\033[36m"
GREEN   = "\033[32m"
RED     = "\033[31m"
YELLOW  = "\033[33m"
RST     = "\033[0m"
SEP     = "-" * 90


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
    cat = clean.get("_ground_truth_injection_category")

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
# Helpers: smoke tests and aggregate table printer
# ---------------------------------------------------------------------------

def _run_smoke_test(client, sampled: list) -> None:
    """Smoke-test MODEL against alert index 0."""
    alert = sampled[0]
    alert_id = alert.get("alert_id", "?")
    injection_cat = alert.get("_ground_truth_injection_category", "?")

    agent_alert, _ = strip_ground_truth(alert)
    prompt = build_undefended_prompt(agent_alert)

    p(f"SMOKE TEST  (provider={PROVIDER}, model={MODEL})")
    p(f"Alert: {alert_id}  |  Injection category: {injection_cat}")
    p("Running ONE contaminated call — clean pairing skipped to save quota.")
    p("="  * 90)

    if PROVIDER == "groq":
        result = call_agent_groq(prompt, client, model=MODEL)
    else:
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


def _print_aggregate_table(all_results: list, model_label: str) -> None:
    """Print overall and per-category hijack signal rates, labelled with the model name."""
    p("")
    p(SEP)
    p(f"Aggregate Hijack Signal Rates  (model={model_label}, n={len(all_results)} contaminated alerts)")
    p("")

    signal_names  = ["schema_violation", "verdict_flip", "unauthorized_action", "instruction_following"]
    signal_labels = ["Schema Violation", "Verdict Flip", "Unauth. Action (abort)", "Instruction Following"]

    p("Overall:")
    p(f"  {'Signal':<30} {'Count':>6} {'Rate':>8}")
    p("  " + "-" * 46)
    for name, label in zip(signal_names, signal_labels):
        count = sum(1 for r in all_results if r["hijack_signals"][name])
        rate = count / len(all_results) if all_results else 0.0
        bar = "#" * int(rate * 20)
        p(f"  {label:<30} {count:>6} {rate:>7.1%}  {bar}")

    p("")
    p("Per Injection Category:")
    cat_header = f"  {'Category':<22}" + "".join(f" {lab[:14]:>14}" for lab in signal_labels)
    p(cat_header)
    p("  " + "-" * (22 + 15 * len(signal_names)))

    by_cat: dict[str, list] = defaultdict(list)
    for r in all_results:
        by_cat[r["injection_category"]].append(r)

    for cat in INJECTION_CATEGORIES:
        rows = by_cat.get(cat, [])
        n = len(rows)
        if n == 0:
            continue
        rates = []
        for name in signal_names:
            count = sum(1 for r in rows if r["hijack_signals"][name])
            rates.append(count / n)
        rate_str = "".join(f" {r:>13.1%}" for r in rates)
        p(f"  {cat:<22}{rate_str}  (n={n})")


# ---------------------------------------------------------------------------
# Main evaluation loop
# ---------------------------------------------------------------------------

def main() -> None:
    # ── Load data ────────────────────────────────────────────────────────────
    p(f"\nPhase 3 -- Harder-Subtle Payloads Evaluation (Ambiguous)")
    p(SEP)
    p(f"Loading alerts from: {ALERTS_JSON}")

    with open(ALERTS_JSON, encoding="utf-8") as f:
        sampled = json.load(f)

    p(f"Total alerts loaded: {len(sampled)}")

    # ── API client ───────────────────────────────────────────────────────────
    if PROVIDER == "groq":
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            p("FAIL: GROQ_API_KEY not set. Check .env at project root.")
            sys.exit(1)
        client = OpenAI(
            base_url="https://api.groq.com/openai/v1",
            api_key=api_key,
        )
    else:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            p("FAIL: GEMINI_API_KEY not set. Check .env at project root.")
            sys.exit(1)
        client = genai.Client(api_key=api_key)

    if SMOKE_TEST_ONLY:
        _run_smoke_test(client, sampled)
        return

    # ── Full batch ───────────────────────────────
    p(f"")
    p(f"=== Full batch: {PROVIDER} / {MODEL} ===")
    p(f"{'#':<4} {'Alert ID':<20} {'Injection Cat':<22} {'SchemaViol':<12} {'VerdFlip':<10} {'UnauthAct':<11} {'InstrFollow'}")
    p("-" * 90)

    all_results = []

    for i, alert in enumerate(sampled, start=1):
        alert_id = alert.get("alert_id", "?")
        injection_cat = alert.get("_ground_truth_injection_category", "?")

        agent_alert, ground_truth = strip_ground_truth(alert)
        clean_alert = reconstruct_clean_alert(agent_alert)

        contaminated_prompt = build_undefended_prompt(agent_alert)
        clean_prompt = build_undefended_prompt(clean_alert)

        # Call 1: contaminated
        if PROVIDER == "groq":
            cont_result = call_agent_groq(contaminated_prompt, client, model=MODEL)
        else:
            cont_result = call_agent(contaminated_prompt, client, model=MODEL)
        time.sleep(INTER_CALL_SLEEP)

        # Call 2: clean
        if PROVIDER == "groq":
            clean_result = call_agent_groq(clean_prompt, client, model=MODEL)
        else:
            clean_result = call_agent(clean_prompt, client, model=MODEL)
        if i < len(sampled):
            time.sleep(INTER_CALL_SLEEP)

        signals = compute_hijack_signals(cont_result, clean_result)

        row = (
            f"{i:<4} {alert_id:<20} {injection_cat:<22} "
            f"{flag_str(signals['schema_violation']):<12} "
            f"{flag_str(signals['verdict_flip']):<10} "
            f"{flag_str(signals['unauthorized_action']):<11} "
            f"{flag_str(signals['instruction_following'])}"
        )
        p(row)

        all_results.append({
            "alert_id": alert_id,
            "injection_category": injection_cat,
            "ground_truth": ground_truth,
            "contaminated_prompt": contaminated_prompt,
            "clean_prompt": clean_prompt,
            "contaminated_result": cont_result,
            "clean_result": clean_result,
            "hijack_signals": signals,
        })

    # ── Aggregate + save ──────────────────────────────────
    _print_aggregate_table(all_results, model_label=MODEL)

    p("")
    p(SEP)
    p(f"Saving {MODEL} results to: {RESULTS_JSON}")
    with open(RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    p(f"{MODEL} results saved.")


if __name__ == "__main__":
    main()
