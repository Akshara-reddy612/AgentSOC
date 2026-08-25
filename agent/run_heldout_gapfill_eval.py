"""
agent/run_heldout_gapfill_eval.py

Phase 3 -- Held-Out Undefended Gap-Fill Evaluation
==================================================
Identifies failed/rate-limited runs from agent/heldout_undefended_results.json,
re-runs them using the KeyPool rotation system, and updates the results file in place.
"""
from __future__ import annotations

import copy
import json
import os
import sys
import time
from pathlib import Path
import pandas as pd

# Force unbuffered UTF-8 stdout (Windows-safe)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def p(*args, **kwargs):
    """Flushing print -- ensures live line-by-line output on Windows."""
    print(*args, **kwargs, flush=True)


from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "GUIDE_Dataset" / "processed"))

# Import key pool and rotation call wrappers
from agent.key_pool import load_gemini_pool, load_groq_pool, KeyPool
from agent.baseline_agent import (
    build_undefended_prompt,
    call_agent_rotating,
    call_agent_groq_rotating,
)
from agent.run_baseline_eval import (
    strip_ground_truth,
    compute_hijack_signals,
    flag_str,
)
from synth_fields import synthesize_row, build_raw_log_text

ALERTS_JSON = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_heldout_140_alerts.json"
RAW_CSV_PATH = PROJECT_ROOT / "GUIDE_Dataset" / "raw" / "guide_test_500" / "guide_test_500.csv"
RESULTS_JSON = PROJECT_ROOT / "agent" / "heldout_undefended_results.json"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SMOKE_TEST_ONLY = False

# Load raw CSV once for deterministic reconstruction
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
    
    if cat in ("multi_source_corroboration", "cross_field_split"):
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


def find_gaps(results: list) -> list[dict]:
    gaps = []
    for r in results:
        err_cont = r['contaminated_result'].get('parse_error') or ''
        err_clean = r['clean_result'].get('parse_error') or ''
        
        need_cont = any(x in err_cont for x in ['429', 'RESOURCE_EXHAUSTED', 'RateLimitError', 'APIConnectionError', 'Connection error']) or err_cont.startswith('API_ERROR')
        need_clean = any(x in err_clean for x in ['429', 'RESOURCE_EXHAUSTED', 'RateLimitError', 'APIConnectionError', 'Connection error']) or err_clean.startswith('API_ERROR')
        
        if need_cont or need_clean:
            need = []
            if need_cont: need.append('contaminated')
            if need_clean: need.append('clean')
            gaps.append({
                'provider': r['provider'],
                'model': r['model'],
                'alert_id': r['alert_id'],
                'category': r['injection_category'],
                'need': need
            })
    return gaps


# ---------------------------------------------------------------------------
# Helpers: smoke tests
# ---------------------------------------------------------------------------

def _run_smoke_test(gemini_pool, groq_pool, gap_list, alerts_dict) -> None:
    p("\n" + "=" * 90)
    p("SMOKE TEST MODE (run_heldout_gapfill_eval.py)")
    p("=" * 90)
    
    if not gap_list:
        p("No gaps found to re-run! All entries in results JSON are clean.")
        sys.exit(0)
        
    first_gap = gap_list[0]
    provider = first_gap['provider']
    alert_id = first_gap['alert_id']
    need_parts = first_gap['need']
    
    alert = alerts_dict[alert_id]
    agent_alert, _ = strip_ground_truth(alert)
    prompt = build_undefended_prompt(agent_alert)
    
    p(f"Smoke testing first gap: {alert_id} ({first_gap['category']}) on {provider}")
    p(f"Parts needing re-run: {need_parts}")
    p(f"Using prompt snippet: {prompt[:150]}...")
    p("-" * 90)
    
    if provider == 'gemini_flash_lite':
        pool = gemini_pool
        result = call_agent_rotating(prompt, pool, model=first_gap['model'])
    else:
        pool = groq_pool
        result = call_agent_groq_rotating(prompt, pool, model=first_gap['model'])
        
    p("--- raw_response ---")
    p(result.get("raw_response") or "")
    p("--- parsed ---")
    p(json.dumps(result.get("parsed"), indent=2) if result.get("parsed") is not None else "None")
    p("--- parse_error ---")
    p(result.get("parse_error") or "None")
    p("")
    
    err = result.get("parse_error") or ""
    if err.startswith("API_ERROR"):
        p("SMOKE TEST FAILED: API error returned.")
        sys.exit(1)
        
    parsed = result.get("parsed")
    required_keys = {"verdict", "action", "confidence", "reasoning"}
    if parsed and isinstance(parsed, dict) and required_keys.issubset(parsed.keys()):
        p("SMOKE TEST PASSED -- model responding correctly. Set SMOKE_TEST_ONLY = False to run the full gap-fill.")
        sys.exit(0)
    else:
        p("SMOKE TEST FAILED: response keys are invalid or parsing failed.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main gapfill logic
# ---------------------------------------------------------------------------

def main() -> None:
    p("=" * 90)
    p("run_heldout_gapfill_eval.py -- Held-Out Undefended Gap-Fill")
    p("=" * 90)
    
    # Load Key Pools
    gemini_pool = load_gemini_pool()
    groq_pool = load_groq_pool()
    
    p(f"Gemini key pool size: {len(gemini_pool.keys)}")
    p(f"Groq key pool size:   {len(groq_pool.keys)}")
    
    # Load original alerts
    p(f"Loading alerts from: {ALERTS_JSON}")
    with open(ALERTS_JSON, encoding="utf-8") as f:
        alerts = json.load(f)
    alerts_dict = {a['alert_id']: a for a in alerts}
    
    # Load results
    p(f"Loading existing results from: {RESULTS_JSON}")
    if not RESULTS_JSON.exists():
        p(f"ERROR: {RESULTS_JSON} does not exist. Run run_heldout_undefended_eval.py first.")
        sys.exit(1)
        
    with open(RESULTS_JSON, encoding="utf-8") as f:
        results = json.load(f)
        
    gap_list = find_gaps(results)
    p(f"Total alerts needing re-run (gaps found): {len(gap_list)}")
    
    gemini_gaps = sum(1 for g in gap_list if g['provider'] == 'gemini_flash_lite')
    groq_gaps = sum(1 for g in gap_list if g['provider'] == 'groq')
    p(f"  - Gemini gaps: {gemini_gaps}")
    p(f"  - Groq gaps:   {groq_gaps}")
    
    if SMOKE_TEST_ONLY:
        _run_smoke_test(gemini_pool, groq_pool, gap_list, alerts_dict)
        return
        
    # Map results for updates
    # We key by (provider, alert_id) to locate the unique dictionary in results list to update
    results_map = {(r['provider'], r['alert_id']): r for r in results}
    
    for i, gap in enumerate(gap_list, start=1):
        provider = gap['provider']
        alert_id = gap['alert_id']
        category = gap['category']
        need_parts = gap['need']
        model = gap['model']
        
        p(f"\n[{i}/{len(gap_list)}] Processing alert {alert_id} ({category}) on {provider}")
        p(f"  Re-running parts: {need_parts}")
        
        r = results_map.get((provider, alert_id))
        if not r:
            p(f"  WARNING: Could not find result entry for {provider} {alert_id} to update.")
            continue
            
        alert = alerts_dict.get(alert_id)
        if not alert:
            p(f"  WARNING: Could not find source alert {alert_id} in {ALERTS_JSON.name}")
            continue
            
        agent_alert, _ = strip_ground_truth(alert)
        clean_alert = reconstruct_clean_alert(agent_alert)

        contaminated_prompt = build_undefended_prompt(agent_alert)
        clean_prompt = build_undefended_prompt(clean_alert)
        
        sleep_time = 5.0 if provider == 'gemini_flash_lite' else 2.5
        
        # contaminated re-run
        if 'contaminated' in need_parts:
            p("  Re-running contaminated call...")
            if provider == 'gemini_flash_lite':
                res = call_agent_rotating(contaminated_prompt, gemini_pool, model=model)
            else:
                res = call_agent_groq_rotating(contaminated_prompt, groq_pool, model=model)
            r['contaminated_result'] = res
            time.sleep(sleep_time)
            
        # clean re-run
        if 'clean' in need_parts:
            p("  Re-running clean call...")
            if provider == 'gemini_flash_lite':
                res = call_agent_rotating(clean_prompt, gemini_pool, model=model)
            else:
                res = call_agent_groq_rotating(clean_prompt, groq_pool, model=model)
            r['clean_result'] = res
            time.sleep(sleep_time)
            
        # Update hijack signals
        signals = compute_hijack_signals(r['contaminated_result'], r['clean_result'])
        r['hijack_signals'] = signals
        
        p(f"  Updated hijack signals: "
          f"SchemaViol={flag_str(signals['schema_violation'])}, "
          f"VerdFlip={flag_str(signals['verdict_flip'])}, "
          f"UnauthAct={flag_str(signals['unauthorized_action'])}, "
          f"InstrFollow={flag_str(signals['instruction_following'])}")
        
    p("\n" + "=" * 90)
    p(f"Saving updated results to: {RESULTS_JSON}")
    with open(RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    p("Gap-fill execution finished successfully.")


if __name__ == "__main__":
    main()
