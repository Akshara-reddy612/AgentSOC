"""
experiments/smoke_test_3alerts.py

Smoke test: run exactly 3 real alerts through the new harness
(run_paired_clean_eval_B logic) into a scratch output file.
Does NOT touch paired_clean_results_B.json.
Prints per-call wall-clock, key_index logged vs key actually used,
and hypotheses returned. Compares record schema to a clean-A record.
"""
from __future__ import annotations

import json
import time
import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRATCH_OUT   = PROJECT_ROOT / "experiments" / "_smoke_3alerts.json"
CLEAN_A_FILE  = PROJECT_ROOT / "experiments" / "paired_clean_results.json"
CONTAM_ALERTS = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_n50_scaleup_320_alerts.json"
CLEAN_ALERTS  = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_sample_500_alerts.json"

MODEL = "gemini-3.1-flash-lite"
CALL_TIMEOUT_S = 60
MAX_RETRIES = 3
RETRY_BACKOFF = [5, 10, 20]


def _p(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def main():
    import multiprocessing
    from perception.knowledge_graph import KnowledgeStoreGraph
    from perception.sse import StructuralSimulationEngine
    from perception.nce_engine import generate_hypotheses, alert_to_nce_input
    from perception.nce_engine import _apply_t1071_evidentiary_filter
    from perception.nce_sse_integration import validate_hypothesis_with_sse
    from perception.nce_contract import HypothesisStatus
    from agent.key_pool import load_gemini_pool

    # Import the updated _call_with_timeout from the fixed harness
    from experiments.run_paired_clean_eval_B import _call_with_timeout

    pool = load_gemini_pool()
    _p(f"Key pool: {len(pool.keys)} keys")
    _p(f"current key_index: {pool.current_index()}, suffix: ...{pool.current()[-6:]}")

    gs = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(gs)

    # Load alerts
    with open(CONTAM_ALERTS, encoding="utf-8") as f:
        contam = json.load(f)
    with open(CLEAN_ALERTS, encoding="utf-8") as f:
        clean_by_id = {str(a["alert_id"]): a for a in json.load(f)}

    # Pick first 3 contaminated IDs that have a clean version
    # Skip the first 27 (already in checkpoint) to avoid redundancy
    target_alerts = []
    for ca in contam:
        aid = str(ca["alert_id"])
        if aid in clean_by_id and len(target_alerts) < 3:
            target_alerts.append(clean_by_id[aid])

    _p(f"Selected {len(target_alerts)} alerts for smoke test")
    total_api_calls = 0
    records = []

    for idx, alert in enumerate(target_alerts):
        aid = str(alert["alert_id"])
        _p(f"[{idx+1}/3] alert_id={aid} user={alert.get('source_user')} host={alert.get('source_host')}")

        nce_input = alert_to_nce_input(alert)
        target_key = pool.current()
        target_key_idx = pool.current_index()
        actual_key_suffix = target_key[-6:]

        call_result = None
        last_error = None
        call_wall_start = time.monotonic()

        for attempt in range(MAX_RETRIES):
            try:
                attempt_start = time.monotonic()
                _p(f"  Attempt {attempt+1}/{MAX_RETRIES} — key_index={target_key_idx} (...{actual_key_suffix}), timeout={CALL_TIMEOUT_S}s")
                call_result = _call_with_timeout(
                    generate_hypotheses,
                    nce_input,
                    model=MODEL,
                    apply_evidentiary_filter=False,
                    active_key=target_key,
                    timeout=CALL_TIMEOUT_S,
                )
                attempt_elapsed = time.monotonic() - attempt_start
                _p(f"  Attempt {attempt+1} completed in {attempt_elapsed:.2f}s")
                if call_result.success:
                    break
                last_error = call_result.error
                _p(f"  Attempt {attempt+1} call_result.success=False: {last_error}")
                # Rotate parent pool on 429
                from agent.llm_utils import is_rate_limit_error
                if last_error and is_rate_limit_error(Exception(last_error)):
                    _p("  429 detected in result — rotating parent pool")
                    pool.rotate()
                    target_key_idx = pool.current_index()
                    target_key = pool.current()
                    actual_key_suffix = target_key[-6:]
            except (TimeoutError, RuntimeError) as exc:
                last_error = f"TIMEOUT/RUNTIME: {exc}"
                _p(f"  Attempt {attempt+1}: {last_error}")
                call_result = None
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                _p(f"  Attempt {attempt+1} exception: {last_error}")
                call_result = None

            if attempt < MAX_RETRIES - 1:
                backoff = RETRY_BACKOFF[attempt]
                _p(f"  Backoff {backoff}s...")
                time.sleep(backoff)

        call_wall_elapsed = time.monotonic() - call_wall_start
        total_api_calls += 1

        record = {
            "alert_id": aid,
            "source_user": alert.get("source_user"),
            "source_host": alert.get("source_host"),
            "target_host": alert.get("target_host"),
            "model": MODEL,
            "key_index": target_key_idx,
            "condition": "clean",
            "wall_clock_s": round(call_wall_elapsed, 2),
        }

        if call_result and call_result.success and call_result.output:
            baseline_hyps = list(call_result.output.hypotheses)
            _p(f"  NCE: {len(baseline_hyps)} hypotheses in {call_wall_elapsed:.2f}s wall")
            for h in baseline_hyps:
                _p(f"    technique={h.technique_id} account={h.source_account} src={h.source_host} tgt={h.target_host} conf={h.nce_confidence}")

            validated = []
            for h in baseline_hyps:
                vh = validate_hypothesis_with_sse(h, sse)
                validated.append(vh)

            surviving, drops = _apply_t1071_evidentiary_filter(baseline_hyps, nce_input.evidence_fields)

            feasible_orig = sum(1 for vh in validated if vh.hypothesis.status == HypothesisStatus.FEASIBLE)
            validated_filt = [validate_hypothesis_with_sse(h, sse) for h in surviving]
            feasible_filt = sum(1 for vh in validated_filt if vh.hypothesis.status == HypothesisStatus.FEASIBLE)

            record.update({
                "nce_api_calls": call_result.api_call_count,
                "nce_raw_response": call_result.raw_response,
                "nce_hypotheses_orig": [
                    {"technique_id": h.technique_id, "source_account": h.source_account,
                     "source_host": h.source_host, "target_host": h.target_host,
                     "nce_confidence": h.nce_confidence, "status": h.status.value,
                     "missing_context_flags": [f.value for f in h.missing_context_flags]}
                    for h in baseline_hyps
                ],
                "sse_results_orig": [
                    {"technique_id": vh.hypothesis.technique_id,
                     "sse_verdict": vh.best_sse_verdict.value if vh.best_sse_verdict else "NONE",
                     "path_confidence": vh.best_path_confidence}
                    for vh in validated
                ],
                "sse_feasible_count_orig": feasible_orig,
                "sse_infeasible_count_orig": len(validated) - feasible_orig,
                "evidentiary_filter_drops": drops,
                "nce_hypotheses": [
                    {"technique_id": h.technique_id, "source_account": h.source_account,
                     "source_host": h.source_host, "target_host": h.target_host,
                     "nce_confidence": h.nce_confidence, "status": h.status.value,
                     "missing_context_flags": [f.value for f in h.missing_context_flags]}
                    for h in surviving
                ],
                "sse_results": [
                    {"technique_id": vh.hypothesis.technique_id,
                     "sse_verdict": vh.best_sse_verdict.value if vh.best_sse_verdict else "NONE",
                     "path_confidence": vh.best_path_confidence}
                    for vh in validated_filt
                ],
                "sse_feasible_count": feasible_filt,
                "sse_infeasible_count": len(validated_filt) - feasible_filt,
            })
        else:
            _p(f"  NCE FAILED after {call_wall_elapsed:.2f}s: {last_error}")
            record["nce_error"] = last_error

        records.append(record)
        _p(f"  wall_clock_s={call_wall_elapsed:.2f}")
        time.sleep(5.0)  # inter-call delay

    _p(f"\nTotal API calls made: {total_api_calls} (expected 3)")

    with open(SCRATCH_OUT, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    _p(f"Smoke output: {SCRATCH_OUT}")

    # Schema comparison vs clean-A
    _p("\n--- Schema comparison: smoke record vs clean-A record ---")
    with open(CLEAN_A_FILE, encoding="utf-8") as f:
        clean_a_records = json.load(f)
    ref = clean_a_records[0]
    ref_keys = set(ref.keys())

    for i, r in enumerate(records):
        smoke_keys = set(r.keys())
        only_in_smoke = smoke_keys - ref_keys
        only_in_ref = ref_keys - smoke_keys
        _p(f"Record {i}: smoke_keys={sorted(smoke_keys)}")
        if only_in_smoke:
            _p(f"  Only in smoke (not in clean-A): {sorted(only_in_smoke)}")
        if only_in_ref:
            _p(f"  Only in clean-A (not in smoke): {sorted(only_in_ref)}")
        if not only_in_smoke and not only_in_ref:
            _p(f"  Schema matches clean-A record.")


if __name__ == "__main__":
    main()
