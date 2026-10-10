"""
experiments/run_paired_clean_eval.py

Experiment 1: Paired clean-vs-contaminated evaluation.

Runs NCE+SSE on 320 clean versions of the same alerts used in the n=320
contaminated evaluation. Uses the same dual-pass code path as
agent/run_nce_n50_scaleup_eval.py:
  1. generate_hypotheses(apply_evidentiary_filter=False)
  2. _apply_t1071_evidentiary_filter post-hoc
  3. SSE on both pre-filter and post-filter hypotheses

Contaminated results are reused from runA and runB (no new LLM calls for those).

Usage:
    python -m experiments.run_paired_clean_eval
    python -m experiments.run_paired_clean_eval --show-selection-only
"""
from __future__ import annotations

import json
import sys
import time
import datetime
import concurrent.futures
from pathlib import Path

# Project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Files
CLEAN_ALERTS_JSON = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_sample_500_alerts.json"
CONTAM_ALERTS_JSON = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_n50_scaleup_320_alerts.json"
RUN_A_JSON = PROJECT_ROOT / "agent" / "nce_n50_scaleup_results_runA.json"
RUN_B_JSON = PROJECT_ROOT / "agent" / "nce_n50_scaleup_results_runB.json"
RESULTS_JSON = PROJECT_ROOT / "experiments" / "paired_clean_results.json"
API_LOG = PROJECT_ROOT / "experiments" / "paired_clean_api_log.jsonl"

# Inter-call delay: key_pool rotates ONLY on 429, so for a single key at
# 15 RPM = 1 call per 4s minimum. With safety margin: 5s.
INTER_CALL_DELAY_S = 5.0

# Per-call timeout (seconds). _call_gemini_nce has no built-in timeout,
# so we wrap generate_hypotheses in a thread with this deadline.
CALL_TIMEOUT_S = 60

# Maximum retries per alert (exponential backoff).
MAX_RETRIES_PER_ALERT = 3
RETRY_BACKOFF = [5, 10, 20]  # seconds between retries

MODEL = "gemini-3.1-flash-lite"


def _p(msg: str) -> None:
    """Print with timestamp, flush immediately."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def _log_api_call(*, alert_id: str, model: str, key_index: int,
                  success: bool, api_call_count: int,
                  error: str | None = None) -> None:
    """Append one line to the JSONL audit log."""
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "alert_id": alert_id,
        "model": model,
        "key_index": key_index,
        "success": success,
        "api_call_count": api_call_count,
    }
    if error:
        entry["error"] = error
    with open(API_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _serialize_hypothesis(h) -> dict:
    """Serialize NCEHypothesis to dict."""
    return {
        "technique_id": h.technique_id,
        "source_account": h.source_account,
        "source_host": h.source_host,
        "target_host": h.target_host,
        "nce_confidence": h.nce_confidence,
        "supporting_evidence_refs": list(h.supporting_evidence_refs),
        "missing_context_flags": [f.value for f in h.missing_context_flags],
        "status": h.status.value,
    }


def _serialize_validated(vh) -> dict:
    """Serialize ValidatedHypothesis to dict."""
    d = _serialize_hypothesis(vh.hypothesis)
    d["sse_verdict"] = vh.best_sse_verdict.value if vh.best_sse_verdict else "NONE"
    d["path_confidence"] = vh.best_path_confidence
    d["confidence_gap"] = vh.confidence_gap
    return d


def _call_with_timeout(fn, *args, timeout=CALL_TIMEOUT_S, **kwargs):
    """Run fn(*args, **kwargs) in a thread pool with a timeout.

    Returns the result or raises TimeoutError / the original exception.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fn, *args, **kwargs)
        return future.result(timeout=timeout)


def main() -> None:
    from perception.knowledge_graph import KnowledgeStoreGraph
    from perception.sse import StructuralSimulationEngine
    from perception.nce_engine import generate_hypotheses, alert_to_nce_input
    from perception.nce_engine import _apply_t1071_evidentiary_filter
    from perception.nce_sse_integration import validate_hypothesis_with_sse
    from perception.nce_contract import HypothesisStatus
    from agent.key_pool import load_gemini_pool

    show_only = "--show-selection-only" in sys.argv

    # Load alert data
    _p("Loading alert data...")
    with open(CLEAN_ALERTS_JSON, encoding="utf-8") as f:
        all_clean = json.load(f)
    with open(CONTAM_ALERTS_JSON, encoding="utf-8") as f:
        contam_alerts = json.load(f)

    # Target alert IDs = the 320 contaminated alert IDs
    target_ids = {str(a["alert_id"]) for a in contam_alerts}
    clean_by_id = {str(a["alert_id"]): a for a in all_clean}

    # Verify all 320 IDs have clean versions
    clean_selection = []
    for ca in contam_alerts:
        aid = str(ca["alert_id"])
        if aid in clean_by_id:
            clean_selection.append(clean_by_id[aid])
        else:
            _p(f"  WARNING: alert_id {aid} not found in clean corpus")

    _p(f"Clean alerts matched: {len(clean_selection)}/320")

    if show_only:
        for i, a in enumerate(clean_selection[:5]):
            _p(f"  [{i}] alert_id={a['alert_id']} user={a.get('source_user')} host={a.get('source_host')}")
        _p(f"  ... ({len(clean_selection)} total)")
        return

    # Load existing results for checkpointing
    results_by_id: dict[str, dict] = {}
    if RESULTS_JSON.exists():
        with open(RESULTS_JSON, encoding="utf-8") as f:
            existing = json.load(f)
        for r in existing:
            if r.get("sse_results") is not None or r.get("nce_error") is not None:
                results_by_id[str(r["alert_id"])] = r
        _p(f"Loaded {len(results_by_id)} existing results for checkpoint resume")

    # Initialize pipeline
    pool = load_gemini_pool()
    _p(f"Key pool: {len(pool.keys)} keys")
    gs = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(gs)
    _p("SSE initialized with default graph")

    # Process alerts
    completed = 0
    skipped = 0
    api_errors = 0
    total = len(clean_selection)

    for idx, alert in enumerate(clean_selection):
        aid = str(alert["alert_id"])

        if aid in results_by_id:
            skipped += 1
            continue

        _p(f"[{idx+1}/{total}] alert_id={aid} user={alert.get('source_user')}")

        nce_input = alert_to_nce_input(alert)
        target_key_idx = pool.current_index()

        record = {
            "alert_id": aid,
            "source_user": alert.get("source_user"),
            "source_host": alert.get("source_host"),
            "target_host": alert.get("target_host"),
            "model": MODEL,
            "key_index": target_key_idx,
            "condition": "clean",
        }

        # Step 1: Call NCE with timeout + bounded retry
        call_result = None
        last_error = None

        for attempt in range(MAX_RETRIES_PER_ALERT):
            try:
                _p(f"  Calling generate_hypotheses (attempt {attempt+1}/{MAX_RETRIES_PER_ALERT}, timeout={CALL_TIMEOUT_S}s)...")
                call_result = _call_with_timeout(
                    generate_hypotheses,
                    nce_input,
                    model=MODEL,
                    apply_evidentiary_filter=False,
                    timeout=CALL_TIMEOUT_S,
                )
                if call_result.success:
                    break
                last_error = call_result.error
                _p(f"  Attempt {attempt+1} failed: {last_error}")
            except concurrent.futures.TimeoutError:
                last_error = f"TIMEOUT after {CALL_TIMEOUT_S}s"
                _p(f"  Attempt {attempt+1}: {last_error}")
                call_result = None
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                _p(f"  Attempt {attempt+1} exception: {last_error}")
                call_result = None

            if attempt < MAX_RETRIES_PER_ALERT - 1:
                backoff = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
                _p(f"  Backing off {backoff}s before retry...")
                time.sleep(backoff)

        # Process result
        if call_result and call_result.success and call_result.output:
            record["nce_api_calls"] = call_result.api_call_count
            record["nce_raw_response"] = call_result.raw_response

            _log_api_call(
                alert_id=aid, model=MODEL, key_index=target_key_idx,
                success=True, api_call_count=call_result.api_call_count,
            )

            baseline_hyps = list(call_result.output.hypotheses)
            _p(f"  NCE Baseline: {len(baseline_hyps)} hypotheses")
        else:
            # Exhausted retries — record as api_error and move on
            error_msg = last_error or "Unknown error after retries"
            record["nce_error"] = error_msg
            record["nce_api_calls"] = 0
            record["nce_hypotheses_orig"] = []
            record["sse_results_orig"] = []
            record["sse_feasible_count_orig"] = 0
            record["sse_infeasible_count_orig"] = 0
            record["nce_hypotheses"] = []
            record["sse_results"] = []
            record["sse_feasible_count"] = 0
            record["sse_infeasible_count"] = 0
            record["evidentiary_filter_drops"] = []

            _log_api_call(
                alert_id=aid, model=MODEL, key_index=target_key_idx,
                success=False, api_call_count=0, error=error_msg,
            )

            _p(f"  API ERROR (exhausted retries): {error_msg}")
            api_errors += 1
            baseline_hyps = []

            # Save and continue
            results_by_id[aid] = record
            completed += 1
            all_results = list(results_by_id.values())
            with open(RESULTS_JSON, "w", encoding="utf-8") as f:
                json.dump(all_results, f, indent=2)
            time.sleep(INTER_CALL_DELAY_S)
            continue

        # Step 2: SSE on Baseline Hypotheses (pre-filter)
        validated_orig = []
        sse_records_orig = []
        for h in baseline_hyps:
            vh = validate_hypothesis_with_sse(h, sse)
            validated_orig.append(vh)
            sse_records_orig.append(_serialize_validated(vh))

        feasible_orig = sum(1 for vh in validated_orig
                           if vh.hypothesis.status == HypothesisStatus.FEASIBLE)
        infeasible_orig = sum(1 for vh in validated_orig
                             if vh.hypothesis.status == HypothesisStatus.INFEASIBLE)

        record["nce_hypotheses_orig"] = [_serialize_hypothesis(h) for h in baseline_hyps]
        record["sse_results_orig"] = sse_records_orig
        record["sse_feasible_count_orig"] = feasible_orig
        record["sse_infeasible_count_orig"] = infeasible_orig

        _p(f"  SSE Baseline: {feasible_orig} FEASIBLE, {infeasible_orig} INFEASIBLE")

        # Step 3: Apply Evidentiary Threshold Filter
        surviving_hyps, drops = _apply_t1071_evidentiary_filter(
            baseline_hyps, nce_input.evidence_fields
        )
        record["evidentiary_filter_drops"] = drops
        if drops:
            _p(f"  Evidentiary Filter: dropped {len(drops)} T1071 hypothesis(es)")

        # Step 4: SSE on Filtered Hypotheses
        validated_filtered = []
        sse_records_filtered = []
        for h in surviving_hyps:
            vh = validate_hypothesis_with_sse(h, sse)
            validated_filtered.append(vh)
            sse_records_filtered.append(_serialize_validated(vh))

        feasible_filtered = sum(1 for vh in validated_filtered
                               if vh.hypothesis.status == HypothesisStatus.FEASIBLE)
        infeasible_filtered = sum(1 for vh in validated_filtered
                                 if vh.hypothesis.status == HypothesisStatus.INFEASIBLE)

        record["nce_hypotheses"] = [_serialize_hypothesis(h) for h in surviving_hyps]
        record["sse_results"] = sse_records_filtered
        record["sse_feasible_count"] = feasible_filtered
        record["sse_infeasible_count"] = infeasible_filtered

        _p(f"  SSE Filtered: {feasible_filtered} FEASIBLE, {infeasible_filtered} INFEASIBLE")

        # Save
        results_by_id[aid] = record
        completed += 1

        # Checkpoint
        all_results = list(results_by_id.values())
        with open(RESULTS_JSON, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2)

        if completed % 10 == 0:
            _p(f"  Checkpoint: {completed} new + {skipped} skipped / {total} ({api_errors} api_errors)")

        time.sleep(INTER_CALL_DELAY_S)

    _p(f"\nDone: {completed} new, {skipped} skipped, {len(results_by_id)} total, {api_errors} api_errors")
    _p(f"Results: {RESULTS_JSON}")


if __name__ == "__main__":
    main()
