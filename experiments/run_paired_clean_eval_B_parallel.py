"""
experiments/run_paired_clean_eval_B_parallel.py

Parallel variant of run_paired_clean_eval_B.py for Experiment 1.

Runs the remaining alerts from paired_clean_results_B.json using one LLM
worker per API key (5 keys = 5 workers).  Only the LLM call runs in
parallel; evidentiary filter, SSE scoring, record building, and checkpoint
writes all happen sequentially in the main thread.

Usage:
    python -m experiments.run_paired_clean_eval_B_parallel
    python -m experiments.run_paired_clean_eval_B_parallel --scratch scratch.json --limit 10
"""
from __future__ import annotations

import json
import multiprocessing
import os
import queue
import sys
import tempfile
import threading
import time
import datetime
from pathlib import Path

# Project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Files
CLEAN_ALERTS_JSON = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_sample_500_alerts.json"
CONTAM_ALERTS_JSON = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_n50_scaleup_320_alerts.json"
RESULTS_JSON = PROJECT_ROOT / "experiments" / "paired_clean_results_B.json"
API_LOG = PROJECT_ROOT / "experiments" / "paired_clean_api_log_B.jsonl"

# Timing
INTER_CALL_DELAY_S = 5.0
CALL_TIMEOUT_S = 60
MAX_ATTEMPTS_PER_ALERT = 3
RETRY_BACKOFF = [5, 10, 20]  # seconds between retries

MODEL = "gemini-3.1-flash-lite"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _p(msg: str) -> None:
    """Print with timestamp, flush immediately."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def _log_api_call(log_path: Path, *, alert_id: str, model: str,
                  key_index: int, child_key_last4: str, success: bool, api_call_count: int,
                  error: str | None = None, wall_clock_s: float = 0.0) -> None:
    """Append one line to the JSONL audit log (thread-safe via GIL)."""
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "alert_id": alert_id,
        "model": model,
        "key_index": key_index,
        "child_key_last4": child_key_last4,
        "wall_clock_s": wall_clock_s,
        "success": success,
        "api_call_count": api_call_count,
    }
    if error:
        entry["error"] = error
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Serialization helpers (same as run_paired_clean_eval.py)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Child process worker (for _call_with_timeout)
# ---------------------------------------------------------------------------

def _worker(q: multiprocessing.Queue, active_key: str, all_keys: list[str], fn, args: tuple, kwargs: dict) -> None:
    """Target for _call_with_timeout child process.

    KEY DELIVERY: The parent passes the desired active_key.
    The child rebuilds GEMINI_API_KEYS so the pool contains ONLY the
    active key first, plus any others that are NOT duplicates.
    """
    if active_key:
        # Build deduped list: active_key first, then others
        other_keys = [
            k.strip() for k in all_keys
            if k.strip() and k.strip() != active_key
        ]
        os.environ["GEMINI_API_KEYS"] = ",".join([active_key] + other_keys)
    try:
        from agent.key_pool import load_gemini_pool
        pool = load_gemini_pool()
        child_key_last4 = pool.current()[-4:] if pool.keys else ""
        
        result = fn(*args, **kwargs)
        q.put(("ok", result, child_key_last4))
    except Exception as exc:  # noqa: BLE001
        q.put(("err", exc, ""))


def _call_with_timeout(fn, *args, active_key: str = "", all_keys: list[str] = None,
                       timeout: float = CALL_TIMEOUT_S, **kwargs):
    """Run fn(*args, **kwargs) in a child *process* with a hard timeout.

    Unlike a thread, the child process can be terminate()d when the network
    socket is blocked, so the 60-second limit is guaranteed.
    Raises TimeoutError on timeout, or re-raises the function's exception.

    active_key: the API key the parent wants the child to use first.
    """
    ctx = multiprocessing.get_context("spawn")
    q: multiprocessing.Queue = ctx.Queue()
    all_keys_list = all_keys or []
    
    p = ctx.Process(target=_worker, args=(q, active_key, all_keys_list, fn, args, kwargs), daemon=True)
    p.start()
    
    p.join(timeout=timeout)
    if p.is_alive():
        p.terminate()
        p.join(timeout=5)
        raise TimeoutError(f"Call timed out after {timeout}s")
    try:
        tag, val, child_key_last4 = q.get(timeout=2)
    except Exception:
        raise RuntimeError(
            "Worker process exited but queue is empty (OS scheduling edge case)"
        )
    if tag == "ok":
        return val, child_key_last4
    raise val


# ---------------------------------------------------------------------------
# Atomic checkpoint write
# ---------------------------------------------------------------------------

def _atomic_checkpoint_write(results_by_id: dict, checkpoint_path: Path) -> None:
    """Write checkpoint atomically: write to temp file, then os.replace.

    Both the temp file and the final file are in the same directory so
    os.replace is guaranteed to be atomic on both NTFS and ext4.
    """
    data = list(results_by_id.values())
    parent = checkpoint_path.parent
    fd, tmp_path = tempfile.mkstemp(
        suffix=".tmp", prefix="ckpt_", dir=str(parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, str(checkpoint_path))
    except BaseException:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _load_checkpoint(checkpoint_path: Path) -> dict[str, dict]:
    """Load existing results. STOP with error if the file exists but is corrupt."""
    if not checkpoint_path.exists():
        return {}
    try:
        with open(checkpoint_path, encoding="utf-8") as f:
            existing = json.load(f)
    except (json.JSONDecodeError, ValueError) as exc:
        _p(f"FATAL: checkpoint {checkpoint_path} is corrupt: {exc}")
        _p("Refusing to restart from zero. Fix the checkpoint or restore backup.")
        sys.exit(3)
    results_by_id: dict[str, dict] = {}
    for r in existing:
        if r.get("sse_results") is not None and not r.get("nce_error"):
            results_by_id[str(r["alert_id"])] = r
    return results_by_id


# ---------------------------------------------------------------------------
# LLM worker thread (one per key)
# ---------------------------------------------------------------------------

def _llm_worker_thread(
    worker_id: int,
    key: str,
    key_index: int,
    task_queue: queue.Queue,
    result_queue: queue.Queue,
    all_keys: list[str],
    stop_event: threading.Event,
) -> None:
    """Worker thread: pulls (alert_id, nce_input) from task_queue, makes the
    LLM call with up to MAX_ATTEMPTS_PER_ALERT attempts, and puts the result
    on result_queue.

    Each worker keeps at least INTER_CALL_DELAY_S between its own calls.
    Each call runs in a spawned child process with a hard CALL_TIMEOUT_S timeout.

    429 handling: on a 429, the worker rotates to another key from its own
    key list (all_keys minus its primary) and retries. After MAX_ATTEMPTS_PER_ALERT
    failures the alert is recorded as api_error.
    """
    from perception.nce_engine import generate_hypotheses
    from agent.llm_utils import is_rate_limit_error

    # Build per-worker key rotation list: primary key first, then others
    worker_keys = [key] + [k for k in all_keys if k != key]
    current_key = key
    current_key_idx = key_index
    last_call_time = 0.0

    while not stop_event.is_set():
        try:
            alert_id, nce_input = task_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        if alert_id is None:  # poison pill
            task_queue.task_done()
            break

        call_result = None
        last_error = None
        used_key_idx = current_key_idx
        child_key_last4 = ""
        duration = 0.0

        for attempt in range(MAX_ATTEMPTS_PER_ALERT):
            # Enforce per-worker inter-call delay
            elapsed = time.monotonic() - last_call_time
            if elapsed < INTER_CALL_DELAY_S:
                time.sleep(INTER_CALL_DELAY_S - elapsed)

            _p(f"  [W{worker_id}] alert_id={alert_id} attempt {attempt+1}/{MAX_ATTEMPTS_PER_ALERT} "
               f"key_idx={current_key_idx} key=...{current_key[-4:]}")

            try:
                last_call_time = time.monotonic()
                t0 = time.monotonic()
                call_result, child_key_last4 = _call_with_timeout(
                    generate_hypotheses,
                    nce_input,
                    model=MODEL,
                    apply_evidentiary_filter=False,
                    active_key=current_key,
                    all_keys=all_keys,
                    timeout=CALL_TIMEOUT_S,
                )
                duration = time.monotonic() - t0
                if call_result.success:
                    used_key_idx = current_key_idx
                    break
                # Check for API_ERROR or success=False
                last_error = call_result.error
                _p(f"  [W{worker_id}] alert_id={alert_id} attempt {attempt+1} failed: {last_error}")

                # Check if rate limit error from NCECallResult error string
                if last_error and (
                    is_rate_limit_error(Exception(last_error))
                    or last_error.startswith("API_ERROR")
                ):
                    # Rotate to next key in worker's list
                    _rotate_worker_key(worker_id, worker_keys, current_key)
                    old_idx = current_key_idx
                    current_key, current_key_idx = _next_key(
                        worker_keys, current_key, all_keys
                    )
                    _p(f"  [W{worker_id}] rotated key {old_idx} -> {current_key_idx}")

            except (TimeoutError, RuntimeError) as exc:
                last_error = f"TIMEOUT after {CALL_TIMEOUT_S}s: {exc}"
                _p(f"  [W{worker_id}] alert_id={alert_id} attempt {attempt+1}: {last_error}")
                call_result = None
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                _p(f"  [W{worker_id}] alert_id={alert_id} attempt {attempt+1} exception: {last_error}")
                call_result = None
                # Check if this is a rate limit exception
                if is_rate_limit_error(exc):
                    old_idx = current_key_idx
                    current_key, current_key_idx = _next_key(
                        worker_keys, current_key, all_keys
                    )
                    _p(f"  [W{worker_id}] rotated key {old_idx} -> {current_key_idx}")

            if attempt < MAX_ATTEMPTS_PER_ALERT - 1:
                backoff = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
                _p(f"  [W{worker_id}] backing off {backoff}s before retry...")
                time.sleep(backoff)

        # Put result on queue for main thread
        result_queue.put((alert_id, call_result, last_error, used_key_idx, child_key_last4, duration))
        task_queue.task_done()


def _next_key(worker_keys: list[str], current_key: str,
              all_keys: list[str]) -> tuple[str, int]:
    """Rotate to the next key in worker_keys, return (key, global_index)."""
    try:
        idx = worker_keys.index(current_key)
    except ValueError:
        idx = -1
    next_idx = (idx + 1) % len(worker_keys)
    next_key = worker_keys[next_idx]
    global_idx = all_keys.index(next_key)
    return next_key, global_idx


def _rotate_worker_key(worker_id: int, worker_keys: list[str],
                       current_key: str) -> None:
    """Log rotation (no-op beyond logging, actual rotation in _next_key)."""
    pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    from perception.knowledge_graph import KnowledgeStoreGraph
    from perception.sse import StructuralSimulationEngine
    from perception.nce_engine import alert_to_nce_input
    from perception.nce_engine import _apply_t1071_evidentiary_filter
    from perception.nce_sse_integration import validate_hypothesis_with_sse
    from perception.nce_contract import HypothesisStatus
    from agent.key_pool import load_gemini_pool

    # CLI args
    scratch_path = None
    limit = None
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--scratch" and i < len(sys.argv) - 1:
            scratch_path = PROJECT_ROOT / "experiments" / sys.argv[i + 1]
        if arg == "--limit" and i < len(sys.argv) - 1:
            limit = int(sys.argv[i + 1])

    checkpoint_path = Path(scratch_path) if scratch_path else RESULTS_JSON
    log_path = API_LOG
    if scratch_path:
        log_path = checkpoint_path.with_suffix(".api_log.jsonl")

    # Load alert data
    _p("Loading alert data...")
    with open(CLEAN_ALERTS_JSON, encoding="utf-8") as f:
        all_clean = json.load(f)
    with open(CONTAM_ALERTS_JSON, encoding="utf-8") as f:
        contam_alerts = json.load(f)

    # Target alert IDs = the 320 contaminated alert IDs
    clean_by_id = {str(a["alert_id"]): a for a in all_clean}
    clean_selection = []
    for ca in contam_alerts:
        aid = str(ca["alert_id"])
        if aid in clean_by_id:
            clean_selection.append(clean_by_id[aid])
        else:
            _p(f"  WARNING: alert_id {aid} not found in clean corpus")

    _p(f"Clean alerts matched: {len(clean_selection)}/320")

    # Load existing results for checkpoint resume
    results_by_id = _load_checkpoint(checkpoint_path)
    _p(f"Loaded {len(results_by_id)} existing results for checkpoint resume")

    # Also load from the MAIN checkpoint if we're in scratch mode,
    # so we don't re-process alerts already done in the real checkpoint
    main_done_ids: set[str] = set()
    if scratch_path and RESULTS_JSON.exists():
        main_results = _load_checkpoint(RESULTS_JSON)
        main_done_ids = set(main_results.keys())
        _p(f"Loaded {len(main_done_ids)} IDs from main checkpoint to skip")

    # Build work queue: skip already-completed alert_ids
    pending_alerts = []
    skipped = 0
    for alert in clean_selection:
        aid = str(alert["alert_id"])
        if aid in results_by_id:
            skipped += 1
            continue
        if scratch_path and aid in main_done_ids:
            skipped += 1
            continue
        pending_alerts.append(alert)

    if limit:
        pending_alerts = pending_alerts[:limit]

    total_pending = len(pending_alerts)
    _p(f"Pending: {total_pending}, skipped: {skipped}")

    if total_pending == 0:
        _p("Nothing to do.")
        return

    # Initialize pipeline (main thread only)
    pool = load_gemini_pool()
    all_keys = list(pool.keys)
    num_workers = len(all_keys)
    _p(f"Key pool: {num_workers} keys, last4: {[k[-4:] for k in all_keys]}")

    gs = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(gs)
    _p("SSE initialized with default graph")

    # Prepare queues
    task_q: queue.Queue = queue.Queue()
    result_q: queue.Queue = queue.Queue()
    stop_event = threading.Event()

    # Pre-compute nce_inputs and enqueue
    alert_map: dict[str, dict] = {}  # alert_id -> alert dict
    for alert in pending_alerts:
        aid = str(alert["alert_id"])
        nce_input = alert_to_nce_input(alert)
        task_q.put((aid, nce_input))
        alert_map[aid] = alert

    # Start worker threads
    workers: list[threading.Thread] = []
    for i in range(num_workers):
        t = threading.Thread(
            target=_llm_worker_thread,
            args=(i, all_keys[i], i, task_q, result_q, all_keys, stop_event),
            daemon=True,
            name=f"llm-worker-{i}",
        )
        t.start()
        workers.append(t)

    _p(f"Started {num_workers} LLM workers")

    # Main loop: collect results, do SSE, checkpoint
    completed = 0
    api_errors = 0
    start_time = time.monotonic()
    per_alert_times: list[float] = []

    try:
        while completed < total_pending:
            try:
                alert_id, call_result, last_error, used_key_idx, child_key_last4, duration = result_q.get(timeout=300)
            except queue.Empty:
                _p("WARNING: 300s without a result from any worker!")
                continue

            alert_start = time.monotonic()
            alert = alert_map[alert_id]

            record = {
                "alert_id": alert_id,
                "source_user": alert.get("source_user"),
                "source_host": alert.get("source_host"),
                "target_host": alert.get("target_host"),
                "model": MODEL,
                "key_index": used_key_idx,
                "condition": "clean",
            }

            if call_result and call_result.success and call_result.output:
                record["nce_api_calls"] = call_result.api_call_count
                record["nce_raw_response"] = call_result.raw_response

                _log_api_call(
                    log_path, alert_id=alert_id, model=MODEL,
                    key_index=used_key_idx, child_key_last4=child_key_last4, success=True,
                    api_call_count=call_result.api_call_count, wall_clock_s=round(duration, 2)
                )

                baseline_hyps = list(call_result.output.hypotheses)
                _p(f"  [{completed+1}/{total_pending}] alert_id={alert_id} "
                   f"NCE: {len(baseline_hyps)} hyps, key_idx={used_key_idx}")
            else:
                # Exhausted retries — record as api_error
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
                    log_path, alert_id=alert_id, model=MODEL,
                    key_index=used_key_idx, child_key_last4=child_key_last4, success=False,
                    api_call_count=0, error=error_msg, wall_clock_s=round(duration, 2)
                )

                _p(f"  [{completed+1}/{total_pending}] alert_id={alert_id} "
                   f"API ERROR: {error_msg}")
                api_errors += 1
                baseline_hyps = []

                results_by_id[alert_id] = record
                completed += 1
                _atomic_checkpoint_write(results_by_id, checkpoint_path)
                per_alert_times.append(time.monotonic() - alert_start)
                continue

            # --- Sequential post-processing (main thread) ---

            # Step 2: SSE on Baseline Hypotheses (pre-filter)
            nce_input = alert_to_nce_input(alert)
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

            # Step 3: Apply Evidentiary Threshold Filter
            surviving_hyps, drops = _apply_t1071_evidentiary_filter(
                baseline_hyps, nce_input.evidence_fields
            )
            record["evidentiary_filter_drops"] = drops

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

            # Save atomically
            results_by_id[alert_id] = record
            completed += 1
            _atomic_checkpoint_write(results_by_id, checkpoint_path)

            elapsed_alert = time.monotonic() - alert_start
            per_alert_times.append(elapsed_alert)

            if completed % 5 == 0:
                elapsed_total = time.monotonic() - start_time
                rate = completed / elapsed_total * 60 if elapsed_total > 0 else 0
                _p(f"  Checkpoint: {completed}/{total_pending} new, "
                   f"{api_errors} errors, {rate:.1f} alerts/min")

    except KeyboardInterrupt:
        _p("KeyboardInterrupt — stopping workers...")
        stop_event.set()

    # Send poison pills
    for _ in workers:
        task_q.put((None, None))

    for t in workers:
        t.join(timeout=10)

    elapsed_total = time.monotonic() - start_time
    _p(f"\nDone: {completed} new, {skipped} skipped, {len(results_by_id)} total, "
       f"{api_errors} api_errors, {elapsed_total:.1f}s total")
    _p(f"Results: {checkpoint_path}")

    if per_alert_times:
        avg = sum(per_alert_times) / len(per_alert_times)
        _p(f"Avg main-thread time per alert: {avg:.2f}s")


if __name__ == "__main__":
    main()
