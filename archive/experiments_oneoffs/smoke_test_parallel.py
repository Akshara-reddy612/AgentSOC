"""
experiments/smoke_test_parallel.py

Smoke test: run 10 alerts (not among the existing 27) in parallel
into a SCRATCH file. Reports per-alert wall-clock, total time, key
used per call, schema comparison, peak memory, and process count.
"""
from __future__ import annotations

import json
import os
import sys
import time
import threading
import psutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

SCRATCH_RESULTS = PROJECT_ROOT / "experiments" / "scratch_smoke_parallel.json"
SCRATCH_LOG = PROJECT_ROOT / "experiments" / "scratch_smoke_parallel.api_log.jsonl"
CLEAN_A_RESULTS = PROJECT_ROOT / "experiments" / "paired_clean_results.json"
CLEAN_B_RESULTS = PROJECT_ROOT / "experiments" / "paired_clean_results_B.json"

peak_mem_mb = 0.0
peak_procs = 0
stop_sampling = False

def _sample_memory():
    global peak_mem_mb, peak_procs
    parent = psutil.Process(os.getpid())
    while not stop_sampling:
        try:
            # Current process + children
            procs = [parent] + parent.children(recursive=True)
            total_mem = sum(p.memory_info().rss for p in procs)
            total_mb = total_mem / (1024 * 1024)
            if total_mb > peak_mem_mb:
                peak_mem_mb = total_mb
            if len(procs) > peak_procs:
                peak_procs = len(procs)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        time.sleep(0.5)

def main():
    global stop_sampling
    
    # Get the 27 existing IDs to exclude
    with open(CLEAN_B_RESULTS, encoding="utf-8") as f:
        existing = json.load(f)
    existing_ids = {str(r["alert_id"]) for r in existing}
    print(f"Existing B IDs to skip: {len(existing_ids)}")

    # Clean up any previous scratch files
    for f in [SCRATCH_RESULTS, SCRATCH_LOG]:
        if f.exists():
            f.unlink()

    sampler = threading.Thread(target=_sample_memory, daemon=True)
    sampler.start()

    # Run the parallel harness with --scratch and --limit 10
    start_time = time.monotonic()

    from experiments.run_paired_clean_eval_B_parallel import main as parallel_main

    orig_argv = sys.argv
    sys.argv = [
        "run_paired_clean_eval_B_parallel",
        "--scratch", "scratch_smoke_parallel.json",
        "--limit", "10",
    ]
    try:
        parallel_main()
    finally:
        sys.argv = orig_argv
        stop_sampling = True

    total_time = time.monotonic() - start_time
    sampler.join()

    print(f"\n{'='*60}")
    print(f"SMOKE TEST RESULTS")
    print(f"{'='*60}")
    print(f"Total wall-clock time: {total_time:.1f}s")
    print(f"Peak memory (process tree): {peak_mem_mb:.1f} MB")
    print(f"Peak process count: {peak_procs}")

    # Load scratch results
    if not SCRATCH_RESULTS.exists():
        print("ERROR: scratch results file not created!")
        return

    with open(SCRATCH_RESULTS, encoding="utf-8") as f:
        results = json.load(f)

    print(f"\nRecords produced: {len(results)}")

    # Per-alert breakdown
    print(f"\n{'Alert ID':<15} {'Idx':<4} {'Used':<5} {'Time(s)':<8} {'Status':<12} {'Raw Response (80 chars)'}")
    print("-" * 110)
    
    # Pre-parse API log to get child_key_last4
    log_data = {}
    if SCRATCH_LOG.exists():
        with open(SCRATCH_LOG) as f:
            for line in f:
                entry = json.loads(line)
                log_data[str(entry["alert_id"])] = entry
                
    for r in results:
        aid = str(r["alert_id"])
        kidx = r.get("key_index", "?")
        log_entry = log_data.get(aid, {})
        used = log_entry.get("child_key_last4", "")
        time_s_val = log_entry.get("wall_clock_s")
        time_s = f"{time_s_val:.1f}" if time_s_val is not None else "N/A"
        raw_resp = r.get("nce_raw_response", "")
        raw_resp_80 = raw_resp[:80].replace("\n", " ") if raw_resp else ""
        if r.get("nce_error"):
            status = "ERROR"
            raw_resp_80 = r.get("nce_error")[:80].replace("\n", " ")
        else:
            n_hyps = len(r.get("sse_results", []))
            status = f"{n_hyps} hyps"
        print(f"{aid:<15} {kidx:<4} {used:<5} {time_s:<8} {status:<12} {raw_resp_80}")

    # Schema comparison with clean-A
    print(f"\n{'='*60}")
    print(f"SCHEMA COMPARISON (scratch vs clean-A)")
    print(f"{'='*60}")

    with open(CLEAN_A_RESULTS, encoding="utf-8") as f:
        clean_a = json.load(f)

    scratch_rec = None
    for r in results:
        if not r.get("nce_error"):
            scratch_rec = r
            break

    if scratch_rec is None:
        print("WARNING: No successful records in scratch to compare!")
    else:
        clean_a_rec = clean_a[0]
        scratch_keys = sorted(scratch_rec.keys())
        clean_a_keys = sorted(clean_a_rec.keys())

        print(f"Scratch keys: {scratch_keys}")
        print(f"Clean-A keys: {clean_a_keys}")

        missing = set(clean_a_keys) - set(scratch_keys)
        extra = set(scratch_keys) - set(clean_a_keys)

        if missing:
            print(f"MISSING in scratch: {missing}")
        if extra:
            print(f"EXTRA in scratch: {extra}")
        if not missing and not extra:
            print("Key sets MATCH exactly")

        # Type comparison
        common = set(scratch_keys) & set(clean_a_keys)
        print(f"\n{'Key':<30} {'Scratch Type':<20} {'Clean-A Type':<20} {'Match'}")
        print("-" * 75)
        for k in sorted(common):
            st = type(scratch_rec[k]).__name__
            ct = type(clean_a_rec[k]).__name__
            match = "YES" if st == ct else "NO"
            print(f"{k:<30} {st:<20} {ct:<20} {match}")

    # API log
    if SCRATCH_LOG.exists():
        print(f"\nAPI log entries:")
        with open(SCRATCH_LOG) as f:
            for line in f:
                entry = json.loads(line)
                print(f"  alert={entry['alert_id']} key_idx={entry['key_index']} "
                      f"success={entry['success']}")

    # Cleanup
    print(f"\nCleaning up scratch files...")
    for fp in [SCRATCH_RESULTS, SCRATCH_LOG]:
        if fp.exists():
            fp.unlink()
            print(f"  Deleted {fp.name}")

    # Estimate full run time
    if len(results) > 0:
        per_alert_serial = total_time / len(results)
        remaining = 293
        est_parallel_min = (remaining / 5 * per_alert_serial) / 60
        print(f"\nPer-alert avg (serial equivalent): {per_alert_serial:.1f}s")
        print(f"Estimated for {remaining} alerts with 5 workers: {est_parallel_min:.0f} min")


if __name__ == "__main__":
    main()
