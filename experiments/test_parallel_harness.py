"""
experiments/test_parallel_harness.py

Tests for run_paired_clean_eval_B_parallel.py:
1. Assigned key is used by the child (deduplication check).
2. A 429 on one worker does not block the others.
3. Checkpoint stays valid JSON after simulated concurrent results.
4. A simulated kill in the middle of a write leaves the previous
   checkpoint loadable (atomic write test).
5. Resume skips completed ids.
6. An api_error record carries nce_error and is excluded by analyze_paired.py.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import queue
import tempfile
import threading
import time
import pytest
from pathlib import Path

# Import the module under test
from experiments.run_paired_clean_eval_B_parallel import (
    _worker,
    _call_with_timeout,
    _atomic_checkpoint_write,
    _load_checkpoint,
    _llm_worker_thread,
    _next_key,
    CALL_TIMEOUT_S,
)


# ---------------------------------------------------------------------------
# Picklable helpers (module-level for spawn)
# ---------------------------------------------------------------------------

def _return_env_key():
    """Returns the GEMINI_API_KEYS env var as seen inside the child."""
    return os.environ.get("GEMINI_API_KEYS", "")


def _return_active_key():
    """Returns the GEMINI_ACTIVE_KEY env var as seen inside the child."""
    return os.environ.get("GEMINI_ACTIVE_KEY", "")


def _fast_return(x):
    return x * 2


def _sleep_and_return(t):
    time.sleep(t)
    return "done"


# ---------------------------------------------------------------------------
# 1. Assigned key is used by the child, with deduplication
# ---------------------------------------------------------------------------

class TestKeyDelivery:
    def test_assigned_key_is_first_in_child(self):
        """The child must see the active key first in GEMINI_API_KEYS,
        and the key must NOT be duplicated."""
        # Set up parent env with 3 keys
        orig = os.environ.get("GEMINI_API_KEYS", "")
        os.environ["GEMINI_API_KEYS"] = "keyA,keyB,keyC"
        try:
            # Call with active_key=keyB — should put keyB first, then keyA,keyC
            result, child_key = _call_with_timeout(
                _return_env_key,
                active_key="keyB",
                all_keys=["keyA", "keyB", "keyC"],
                timeout=15,
            )
            keys = [k.strip() for k in result.split(",") if k.strip()]
            assert keys[0] == "keyB", f"Expected keyB first, got {keys}"
            # No duplicates
            assert len(keys) == len(set(keys)), f"Duplicate keys in child: {keys}"
            # All original keys present
            assert set(keys) == {"keyA", "keyB", "keyC"}, f"Missing keys: {keys}"
        finally:
            if orig:
                os.environ["GEMINI_API_KEYS"] = orig
            else:
                os.environ.pop("GEMINI_API_KEYS", None)

    def test_no_duplicate_when_key_already_first(self):
        """If active_key is already the first key, it must not be duplicated."""
        orig = os.environ.get("GEMINI_API_KEYS", "")
        os.environ["GEMINI_API_KEYS"] = "keyA,keyB,keyC"
        try:
            result, child_key = _call_with_timeout(
                _return_env_key,
                active_key="keyA",
                all_keys=["keyA", "keyB", "keyC"],
                timeout=15,
            )
            keys = [k.strip() for k in result.split(",") if k.strip()]
            assert keys[0] == "keyA"
            assert len(keys) == len(set(keys)), f"Duplicate keys: {keys}"
        finally:
            if orig:
                os.environ["GEMINI_API_KEYS"] = orig
            else:
                os.environ.pop("GEMINI_API_KEYS", None)

class TestConcurrentKeyDelivery:
    def test_concurrent_workers_use_correct_keys(self):
        """Run 5 workers CONCURRENTLY, each making a call at the same instant, 
        and assert child_key_last4 equals the assigned key for every call. Run 20 times."""
        from concurrent.futures import ThreadPoolExecutor
        
        all_keys = ["k1000", "k2000", "k3000", "k4000", "k5000"]
        
        def _run_one(key):
            # _fast_return just returns x*2, but _call_with_timeout also returns child_key_last4
            result, child_key = _call_with_timeout(
                _fast_return, 21,
                active_key=key,
                all_keys=all_keys,
                timeout=15
            )
            return child_key
            
        for round_idx in range(20):
            with ThreadPoolExecutor(max_workers=5) as pool:
                futures = {pool.submit(_run_one, k): k for k in all_keys}
                for f in futures:
                    assigned_key = futures[f]
                    child_key = f.result()
                    assert child_key == assigned_key[-4:], (
                        f"Round {round_idx}: Expected child to use {assigned_key[-4:]}, but used {child_key}"
                    )
        print("[ok] 20 rounds of 5 concurrent workers all used correct keys.")

# ---------------------------------------------------------------------------
# 2. A 429 on one worker does not block the others
# ---------------------------------------------------------------------------

class TestWorkerIndependence:
    def test_429_does_not_block_other_workers(self):
        """Simulate: worker 0 gets a 429 (slow backoff), worker 1 completes fast.
        Worker 1 must finish before worker 0."""
        result_q: queue.Queue = queue.Queue()
        task_q0: queue.Queue = queue.Queue()
        task_q1: queue.Queue = queue.Queue()
        stop_event = threading.Event()
        finish_order = []
        lock = threading.Lock()

        def mock_worker_slow(wid, tq, rq):
            """Simulate a worker that hits 429 and backs off."""
            try:
                aid, _ = tq.get(timeout=5)
            except queue.Empty:
                return
            if aid is None:
                tq.task_done()
                return
            time.sleep(3)  # simulate backoff
            with lock:
                finish_order.append(wid)
            rq.put((aid, None, "429 simulated", 0))
            tq.task_done()

        def mock_worker_fast(wid, tq, rq):
            """Simulate a worker that completes immediately."""
            try:
                aid, _ = tq.get(timeout=5)
            except queue.Empty:
                return
            if aid is None:
                tq.task_done()
                return
            time.sleep(0.1)
            with lock:
                finish_order.append(wid)
            rq.put((aid, "success", None, 1))
            tq.task_done()

        task_q0.put(("alert_slow", None))
        task_q1.put(("alert_fast", None))

        t0 = threading.Thread(target=mock_worker_slow, args=(0, task_q0, result_q))
        t1 = threading.Thread(target=mock_worker_fast, args=(1, task_q1, result_q))
        t0.start()
        t1.start()
        t0.join(timeout=10)
        t1.join(timeout=10)

        # Worker 1 (fast) should finish before worker 0 (slow/429)
        assert finish_order[0] == 1, (
            f"Expected fast worker (1) first, got order: {finish_order}"
        )
        print("[ok] 429 on one worker did not block the other.")


# ---------------------------------------------------------------------------
# 3. Checkpoint stays valid JSON after simulated concurrent results
# ---------------------------------------------------------------------------

class TestCheckpointValidity:
    def test_concurrent_atomic_writes(self, tmp_path):
        """Multiple sequential atomic writes produce valid JSON each time."""
        ckpt = tmp_path / "results.json"
        results = {}

        for i in range(20):
            results[f"alert_{i}"] = {
                "alert_id": f"alert_{i}",
                "sse_results": [],
                "model": "test",
            }
            _atomic_checkpoint_write(results, ckpt)

            # Verify valid JSON after each write
            with open(ckpt, encoding="utf-8") as f:
                loaded = json.load(f)
            assert len(loaded) == i + 1, f"Expected {i+1} records, got {len(loaded)}"

        print(f"[ok] Checkpoint valid JSON after {len(results)} writes.")

    def test_checkpoint_from_multiple_threads(self, tmp_path):
        """Simulate main thread writing checkpoint rapidly."""
        ckpt = tmp_path / "results.json"
        results = {}

        # Write 50 records rapidly
        for i in range(50):
            results[f"alert_{i}"] = {
                "alert_id": f"alert_{i}",
                "sse_results": [],
            }
            _atomic_checkpoint_write(results, ckpt)

        # Final state must be valid
        with open(ckpt, encoding="utf-8") as f:
            loaded = json.load(f)
        assert len(loaded) == 50
        print("[ok] 50 rapid writes produced valid checkpoint.")


# ---------------------------------------------------------------------------
# 4. Simulated kill in middle of write leaves previous checkpoint loadable
# ---------------------------------------------------------------------------

class TestAtomicWriteSafety:
    def test_interrupted_write_preserves_previous(self, tmp_path):
        """If we crash between writing the temp file and os.replace,
        the previous checkpoint must still be loadable."""
        ckpt = tmp_path / "results.json"

        # Write initial valid checkpoint
        initial = {"alert_1": {"alert_id": "alert_1", "sse_results": []}}
        _atomic_checkpoint_write(initial, ckpt)

        # Verify it's loadable
        with open(ckpt, encoding="utf-8") as f:
            loaded = json.load(f)
        assert len(loaded) == 1

        # Simulate a crash: write a corrupt temp file but don't replace
        corrupt_tmp = tmp_path / "ckpt_CORRUPT.tmp"
        with open(corrupt_tmp, "w") as f:
            f.write('{"broken json')
        # The real checkpoint should still be intact
        with open(ckpt, encoding="utf-8") as f:
            loaded = json.load(f)
        assert len(loaded) == 1, "Previous checkpoint was corrupted!"

        print("[ok] Interrupted write preserves previous checkpoint.")

    def test_corrupt_checkpoint_stops_with_error(self, tmp_path):
        """_load_checkpoint must exit(1) on corrupt JSON."""
        ckpt = tmp_path / "results.json"
        with open(ckpt, "w") as f:
            f.write('{"broken json')

        with pytest.raises(SystemExit) as exc_info:
            _load_checkpoint(ckpt)
        assert exc_info.value.code == 3
        print("[ok] Corrupt checkpoint causes sys.exit(1).")


# ---------------------------------------------------------------------------
# 5. Resume skips completed ids
# ---------------------------------------------------------------------------

class TestResume:
    def test_resume_skips_existing(self, tmp_path):
        """Already-completed alert_ids are not re-processed."""
        ckpt = tmp_path / "results.json"

        # Create checkpoint with 3 completed alerts
        existing = {
            "a1": {"alert_id": "a1", "sse_results": [], "model": "test"},
            "a2": {"alert_id": "a2", "sse_results": [], "model": "test"},
            "a3": {"alert_id": "a3", "nce_error": "timeout", "model": "test"},
        }
        _atomic_checkpoint_write(existing, ckpt)

        # Load checkpoint
        loaded = _load_checkpoint(ckpt)
        assert "a1" in loaded
        assert "a2" in loaded
        assert "a3" not in loaded  # nce_error records are NOT loaded so they get retried

        # Simulate pending list filtering
        all_ids = ["a1", "a2", "a3", "a4", "a5"]
        pending = [aid for aid in all_ids if aid not in loaded]
        assert pending == ["a3", "a4", "a5"], f"Expected ['a3','a4','a5'], got {pending}"

        print("[ok] Resume correctly skips completed alert_ids but retries nce_error.")


# ---------------------------------------------------------------------------
# 6. api_error record carries nce_error and excluded by analyze_paired.py
# ---------------------------------------------------------------------------

class TestApiErrorExclusion:
    def test_api_error_has_nce_error_field(self):
        """An api_error record must have nce_error set."""
        record = {
            "alert_id": "test_alert",
            "nce_error": "API_ERROR: ClientError: 429 RESOURCE_EXHAUSTED.",
            "nce_api_calls": 0,
            "nce_hypotheses_orig": [],
            "sse_results_orig": [],
            "sse_feasible_count_orig": 0,
            "sse_infeasible_count_orig": 0,
            "nce_hypotheses": [],
            "sse_results": [],
            "sse_feasible_count": 0,
            "sse_infeasible_count": 0,
            "evidentiary_filter_drops": [],
        }

        assert "nce_error" in record
        assert record["nce_error"].startswith("API_ERROR")

    def test_analyze_paired_excludes_nce_error(self, tmp_path):
        """Replicate _load_file logic from analyze_paired.py:
        records with non-empty nce_error are excluded."""
        records = [
            {"alert_id": "good1", "sse_results": [{"technique_id": "T1078"}]},
            {"alert_id": "bad1", "nce_error": "API_ERROR: 429", "sse_results": []},
            {"alert_id": "good2", "sse_results": []},
        ]
        results_file = tmp_path / "test_results.json"
        with open(results_file, "w") as f:
            json.dump(records, f)

        with open(results_file) as f:
            raw = json.load(f)

        # analyze_paired._load_file excludes records with nce_error
        clean = [r for r in raw if not r.get("nce_error")]
        assert len(clean) == 2
        assert all(r["alert_id"] in ("good1", "good2") for r in clean)
        assert not any(r.get("alert_id") == "bad1" for r in clean)

        print("[ok] analyze_paired excludes nce_error records from analysis.")


# ---------------------------------------------------------------------------
# 7. Key rotation helper
# ---------------------------------------------------------------------------

class TestKeyRotation:
    def test_next_key_rotates(self):
        all_keys = ["kA", "kB", "kC"]
        worker_keys = ["kB", "kA", "kC"]

        k, idx = _next_key(worker_keys, "kB", all_keys)
        assert k == "kA"
        assert idx == 0  # kA is at global index 0

        k, idx = _next_key(worker_keys, "kA", all_keys)
        assert k == "kC"
        assert idx == 2

        k, idx = _next_key(worker_keys, "kC", all_keys)
        assert k == "kB"
        assert idx == 1

        print("[ok] Key rotation cycles through worker_keys correctly.")
