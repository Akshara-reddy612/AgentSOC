"""
experiments/run_with_watchdog_B.py

Supervisor for run_paired_clean_eval_B.py.

Stall detection polls the checkpoint file's mtime from the main loop
(no stdout reads that could block). On stall: kills the whole process
tree with `taskkill /PID <pid> /T /F`, verifies no python eval process
remains, then relaunches.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_JSON = PROJECT_ROOT / "experiments" / "paired_clean_results_B.json"
STATUS_FILE  = PROJECT_ROOT / "experiments" / "WATCHDOG_STATUS_B.txt"

STALL_TIMEOUT_S = 240   # seconds without a new checkpoint write
MAX_RESTARTS    = 5
POLL_INTERVAL_S = 15    # how often to check mtime


def _ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _log(msg: str) -> None:
    line = f"[{_ts()}] {msg}"
    print(line, flush=True)
    with open(STATUS_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _result_count() -> int:
    try:
        with open(RESULTS_JSON, encoding="utf-8") as f:
            return len(json.load(f))
    except Exception:
        return 0


def _mtime() -> float:
    try:
        return os.path.getmtime(RESULTS_JSON)
    except OSError:
        return 0.0


def _kill_tree(pid: int) -> None:
    """Kill an entire Windows process tree using taskkill."""
    _log(f"Running: taskkill /PID {pid} /T /F")
    r = subprocess.run(
        ["taskkill", "/PID", str(pid), "/T", "/F"],
        capture_output=True, text=True,
    )
    _log(f"taskkill stdout: {r.stdout.strip()!r}")
    _log(f"taskkill stderr: {r.stderr.strip()!r}")
    # Brief wait then confirm
    time.sleep(3)
    remaining = subprocess.run(
        ["tasklist", "/FI", f"IMAGENAME eq python.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True,
    ).stdout.strip()
    _log(f"python.exe processes after kill: {remaining!r}")


def main() -> None:
    python = sys.executable
    cmd = [python, "-m", "experiments.run_paired_clean_eval_B"]

    restarts = 0
    _log(f"Watchdog started. Max restarts={MAX_RESTARTS}, stall_timeout={STALL_TIMEOUT_S}s, "
         f"poll={POLL_INTERVAL_S}s")

    while restarts <= MAX_RESTARTS:
        count_before = _result_count()
        _log(f"Launching eval subprocess (attempt #{restarts}). "
             f"Checkpoint: {count_before}/320")

        # stdout/stderr inherited so they stream to the terminal.
        # We do NOT pipe them — that is what caused readline() to block.
        proc = subprocess.Popen(cmd, cwd=str(PROJECT_ROOT))

        last_mtime  = _mtime()
        last_update = time.time()

        try:
            while True:
                time.sleep(POLL_INTERVAL_S)

                # 1. Has the process exited?
                ret = proc.poll()
                if ret is not None:
                    count_after = _result_count()
                    if count_after >= 320:
                        _log(f"Eval completed: {count_after}/320. Exit code {ret}.")
                        return
                    elif ret == 0:
                        _log(f"Eval exited cleanly with {count_after}/320.")
                        return
                    else:
                        _log(f"Eval crashed (exit {ret}). "
                             f"Results so far: {count_after}/320.")
                        break   # fall through to restart logic

                # 2. Stall check — mtime only, no stdout touching.
                m = _mtime()
                now = time.time()
                if m > last_mtime:
                    last_mtime  = m
                    last_update = now
                elif now - last_update > STALL_TIMEOUT_S:
                    count_now = _result_count()
                    elapsed = int(now - last_update)
                    _log(f"STALL: no checkpoint update for {elapsed}s "
                         f"(limit {STALL_TIMEOUT_S}s). "
                         f"Results: {count_now}/320. Killing tree PID={proc.pid}.")
                    _kill_tree(proc.pid)
                    try:
                        proc.wait(timeout=10)
                    except Exception:
                        pass
                    break   # fall through to restart logic

        except KeyboardInterrupt:
            _log("KeyboardInterrupt — killing tree.")
            _kill_tree(proc.pid)
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
            return

        restarts += 1
        if restarts > MAX_RESTARTS:
            _log(f"MAX RESTARTS ({MAX_RESTARTS}) EXCEEDED. Stopping.")
            return

        _log(f"Waiting 10s before attempt #{restarts}...")
        time.sleep(10)

    _log("Watchdog finished.")


if __name__ == "__main__":
    main()
