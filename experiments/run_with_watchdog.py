"""
experiments/run_with_watchdog.py

Supervisor that launches run_paired_clean_eval.py as a subprocess,
monitors the checkpoint file's modification time, and restarts if
no new alert is written for 4 minutes. Caps restarts at 5.

Usage:
    python -m experiments.run_with_watchdog
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_JSON = PROJECT_ROOT / "experiments" / "paired_clean_results.json"
STATUS_FILE = PROJECT_ROOT / "experiments" / "WATCHDOG_STATUS.txt"

STALL_TIMEOUT_S = 240  # 4 minutes
MAX_RESTARTS = 5
POLL_INTERVAL_S = 15


def _ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _log(msg: str) -> None:
    line = f"[{_ts()}] {msg}"
    print(line, flush=True)
    with open(STATUS_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _result_count() -> int:
    """Read the current count of results from the checkpoint file."""
    try:
        import json
        with open(RESULTS_JSON, encoding="utf-8") as f:
            return len(json.load(f))
    except Exception:
        return 0


def _last_modified() -> float:
    """Return mtime of the results file, or 0 if not exists."""
    try:
        return os.path.getmtime(RESULTS_JSON)
    except OSError:
        return 0.0


def main() -> None:
    python = sys.executable
    cmd = [python, "-m", "experiments.run_paired_clean_eval"]

    restarts = 0
    _log(f"Watchdog started. Max restarts={MAX_RESTARTS}, stall timeout={STALL_TIMEOUT_S}s")

    while restarts <= MAX_RESTARTS:
        count_before = _result_count()
        _log(f"Launching eval subprocess (restart #{restarts}). Current results: {count_before}/320")

        proc = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        last_mtime = _last_modified()
        last_check = time.time()

        try:
            while True:
                # Check if process exited
                ret = proc.poll()
                if ret is not None:
                    # Process finished
                    remaining = proc.stdout.read() if proc.stdout else ""
                    if remaining:
                        for line in remaining.splitlines():
                            print(f"  [eval] {line}", flush=True)
                    count_after = _result_count()
                    if count_after >= 320:
                        _log(f"Eval completed successfully: {count_after}/320 results. Exit code {ret}")
                        return
                    elif ret == 0:
                        # Exit 0 without a full checkpoint is NOT success (2026-10-11,
                        # same fix as run_with_watchdog_B_parallel.py) — restart it.
                        _log(f"Eval exited with code 0 but only {count_after}/320 "
                             f"results - treating as failure.")
                        break
                    else:
                        _log(f"Eval crashed with exit code {ret}. Results: {count_after}/320")
                        break  # will restart

                # Drain stdout non-blocking
                if proc.stdout:
                    import select
                    # On Windows, can't use select on pipes. Just read available.
                    try:
                        while True:
                            line = proc.stdout.readline()
                            if not line:
                                break
                            print(f"  [eval] {line.rstrip()}", flush=True)
                    except Exception:
                        pass

                # Check stall
                current_mtime = _last_modified()
                now = time.time()

                if current_mtime > last_mtime:
                    last_mtime = current_mtime
                    last_check = now
                elif now - last_check > STALL_TIMEOUT_S:
                    count_now = _result_count()
                    _log(f"STALL DETECTED: no checkpoint update for {STALL_TIMEOUT_S}s. "
                         f"Results: {count_now}/320. Killing subprocess.")
                    proc.kill()
                    proc.wait(timeout=10)
                    break

                time.sleep(POLL_INTERVAL_S)

        except KeyboardInterrupt:
            _log("KeyboardInterrupt received. Killing subprocess.")
            proc.kill()
            proc.wait(timeout=10)
            return

        restarts += 1
        if restarts > MAX_RESTARTS:
            _log(f"MAX RESTARTS ({MAX_RESTARTS}) EXCEEDED. Stopping.")
            return

        _log(f"Waiting 10s before restart #{restarts}...")
        time.sleep(10)

    _log("Watchdog finished.")


if __name__ == "__main__":
    main()
