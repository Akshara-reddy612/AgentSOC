"""
experiments/test_watchdog.py

Manual (slow, Windows-only) check of the watchdog's stall-kill and restart
behaviour.  Not collected as a pytest test: run with

    python -m experiments.test_watchdog

Uses environment overrides to supervise experiments.fake_harness against a
temporary checkpoint.  It never edits source files and never touches the
real paired_clean_results_B.json.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run_case(name: str, extra_env: dict, workdir: Path) -> None:
    print(f"\n=== CASE: {name} ===", flush=True)
    results = workdir / f"{name}_results.json"
    results.write_text("[]", encoding="utf-8")
    old = time.time() - 1000  # stale checkpoint at launch must not trigger an immediate kill
    os.utime(results, (old, old))
    env = {
        **os.environ,
        "WATCHDOG_HARNESS_MODULE": "experiments.fake_harness",
        "WATCHDOG_RESULTS_JSON": str(results),
        "WATCHDOG_STATUS_FILE": str(workdir / f"{name}_status.txt"),
        "WATCHDOG_MAX_RESTARTS": "1",
        "STALL_TIMEOUT_S": "5",
        "POLL_INTERVAL_S": "2",
        **extra_env,
    }
    proc = subprocess.run(
        [sys.executable, "-m", "experiments.run_with_watchdog_B_parallel"],
        cwd=str(PROJECT_ROOT), env=env, capture_output=True, text=True, timeout=180,
    )
    print(proc.stdout, flush=True)


def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        workdir = Path(d)
        _run_case("hang_with_child", {"FAKE_HARNESS_MODE": "hang_with_child"}, workdir)
        _run_case("exit_0_incomplete", {"FAKE_HARNESS_MODE": "normal"}, workdir)
        _run_case("exit_3", {"FAKE_HARNESS_MODE": "exit_3"}, workdir)


if __name__ == "__main__":
    main()
