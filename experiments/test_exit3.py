"""
experiments/test_exit3.py

The watchdog must stop (not restart) when the harness exits with code 3
(corrupt checkpoint).  Runs the real watchdog against experiments.fake_harness
via environment overrides; never edits source files and never touches the
real checkpoint.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_watchdog_stops_on_exit_code_3(tmp_path):
    env = {
        **os.environ,
        "WATCHDOG_HARNESS_MODULE": "experiments.fake_harness",
        "WATCHDOG_RESULTS_JSON": str(tmp_path / "results.json"),
        "WATCHDOG_STATUS_FILE": str(tmp_path / "status.txt"),
        "FAKE_HARNESS_MODE": "exit_3",
        "STALL_TIMEOUT_S": "5",
        "POLL_INTERVAL_S": "1",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "experiments.run_with_watchdog_B_parallel"],
        cwd=str(PROJECT_ROOT), env=env, capture_output=True, text=True, timeout=60,
    )
    assert "exit code 3" in proc.stdout, proc.stdout
    assert "attempt #1" not in proc.stdout, "watchdog restarted after exit code 3"
    # The real checkpoint path must not appear in the log.
    assert "paired_clean_results_B.json" not in proc.stdout
