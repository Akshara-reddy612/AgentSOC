"""
experiments/a8_runs.py

Checklist A8 (2026-11-22): low-and-slow poisoning, offline replays (no API call, NCE off). Design:
experiments/A8_LOW_AND_SLOW_DESIGN.md. Baselines without the attacker are the frozen runs (F_frozen, F_gated, F_d4,
F_d4_nob5).

    python -m experiments.a8_runs [--workers 7]   -> D:/agentsoc_data/runs/dedale_host_*_A8_*
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANALYST = ["--mode", "gated", "--analyst", "oracle"]
ALL = ["--plant-detectors", "lineage", "exec_file_write", "pipe", "powershell"]
JOBS = {
    "A8_test_gated": ["--mode", "gated", "--plant", "test"],
    "A8_test_d4": [*ANALYST, "--plant", "test"],
    "A8_test_d4_nob5": [*ANALYST, "--plant", "test", "--no-unlearn"],
    "A8_test_all_d4": [*ANALYST, "--plant", "test", *ALL],
    "A8_train_frozen": ["--mode", "frozen", "--plant", "train"],
    "A8_train_d4": [*ANALYST, "--plant", "train"],
    "A8_train_all_d4": [*ANALYST, "--plant", "train", *ALL],
}


def run(tag: str) -> tuple[str, int]:
    with open(ROOT / "logs" / f"replay_{tag}.txt", "w", encoding="utf-8") as out:
        rc = subprocess.call([sys.executable, "-m", "experiments.dedale_host_replay", *JOBS[tag], "--tag", tag,
                              "--overwrite"], cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
    return tag, rc


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=7)
    args = ap.parse_args()
    with ThreadPoolExecutor(args.workers) as ex:
        for tag, rc in ex.map(run, JOBS):
            print(f"{tag}: rc={rc}", flush=True)


if __name__ == "__main__":
    main()
