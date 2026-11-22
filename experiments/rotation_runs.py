"""
experiments/rotation_runs.py

Checklist A11 (2026-11-22): rotate the training window. Offline replays (no API call). For each of the two
single-week training windows, the three conditions whose result the paper leans on:
  frozen               the clean-week store, no learning in testing, NCE off, no analyst
  gated + analyst m20  the analyst misses 20% of attacks, B5 (unlearning) on
  same, B5 off
The "both weeks" rows are the frozen runs already scored (frozen_F_frozen, gated_analyst_F_m20[_nob5]).

    python -m experiments.rotation_runs [--workers 6]   -> D:/agentsoc_data/runs/dedale_host_*_rot_*
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WINDOWS = ("week1", "week2")
CONDITIONS = {
    "frozen": ["--mode", "frozen"],
    "m20": ["--mode", "gated", "--analyst", "oracle", "--analyst-miss", "0.2", "--analyst-seed", "0"],
    "m20_nob5": ["--mode", "gated", "--analyst", "oracle", "--analyst-miss", "0.2", "--analyst-seed", "0", "--no-unlearn"],
}


def jobs() -> list[tuple[str, list[str]]]:
    return [(f"rot_{w}_{c}", [*args, "--train-window", w, "--tag", f"rot_{w}_{c}", "--overwrite"])
            for w in WINDOWS for c, args in CONDITIONS.items()]


def run(job: tuple[str, list[str]]) -> tuple[str, int]:
    tag, args = job
    log = ROOT / "logs" / f"replay_{tag}.txt"
    with open(log, "w", encoding="utf-8") as out:
        rc = subprocess.call([sys.executable, "-m", "experiments.dedale_host_replay", *args], cwd=ROOT, stdout=out,
                             stderr=subprocess.STDOUT)
    return tag, rc


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()
    with ThreadPoolExecutor(args.workers) as ex:
        for tag, rc in ex.map(run, jobs()):
            print(f"{tag}: rc={rc}", flush=True)


if __name__ == "__main__":
    main()
