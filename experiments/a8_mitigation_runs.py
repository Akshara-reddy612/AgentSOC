"""
experiments/a8_mitigation_runs.py

Checklist A8 mitigation (2026-11-23): cross-host unlearning (`--unlearn-scope all`, off by default) against the
low-and-slow attacker (experiments/a8_runs.py), and its cost without an attacker. Offline, NCE off. The first job is
a check: the default scope must reproduce the frozen F_d4 run exactly.

    python -m experiments.a8_mitigation_runs [--workers 7]   -> D:/agentsoc_data/runs/dedale_host_*_A8x_*
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANALYST = ["--mode", "gated", "--analyst", "oracle", "--case-store"]   # as the frozen F_* runs
ALL_DET = ["--plant-detectors", "lineage", "exec_file_write", "pipe", "powershell"]
XH = ["--unlearn-scope", "all"]
JOBS = {
    "A8x_check_d4": [*ANALYST],                                   # default scope: must equal F_d4
    "A8x_check_d4_nocs": ["--mode", "gated", "--analyst", "oracle"],   # without a case store (as a8_runs.py)
    "A8x_test_d4": [*ANALYST, "--plant", "test", *XH],
    "A8x_test_all_d4": [*ANALYST, "--plant", "test", *ALL_DET, *XH],
    "A8x_train_d4": [*ANALYST, "--plant", "train", *XH],
    "A8x_d4": [*ANALYST, *XH],                                    # cost: no attacker, perfect analyst
    "A8x_m20": [*ANALYST, "--analyst-miss", "0.2", "--analyst-seed", "0", *XH],
    "A8x_fa5": [*ANALYST, "--analyst-false-alarm", "0.05", "--analyst-seed", "0", *XH],
}


def run(tag: str) -> tuple[str, int]:
    with open(ROOT / "logs" / f"replay_{tag}.txt", "w", encoding="utf-8") as out:
        rc = subprocess.call([sys.executable, "-m", "experiments.dedale_host_replay", *JOBS[tag], "--tag", tag,
                              "--overwrite"], cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
    return tag, rc


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    with ThreadPoolExecutor(args.workers) as ex:
        for tag, rc in ex.map(run, JOBS):
            print(f"{tag}: rc={rc}", flush=True)


if __name__ == "__main__":
    main()
