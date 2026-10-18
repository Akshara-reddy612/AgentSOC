"""
experiments/freeze_dedale.py

M1 freeze (PROJECT_PLAN.md, 2026-10-18): re-run every DEDALE condition behind
the paper's claims C2-C5 on the final code, then score them.  No API call:
NCE runs use the cached hypotheses only (`--nce cache`; a cache miss is
recorded and the case goes to review unreasoned).

    python -m experiments.freeze_dedale [--workers 6] [--rerun]
    -> experiments/dedale_results/final_host_scores.json, final_network_scores.json
       (replay outputs under <data root>/runs/dedale_*_F_*, logs in runs/freeze_logs/)

Conditions (tag -> replay arguments).  "B5" = unlearn on confirmed compromise
(decision B5 a, default on); "_nob5" runs switch it off for the ablation.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dedale import data_dir

ORACLE = ["--analyst", "oracle", "--case-store"]
HOST = {  # C2-C5 on host logs
    "F_static": ["--mode", "static"],
    "F_frozen": ["--mode", "frozen"],
    "F_gated": ["--mode", "gated"],
    "F_ungated": ["--mode", "ungated"],
    "F_d4": ["--mode", "gated", *ORACLE],
    "F_d4_nob5": ["--mode", "gated", *ORACLE, "--no-unlearn"],
    "F_d1": ["--mode", "gated", *ORACLE, "--analyst-delay", "1"],
    "F_d24": ["--mode", "gated", *ORACLE, "--analyst-delay", "24"],
    "F_d72": ["--mode", "gated", *ORACLE, "--analyst-delay", "72"],
    "F_m5": ["--mode", "gated", *ORACLE, "--analyst-miss", "0.05"],
    "F_m5_nob5": ["--mode", "gated", *ORACLE, "--analyst-miss", "0.05", "--no-unlearn"],
    "F_m20": ["--mode", "gated", *ORACLE, "--analyst-miss", "0.2"],
    "F_m20_nob5": ["--mode", "gated", *ORACLE, "--analyst-miss", "0.2", "--no-unlearn"],
    "F_fa5": ["--mode", "gated", *ORACLE, "--analyst-false-alarm", "0.05"],
    "F_fa5_nob5": ["--mode", "gated", *ORACLE, "--analyst-false-alarm", "0.05", "--no-unlearn"],
    "F_nce": ["--mode", "gated", "--nce", "cache"],
    "F_nce_closed": ["--mode", "gated", "--nce", "cache", "--closed-world"],
    "F_nce_d4": ["--mode", "gated", "--nce", "cache", *ORACLE],
}
NETWORK = {  # C2, C5 on network alerts
    "F_static": ["--mode", "static"],
    "F_frozen": ["--mode", "frozen"],
    "F_gated": ["--mode", "gated"],
    "F_ungated": ["--mode", "ungated"],
    "F_noact": ["--mode", "gated", "--unreasoned", "no_actionable"],
    "F_d4": ["--mode", "gated", *ORACLE],
    "F_d4_nob5": ["--mode", "gated", *ORACLE, "--no-unlearn"],
    "F_d1": ["--mode", "gated", *ORACLE, "--analyst-delay", "1"],
    "F_d24": ["--mode", "gated", *ORACLE, "--analyst-delay", "24"],
    "F_d72": ["--mode", "gated", *ORACLE, "--analyst-delay", "72"],
    "F_fa5": ["--mode", "gated", *ORACLE, "--analyst-false-alarm", "0.05"],
}


def run_name(kind: str, tag: str, args: list[str]) -> str:
    """The run name the replay scripts derive from their arguments."""
    mode = args[args.index("--mode") + 1]
    oracle = "--analyst" in args
    if kind == "host":
        return mode + ("_nce" if "--nce" in args else "") + ("_analyst" if oracle else "") + f"_{tag}"
    noact = "--unreasoned" in args and args[args.index("--unreasoned") + 1] == "no_actionable"
    return mode + ("_noact" if noact else "") + ("_analyst" if oracle else "") + f"_{tag}"


def jobs() -> list[tuple[str, str, list[str], str]]:
    out = [("host", t, a, f"dedale_host_{run_name('host', t, a)}") for t, a in HOST.items()]
    out += [("network", t, a, f"dedale_{run_name('network', t, a)}") for t, a in NETWORK.items()]
    return out


def _run(job, runs_dir: Path, logs: Path, rerun: bool) -> tuple[str, float, int]:
    kind, tag, args, dirname = job
    if not rerun and (runs_dir / dirname / "summary.json").exists():
        return dirname, 0.0, 0
    module = "experiments.dedale_host_replay" if kind == "host" else "experiments.dedale_replay"
    env = dict(os.environ, HF_HUB_OFFLINE="1", PYTHONHASHSEED="0")
    t0 = time.perf_counter()
    with open(logs / f"{dirname}.log", "w", encoding="utf-8") as log:
        rc = subprocess.run([sys.executable, "-m", module, *args, "--tag", tag, "--overwrite"],
                            stdout=log, stderr=subprocess.STDOUT, env=env).returncode
    return dirname, time.perf_counter() - t0, rc


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--rerun", action="store_true", help="re-run conditions that already have results")
    args = ap.parse_args()
    runs_dir = data_dir().parent / "runs"
    logs = runs_dir / "freeze_logs"
    logs.mkdir(parents=True, exist_ok=True)
    todo = jobs()
    failed = []
    with ThreadPoolExecutor(args.workers) as pool:
        for dirname, secs, rc in pool.map(lambda j: _run(j, runs_dir, logs, args.rerun), todo):
            print(f"{dirname:45s} {'skipped (exists)' if secs == 0 and rc == 0 else f'{secs:7.1f} s  rc={rc}'}",
                  flush=True)
            if rc:
                failed.append(dirname)
    if failed:
        sys.exit(f"failed: {failed} (see {logs})")
    env = dict(os.environ, HF_HUB_OFFLINE="1")
    host_runs = [run_name("host", t, a) for t, a in HOST.items()]
    net_runs = [run_name("network", t, a) for t, a in NETWORK.items()]
    subprocess.run([sys.executable, "-m", "experiments.dedale_host_score", "--runs", *host_runs,
                    "--out", "final_host_scores.json"], env=env, check=True)
    subprocess.run([sys.executable, "-m", "experiments.dedale_score", "--runs", *net_runs,
                    "--out", "final_network_scores.json"], env=env, check=True)


if __name__ == "__main__":
    main()
