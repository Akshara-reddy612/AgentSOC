"""
experiments/persuaded_runs.py

A10, the persuaded analyst (experiments/PERSUADED_ANALYST_DESIGN.md, decision P10,
2026-11-22): runs the design's grid of DEDALE host replays offline (recorded LLM
answers only, no API call) and scores them.

    python -m experiments.persuaded_runs [--workers 8] [--only-check] [--rerun]
    -> runs under <data root>/runs/dedale_host_gated_nce_analyst_P*_..., logs in runs/persuaded_logs/
    -> experiments/dedale_results/persuaded_analyst_scores.json (python -m experiments.persuaded_score)

Every run: gated learning, NCE from E1's recorded answers for the family, asymmetric
trust, case store, the oracle analyst after 4 h, plus the persuasion options.  Jobs are
ordered so the decisive conditions (q = 1.0) finish first.  `--only-check` runs the
q = 0 check: the frozen condition A_E1_fake_approval (analyst) through the default path
and through the persuasion path with q = 0; their outputs must be identical.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from dedale import data_dir

BASE = ["--mode", "gated", "--nce", "cache", "--analyst", "oracle", "--case-store", "--llm-authority", "escalate"]
SEEDS = range(10)


def _job(family: str, model: str, q: float, m: float, b5: bool, seed: int) -> tuple[str, list[str]]:
    tag = f"P{model}_q{int(q * 100):03d}_m{int(m * 100):02d}{'' if b5 else '_nob5'}_s{seed}_{family}"
    args = [*BASE, "--inject", family, "--analyst-persuaded", str(q), "--persuasion", model, "--analyst-seed", str(seed)]
    if m:
        args += ["--analyst-miss", str(m)]
    if not b5:
        args.append("--no-unlearn")
    return tag, args


def grid() -> list[tuple[str, list[str]]]:
    """The design's conditions, decisive ones first."""
    jobs = []
    for b5 in (True, False):                                      # 1. q = 1.0, both models, every family
        for model in ("host", "case"):
            for family in ("fake_approval", "suppress", "steer"):
                jobs.append(_job(family, model, 1.0, 0.0, b5, 0))
    for model in ("host", "case"):                                # 2. stress: q = 1.0 + 20% base miss
        for b5 in (True, False):
            jobs += [_job("fake_approval", model, 1.0, 0.2, b5, s) for s in SEEDS]
    for q in (0.5, 0.2):                                          # 3. the q sweep with seeds
        for model in ("host", "case"):
            for b5 in (True, False):
                jobs += [_job("fake_approval", model, q, 0.0, b5, s) for s in SEEDS]
    return jobs


def checks() -> list[tuple[str, list[str]]]:
    return [("A_E1_fake_approval", [*BASE, "--inject", "fake_approval"]),
            ("Pcheck_q000_fake_approval", [*BASE, "--inject", "fake_approval", "--analyst-persuaded", "0"])]


def _run(job, logs, rerun: bool) -> tuple[str, float, int]:
    tag, args = job
    name = f"dedale_host_gated_nce_analyst_{tag}"
    if not rerun and (data_dir().parent / "runs" / name / "summary.json").exists():
        return name, 0.0, 0
    env = dict(os.environ, HF_HUB_OFFLINE="1", PYTHONHASHSEED="0")
    t0 = time.perf_counter()
    with open(logs / f"{name}.log", "w", encoding="utf-8") as log:
        rc = subprocess.run([sys.executable, "-m", "experiments.dedale_host_replay", *args, "--tag", tag, "--overwrite"],
                            stdout=log, stderr=subprocess.STDOUT, env=env).returncode
    return name, time.perf_counter() - t0, rc


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--only-check", action="store_true")
    ap.add_argument("--rerun", action="store_true")
    args = ap.parse_args()
    logs = data_dir().parent / "runs" / "persuaded_logs"
    logs.mkdir(parents=True, exist_ok=True)
    todo = checks() if args.only_check else grid()
    print(f"{len(todo)} replays, {args.workers} workers", flush=True)
    failed = []
    with ThreadPoolExecutor(args.workers) as pool:
        for name, secs, rc in pool.map(lambda j: _run(j, logs, args.rerun), todo):
            print(f"{time.strftime('%H:%M:%S')} {name:75s} {'skipped' if secs == 0 and rc == 0 else f'{secs:6.0f} s rc={rc}'}",
                  flush=True)
            if rc:
                failed.append(name)
    if failed:
        sys.exit(f"failed: {failed} (see {logs})")


if __name__ == "__main__":
    main()
