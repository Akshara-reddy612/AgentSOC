"""
experiments/a7_runs.py

Checklist A7 (2026-11-28; design experiments/A7_MEMSTREAM_DESIGN.md): the MemStream scoring passes, in parallel,
one thread each.  β grid: the reference grid (<= 10) admits only a few percent of records on this data (a pilot of
50,000 records scored 2-114, median 53, against the initial memory), so the grid spans the observed scale.  Both
initialisations run over the whole grid: the reference code's first N records turned out to be the first minutes
of the training weeks and nearly identical (autoencoder loss 5e-5), so the uniform sample is the fairer baseline.

    python -m experiments.a7_runs [--init first sample] [--workers 6]   -> <data>/runs/a7_memstream/*.npz
    (a pass whose .json exists is skipped; logs in logs/a7_<tag>.txt)
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from experiments.memstream_eval import OUT_DIR

ROOT = Path(__file__).resolve().parent.parent
BETAS = (0.3, 1, 3, 10, 30, 100)


def run(job: tuple[float, str, str | None]) -> tuple[str, int | str]:
    beta, init, plant = job
    tag = f"b{beta:g}_{init}" + (f"_{plant}" if plant else "")
    if (OUT_DIR / f"{tag}.json").exists():
        return tag, "skipped (done)"
    env = {**os.environ, "OMP_NUM_THREADS": "1", "MKL_NUM_THREADS": "1", "HF_HUB_OFFLINE": "1"}
    with open(ROOT / "logs" / f"a7_{tag}.txt", "w", encoding="utf-8") as out:
        rc = subprocess.call([sys.executable, "-m", "experiments.memstream_eval", "score", "--beta", str(beta),
                              "--init", init, *(["--plant", plant] if plant else []), "--tag", tag],
                             cwd=ROOT, env=env, stdout=out, stderr=subprocess.STDOUT)
    return tag, rc


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--init", nargs="+", default=["first", "sample"], choices=["first", "sample"])
    ap.add_argument("--betas", nargs="+", type=float, default=list(BETAS))
    ap.add_argument("--plant", default=None, choices=["test", "slow"])
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()
    jobs = [(b, i, args.plant) for i in args.init for b in args.betas]
    with ThreadPoolExecutor(args.workers) as ex:
        for tag, rc in ex.map(run, jobs):
            print(f"{tag}: rc={rc}", flush=True)


if __name__ == "__main__":
    main()
