"""
experiments/tier1_runs.py

Paper revision, Tier 1 (decision P10; experiments/TIER1_EXPERIMENTS_DESIGN.md, 2026-11-22): the offline
replays for A7 (frequency-threshold memory baseline), A8 (gate-delay and unlearning-lookback sweeps) and
A11 (analyst mistakes over seeds).  Recorded LLM answers only, no API call.

    python -m experiments.tier1_runs [--workers 6] [--rerun]
    -> runs under <data root>/runs/dedale[_host]_*_T1*, logs in runs/tier1_logs/

The first two jobs are checks: the frozen conditions F_gated (host) and F_noact (network) replayed with
every new option at its default; their outputs must equal the frozen runs of 2026-10-18 byte for byte
(experiments.tier1_score --check).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from dedale import data_dir

ORACLE = ["--analyst", "oracle", "--case-store"]
NCE = ["--nce", "cache"]


def jobs() -> list[tuple[str, str, list[str]]]:
    """(kind, run directory name, replay arguments incl. --tag), checks first."""
    out = [("host", "T1check_gated", ["--mode", "gated"]),
           ("network", "T1check_noact", ["--mode", "gated", "--unreasoned", "no_actionable"])]
    for k in (2, 5, 10):                                                    # A7
        for mode in ("frozen", "gated"):
            out.append(("host", f"T1_k{k}", ["--mode", mode, "--min-train-count", str(k)]))
    for h in (1, 72, 168):                                                  # A8 gate delay
        out.append(("host", f"T1_gd{h}", ["--mode", "gated", *NCE, "--gate-delay", str(h)]))
        out.append(("network", f"T1_gd{h}", ["--mode", "gated", "--unreasoned", "no_actionable", "--gate-delay", str(h)]))
    for name, extra in (("m5", ["--analyst-miss", "0.05"]), ("m20", ["--analyst-miss", "0.2"]),
                        ("fa5", ["--analyst-false-alarm", "0.05"])):        # A11
        for b5 in (True, False):
            for s in range(1, 10):
                out.append(("host", f"T1_{name}{'' if b5 else '_nob5'}_s{s}",
                            ["--mode", "gated", *ORACLE, *extra, "--analyst-seed", str(s), *([] if b5 else ["--no-unlearn"])]))
    for d in (1, 3, 14):                                                    # A8 lookback
        for s in range(10):
            out.append(("host", f"T1_lb{d}_s{s}", ["--mode", "gated", *ORACLE, "--analyst-miss", "0.2",
                                                    "--analyst-seed", str(s), "--unlearn-lookback", str(d)]))
    return [(kind, tag, [*args, "--tag", tag]) for kind, tag, args in out]


def run_dir(kind: str, args: list[str]) -> str:
    mode = args[args.index("--mode") + 1]
    tag = args[args.index("--tag") + 1]
    if kind == "host":
        return "dedale_host_" + mode + ("_nce" if "--nce" in args else "") + ("_analyst" if "--analyst" in args else "") + f"_{tag}"
    noact = "--unreasoned" in args and args[args.index("--unreasoned") + 1] == "no_actionable"
    return "dedale_" + mode + ("_noact" if noact else "") + ("_analyst" if "--analyst" in args else "") + f"_{tag}"


def _run(job, logs, rerun: bool):
    kind, _, args = job
    name = run_dir(kind, args)
    if not rerun and (data_dir().parent / "runs" / name / "summary.json").exists():
        return name, 0.0, 0
    module = "experiments.dedale_host_replay" if kind == "host" else "experiments.dedale_replay"
    env = dict(os.environ, HF_HUB_OFFLINE="1", PYTHONHASHSEED="0")
    t0 = time.perf_counter()
    with open(logs / f"{name}.log", "w", encoding="utf-8") as log:
        rc = subprocess.run([sys.executable, "-m", module, *args, "--overwrite"], stdout=log,
                            stderr=subprocess.STDOUT, env=env).returncode
    return name, time.perf_counter() - t0, rc


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--rerun", action="store_true")
    args = ap.parse_args()
    logs = data_dir().parent / "runs" / "tier1_logs"
    logs.mkdir(parents=True, exist_ok=True)
    todo = jobs()
    print(f"{len(todo)} replays, {args.workers} workers", flush=True)
    failed = []
    with ThreadPoolExecutor(args.workers) as pool:
        for name, secs, rc in pool.map(lambda j: _run(j, logs, args.rerun), todo):
            print(f"{time.strftime('%H:%M:%S')} {name:60s} {'skipped' if secs == 0 and rc == 0 else f'{secs:6.0f} s rc={rc}'}",
                  flush=True)
            if rc:
                failed.append(name)
    if failed:
        sys.exit(f"failed: {failed} (see {logs})")


if __name__ == "__main__":
    main()
