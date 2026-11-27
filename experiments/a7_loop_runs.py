"""
experiments/a7_loop_runs.py

Checklist A7 (2026-11-28; design experiments/A7_MEMSTREAM_DESIGN.md), stages 2-4: MemStream's alerts through the SOC
loop (experiments/memstream_loop.py), scored with the host scorer of experiments/tier1_score.py.  Offline.

    python -m experiments.a7_loop_runs --tag b10_sample [--plant-tags b10_sample_test b10_sample_slow]
        -> experiments/dedale_results/a7_memstream_scores.json

  stage 2  pure MemStream (store in static mode, no analyst): tau bisected so that reviews/day match the gated
           store's (F_gated), at most --steps replays; and tau = the 99.9th percentile of the stream's training scores
  stage 3  the same tau with the A8 plants scored in-stream (score files made with `memstream_eval score --plant`)
  stage 4  the combination (store in frozen mode: a review needs a novel key AND a MemStream anomaly) at the taus that
           call the most normal 50% and 90% of test records normal
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import numpy as np

from experiments.dedale_host_novelty import load_host_labels
from experiments.dedale_host_replay import TRAINING_END
from experiments.memstream_eval import OUT_DIR
from experiments.tier1_score import _host

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "experiments" / "dedale_results" / "a7_memstream_scores.json"
TARGET_RUN = "gated_F_gated"


def replay(tag: str, mode: str, tau: float, name: str, plant: str | None = None) -> str:
    args = [sys.executable, "-m", "experiments.dedale_host_replay", "--mode", mode, "--memstream-scores", tag,
            "--memstream-tau", repr(tau), "--tag", name, "--overwrite", *(["--plant", plant] if plant else [])]
    with open(ROOT / "logs" / f"replay_{name}.txt", "w", encoding="utf-8") as out:
        rc = subprocess.call(args, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
    if rc:
        raise SystemExit(f"replay {name} failed (rc={rc}); see logs/replay_{name}.txt")
    return f"{mode}_{name}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True, help="score file of the chosen beta / init (no plants)")
    ap.add_argument("--plant-tags", nargs="*", default=[])
    ap.add_argument("--steps", type=int, default=5)
    args = ap.parse_args()
    labels = load_host_labels()
    z = np.load(OUT_DIR / f"{args.tag}.npz")
    test = z["t"] >= TRAINING_END.timestamp()
    s_test, s_train = z["score"][test].astype(np.float64), z["score"][~test].astype(np.float64)
    target = _host(TARGET_RUN, labels)["reviews_per_day"]
    out = {"tag": args.tag, "target": {"run": TARGET_RUN, "reviews_per_day": target}, "bisection": []}

    lo, hi = -5.0, np.log10(0.5)                 # log10 of the share of test records alerted
    best = None
    for i in range(args.steps):
        q = (lo + hi) / 2
        tau = float(np.quantile(s_test, 1 - 10 ** q))
        run = replay(args.tag, "static", tau, f"A7_{args.tag}_m{i}")
        r = {"share_alerted": 10 ** q, "tau": tau, **_host(run, labels)}
        out["bisection"].append(r)
        print(f"step {i}: share {10 ** q:.2e} tau {tau:.3f} -> reviews/day {r['reviews_per_day']} "
              f"attack cases {r['attack_cases_raised']} events {r['class1_events_alerted']}", flush=True)
        if best is None or abs(r["reviews_per_day"] - target) < abs(best["reviews_per_day"] - target):
            best = r
        lo, hi = (q, hi) if r["reviews_per_day"] < target else (lo, q)
    out["matched"] = best

    tau_cal = float(np.quantile(s_train, 0.999))
    out["calibrated"] = {"tau": tau_cal, "rule": "99.9th percentile of training scores",
                         **_host(replay(args.tag, "static", tau_cal, f"A7_{args.tag}_cal"), labels)}

    out["plants"] = {}
    for ptag in args.plant_tags:
        meta = json.loads((OUT_DIR / f"{ptag}.json").read_text(encoding="utf-8"))
        pz = np.load(OUT_DIR / f"{ptag}.npz")
        run = replay(ptag, "static", best["tau"], f"A7_{ptag}", plant=meta["plant"])
        out["plants"][ptag] = {"plant": meta["plant"], "tau": best["tau"], **_host(run, labels),
                               "plant_records_admitted": int((pz["admitted"] & (pz["rid"] < 0)).sum()),
                               "plant_records": int((pz["rid"] < 0).sum())}

    out["combination"] = {}
    for normal_share in (0.5, 0.9):
        tau = float(np.quantile(s_test, normal_share))
        out["combination"][str(normal_share)] = {
            "tau": tau, **_host(replay(args.tag, "frozen", tau, f"A7_{args.tag}_c{int(normal_share * 100)}"), labels)}
    out["keyed"] = {name: _host(name, labels) for name in ("frozen_F_frozen", TARGET_RUN)}
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k != "bisection"}, indent=1)[:4000])
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
