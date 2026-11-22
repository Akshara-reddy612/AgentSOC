"""
experiments/rotation_score.py

Checklist A11 (2026-11-22): score the training-window rotation (experiments/rotation_runs.py) beside the frozen
both-weeks runs, with the same host scorer as experiments/tier1_score.py. Offline.

    python -m experiments.rotation_score   -> prints; writes experiments/dedale_results/rotation_scores.json
"""
from __future__ import annotations

import json
from pathlib import Path

from dedale import data_dir
from experiments.dedale_host_novelty import load_host_labels
from experiments.tier1_score import _host

OUT = Path(__file__).resolve().parent / "dedale_results" / "rotation_scores.json"
RUNS = {
    "both": {"frozen": "frozen_F_frozen", "m20": "gated_analyst_F_m20", "m20_nob5": "gated_analyst_F_m20_nob5"},
    **{w: {c: f"{'frozen' if c == 'frozen' else 'gated_analyst'}_rot_{w}_{c}" for c in ("frozen", "m20", "m20_nob5")}
       for w in ("week1", "week2")},
}


def main() -> None:
    labels = load_host_labels()
    out = {}
    for window, conds in RUNS.items():
        out[window] = {}
        for cond, run in conds.items():
            if (data_dir().parent / "runs" / f"dedale_host_{run}" / "summary.json").exists():
                out[window][cond] = {"run": run, **_host(run, labels)}
    for window, conds in out.items():
        for cond, r in conds.items():
            print(f"{window:6s} {cond:9s} reviews/day {r['reviews_per_day']:7} | attack cases {r['attack_cases_raised']:3} "
                  f"| events {r['class1_events_alerted']:3} | attack patterns learned {r['attack_cases_learned']:3} "
                  f"| precision {r['precision']}")
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
