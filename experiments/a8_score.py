"""
experiments/a8_score.py

Checklist A8 (2026-11-22): score the low-and-slow runs (experiments/a8_runs.py) beside their no-attacker baselines,
with the host scorer of experiments/tier1_score.py, plus what the planting cost the attacker (its harmless runs that
were reviewed). Offline.

    python -m experiments.a8_score   -> prints; writes experiments/dedale_results/a8_scores.json
"""
from __future__ import annotations

import gzip
import json
from collections import Counter
from pathlib import Path

from dedale import data_dir
from experiments.dedale_host_novelty import load_host_labels
from experiments.tier1_score import _host

RUNS = data_dir().parent / "runs"
OUT = Path(__file__).resolve().parent / "dedale_results" / "a8_scores.json"
ROWS = [  # (label, run, baseline run)
    ("test period, no analyst", "gated_A8_test_gated", "gated_F_gated"),
    ("test period, analyst 4 h, B5 on", "gated_analyst_A8_test_d4", "gated_analyst_F_d4"),
    ("test period, analyst 4 h, B5 off", "gated_analyst_A8_test_d4_nob5", "gated_analyst_F_d4_nob5"),
    ("test period, analyst, B5 on, PowerShell keys too", "gated_analyst_A8_test_all_d4", "gated_analyst_F_d4"),
    ("training weeks, no analyst (frozen)", "frozen_A8_train_frozen", "frozen_F_frozen"),
    ("training weeks, analyst 4 h, B5 on", "gated_analyst_A8_train_d4", "gated_analyst_F_d4"),
    ("training weeks, analyst, B5 on, PowerShell keys too", "gated_analyst_A8_train_all_d4", "gated_analyst_F_d4"),
]


def planting_cost(run: str) -> dict:
    """The attacker's planted events: how many, how many alerted, and the outcomes of the cases they opened."""
    d = RUNS / f"dedale_host_{run}"
    planted = sum(1 for _ in open(d / "plants.jsonl", encoding="utf-8"))
    cases, alerted = set(), 0
    with gzip.open(d / "alerts.jsonl.gz", "rt", encoding="utf-8") as f:
        for case_id, _host_, _ch, rid in map(json.loads, f):
            if isinstance(rid, int) and rid < 0:
                cases.add(case_id)
                alerted += 1
    outcomes = Counter()
    with open(d / "cases.jsonl", encoding="utf-8") as f:
        for c in map(json.loads, f):
            if c["case_id"] in cases:
                outcomes[c.get("outcome") or "training"] += 1
    return {"planted_events": planted, "planted_alerted": alerted, "planted_cases": dict(outcomes)}


def main() -> None:
    labels = load_host_labels()
    out = {}
    for label, run, base in ROWS:
        if not (RUNS / f"dedale_host_{run}" / "summary.json").exists():
            continue
        out[label] = {"run": run, **_host(run, labels), **planting_cost(run), "baseline": {"run": base, **_host(base, labels)}}
    for label, r in out.items():
        b = r["baseline"]
        print(f"{label:52s} attack cases {r['attack_cases_raised']:3} (base {b['attack_cases_raised']:3}) | events "
              f"{r['class1_events_alerted']:3} ({b['class1_events_alerted']:3}) | learned {r['attack_cases_learned']:3} "
              f"| reviews/day {r['reviews_per_day']} ({b['reviews_per_day']}) | TTD {r['time_to_detect_min']} "
              f"| plants alerted {r['planted_alerted']}/{r['planted_events']} {r['planted_cases']}")
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
