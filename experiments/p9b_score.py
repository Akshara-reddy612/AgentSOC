"""
experiments/p9b_score.py

Decision P9 B (2026-11-28): score the corroborated-learning replays (experiments/p9b_runs.py) beside their recorded
baselines, with the host scorer of experiments/tier1_score.py and the planting cost of experiments/a8_score.py.
Offline.

    python -m experiments.p9b_score   -> prints; writes experiments/dedale_results/p9b_scores.json
"""
from __future__ import annotations

import json
from pathlib import Path

from experiments.a8_score import planting_cost
from experiments.dedale_host_novelty import load_host_labels
from experiments.p9b_runs import BASELINES, JOBS, RUNS, run_name
from experiments.tier1_score import _agg, _host

OUT = Path(__file__).resolve().parent / "dedale_results" / "p9b_scores.json"


def _row(run: str, labels: dict) -> dict:
    summ = json.loads((RUNS / f"dedale_host_{run}" / "summary.json").read_text(encoding="utf-8"))
    out = {"run": run, **_host(run, labels),
           "uncorroborated_not_learned": summ.get("uncorroborated_not_learned"),
           "training_patterns_retracted_single_host": summ.get("training_patterns_retracted_single_host")}
    if summ.get("plant"):
        out.update(planting_cost(run))
    return out


def main() -> None:
    labels = load_host_labels()
    jobs, cache = {}, {}

    def score(run):
        if run not in cache:
            cache[run] = _row(run, labels)
        return cache[run]

    for tag in JOBS:
        run = run_name(tag)
        if not (RUNS / f"dedale_host_{run}" / "summary.json").exists():
            continue
        jobs[tag] = {**score(run), "baseline": score(BASELINES[tag])}
    seeds = {}                                         # 20% analyst misses: mean ± sd over the six seeds
    for rule in ("R1", "R1b", "R4"):
        tags = [f"P9B_{rule}_m20_s{s}" for s in range(6)]
        if all(t in jobs for t in tags):
            seeds[rule] = {"rule": _agg([jobs[t] for t in tags]),
                           "baseline": _agg([jobs[t]["baseline"] for t in tags])}
    OUT.write_text(json.dumps({"jobs": jobs, "m20_seeds": seeds}, indent=1), encoding="utf-8")
    for tag, r in jobs.items():
        b = r["baseline"]
        print(f"{tag:22s} attack cases {r['attack_cases_raised']:3} (base {b['attack_cases_raised']:3}) | events "
              f"{r['class1_events_alerted']:3} ({b['class1_events_alerted']:3}) | learned {r['attack_cases_learned']:3} "
              f"({b['attack_cases_learned']:3}) | reviews/day {r['reviews_per_day']} ({b['reviews_per_day']}) "
              f"| not learned {r['uncorroborated_not_learned']}")
    for rule, s in seeds.items():
        print(f"m20 seeds {rule}: reviews/day {s['rule']['reviews_per_day']['mean']} ± {s['rule']['reviews_per_day']['sd']}"
              f" (base {s['baseline']['reviews_per_day']['mean']}); attack cases learned "
              f"{s['rule']['attack_cases_learned']['mean']} (base {s['baseline']['attack_cases_learned']['mean']})")
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
