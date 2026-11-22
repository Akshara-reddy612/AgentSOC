"""
experiments/flood_eval.py

Checklist A3 (flooding, 2026-11-23): where the attack's cases land in the review queue when the attacker floods it
(experiments/dedale_flood.py). Each day's REVIEW cases are ordered as experiments/dedale_queue_eval.py orders them
(review_service.priority with all factors, "v2"; and oldest first, "fifo"), at the end of the day. An analyst team
that reviews K cases a day reviews the top K. Labels are read here only.

    python -m experiments.flood_eval   -> prints; writes experiments/dedale_results/flood_scores.json
"""
from __future__ import annotations

import bisect
import gzip
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from dedale import data_dir
from experiments.dedale_host_novelty import load_host_labels
from experiments.dedale_host_score import CLIENT_STEPS
from perception.case_store import CaseStore
from perception.review_service import PEER_WINDOW, priority

RUNS = data_dir().parent / "runs"
OUT = Path(__file__).resolve().parent / "dedale_results" / "flood_scores.json"
FLOODS = {"none": "gated_A3_flood0", "5 / hour": "gated_A3_flood5", "50 / hour": "gated_A3_flood50"}
CAPACITY = (25, 50, 100, 200)


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def score(run: str, labels: dict) -> dict:
    d = RUNS / f"dedale_host_{run}"
    malicious, flood_cases = set(), set()
    with gzip.open(d / "alerts.jsonl.gz", "rt", encoding="utf-8") as f:
        for case_id, host, ch, rid in map(json.loads, f):
            if labels.get((host, ch, rid)) == 1:
                malicious.add(case_id)
            elif isinstance(rid, int) and rid <= -1_000_000:
                flood_cases.add(case_id)
    store = CaseStore(d / "cases.sqlite")
    cases = [c for c in store.cases(limit=10**7) if c["review_status"] != "none"]
    opened_by_host = defaultdict(list)
    for c in cases:
        opened_by_host[c["host"]].append(_t(c["opened"]))
    for v in opened_by_host.values():
        v.sort()

    def peers(c: dict) -> int:          # = review_service.host_peers(c, cases), in O(log n)
        times, t = opened_by_host[c["host"]], _t(c["opened"])
        return bisect.bisect_right(times, t) - bisect.bisect_left(times, t - PEER_WINDOW) - 1

    by_day = defaultdict(list)
    for c in cases:
        by_day[c["opened"][:10]].append(c)
    rank = {}                           # case id -> (order, rank in its day, queue length)
    queue = {}
    for day, day_cases in sorted(by_day.items()):
        end = datetime.fromisoformat(day + "T23:59:59+00:00")
        pts = {c["case_id"]: priority(c, store.decision(c["case_id"]), store.actions(c["case_id"]), end, peers(c))[0]
               for c in day_cases}
        v2 = sorted(day_cases, key=lambda c: (-pts[c["case_id"]], c["opened"]))
        fifo = sorted(day_cases, key=lambda c: c["opened"])
        queue[day] = {"cases": len(day_cases), "flood": sum(c["case_id"] in flood_cases for c in day_cases),
                      "attack": sum(c["case_id"] in malicious for c in day_cases)}
        for name, order in (("v2", v2), ("fifo", fifo)):
            for i, c in enumerate(order):
                if c["case_id"] in malicious:
                    rank[(name, c["case_id"])] = i + 1
    attack = [c for c in cases if c["case_id"] in malicious]
    out = {"review_cases": len(cases), "attack_cases": len(attack), "flood_cases": len(flood_cases), "days": queue}
    for name in ("v2", "fifo"):
        ranks = [rank[(name, c["case_id"])] for c in attack]
        out[name] = {"attack_cases_in_top_k": {k: sum(r <= k for r in ranks) for k in CAPACITY},
                     "median_rank": sorted(ranks)[len(ranks) // 2] if ranks else None}
        steps = {}
        for step, t, host in CLIENT_STEPS:     # is one of the step's attack cases within the day's top K?
            best = min((rank[(name, c["case_id"])] for c in attack if c["host"] == host
                        and t - timedelta(minutes=10) <= _t(c["opened"]) <= t + timedelta(hours=24)), default=None)
            steps[step] = {"best_rank": best, **{f"top_{k}": best is not None and best <= k for k in CAPACITY}}
        out[name]["steps"] = steps
    store.close()
    return out


def main() -> None:
    labels = load_host_labels()
    out = {name: {"run": run, **score(run, labels)} for name, run in FLOODS.items()
           if (RUNS / f"dedale_host_{run}" / "cases.sqlite").exists()}
    for name, r in out.items():
        for order in ("v2", "fifo"):
            o = r[order]
            print(f"flood {name:9s} {order:4s} review cases {r['review_cases']:6} | attack cases in top K/day "
                  f"{o['attack_cases_in_top_k']} of {r['attack_cases']} | median rank {o['median_rank']} | steps "
                  f"in top 50: {sum(s['top_50'] for s in o['steps'].values())}/4, best ranks "
                  f"{[s['best_rank'] for s in o['steps'].values()]}")
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
