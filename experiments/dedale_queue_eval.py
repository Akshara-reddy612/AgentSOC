"""
experiments/dedale_queue_eval.py

Review-queue order on DEDALE (analyst review loop, 2026-10-11): for each test
day, the REVIEW cases opened that day are ordered as the review service would
order them at the end of the day, and the scorer looks up where the cases with
labelled malicious events land.  Labels are read here only (invariant I4).

Orders compared on the same case store:
  v2   - review_service.priority with all factors (incl. other targets named by
         the hypotheses and other cases on the same host in 24 h);
  v1   - the same without those two factors (the first version);
  fifo - oldest first.
Caveat: the two v2 factors were chosen after looking at this dataset (in-sample).

    python -m experiments.dedale_queue_eval --run gated_nce_q2
    -> experiments/dedale_results/queue_order.json
"""
from __future__ import annotations

import argparse
import gzip
import json
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from dedale import data_dir
from experiments.dedale_host_novelty import load_host_labels
from perception.case_store import CaseStore
from perception.review_service import host_peers, priority

RESULTS = Path(__file__).resolve().parent / "dedale_results"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, help="host replay run with a case store, e.g. gated_nce_q2")
    args = ap.parse_args()
    run_dir = data_dir().parent / "runs" / f"dedale_host_{args.run}"
    labels = load_host_labels()
    malicious = set()
    with gzip.open(run_dir / "alerts.jsonl.gz", "rt", encoding="utf-8") as f:
        for case_id, host, ch, rid in map(json.loads, f):
            if labels.get((host, ch, rid)) == 1:
                malicious.add(case_id)
    store = CaseStore(run_dir / "cases.sqlite")
    cases = [c for c in store.cases(limit=10**6) if c["review_status"] != "none"]
    by_day = defaultdict(list)
    for c in cases:
        by_day[c["opened"][:10]].append(c)
    ranks = {k: [] for k in ("v2", "v1", "fifo")}
    days = []
    for day, day_cases in sorted(by_day.items()):
        end = datetime.fromisoformat(day + "T23:59:59+00:00")
        rows = []
        for c in day_cases:
            d, acts = store.decision(c["case_id"]), store.actions(c["case_id"])
            rows.append((c, priority(c, dict(d, other_targets=[]), acts, end, 0)[0],
                         priority(c, d, acts, end, host_peers(c, cases))[0]))
        orders = {"v2": [r[0]["case_id"] for r in sorted(rows, key=lambda r: (-r[2], r[0]["opened"]))],
                  "v1": [r[0]["case_id"] for r in sorted(rows, key=lambda r: (-r[1], r[0]["opened"]))],
                  "fifo": [r[0]["case_id"] for r in sorted(rows, key=lambda r: r[0]["opened"])]}
        bad = [c["case_id"] for c in day_cases if c["case_id"] in malicious]
        day_ranks = {k: sorted(o.index(c) + 1 for c in bad) for k, o in orders.items()}
        for k, o in orders.items():
            ranks[k] += [(o.index(c), len(o)) for c in bad]
        days.append({"day": day, "queue": len(day_cases), "malicious": len(bad), "ranks": day_ranks})
    summary = {k: {"mean_percentile_rank": round(statistics.mean(i / n for i, n in v), 3),
                   "in_top_10_of_day": sum(i < 10 for i, _ in v), "malicious_cases": len(v)}
               for k, v in ranks.items()}
    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / "queue_order.json"
    out.write_text(json.dumps({"run": args.run, "summary": summary, "days": days}, indent=1), encoding="utf-8")
    for k, s in summary.items():
        print(f"{k:5s} mean percentile rank {s['mean_percentile_rank']:.2f} | in top 10 of their day "
              f"{s['in_top_10_of_day']}/{s['malicious_cases']}")
    print(f"-> {out}")


if __name__ == "__main__":
    main()
