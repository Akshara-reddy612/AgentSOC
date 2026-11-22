"""
experiments/event_fpr.py

Event-level false-positive rate for the frozen DEDALE host run (paper revision, checklist A9, 2026-11-22). Offline.

  negatives  = test-period host events (from TRAINING_END) that carry no class-1 label
  false pos. = negatives that raised an alert in the run (alerts.jsonl.gz lists every alerted event)
  FPR        = false positives / negatives

    python -m experiments.event_fpr [--run frozen_F_frozen]  -> prints; writes experiments/dedale_results/event_fpr.json
"""
from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

from dedale import data_dir
from experiments.dedale_host_novelty import load_host_labels
from experiments.dedale_host_replay import EVENTS, TRAINING_END, _t

RESULTS = Path(__file__).resolve().parent / "dedale_results"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="frozen_F_frozen")
    args = ap.parse_args()
    labels = load_host_labels()                                   # (host, source, record id) -> class
    alerted = set()
    with gzip.open(data_dir().parent / "runs" / f"dedale_host_{args.run}" / "alerts.jsonl.gz", "rt", encoding="utf-8") as f:
        for line in f:
            _, host, source, rid = json.loads(line)
            alerted.add((host, source, int(rid)))
    n_events = n_neg = 0
    fp = set()                                                    # distinct: an event can repeat across hour files
    for path in sorted(EVENTS.glob("*.jsonl.gz")):
        if _t(path.name.split(".")[0] + ":00:00Z") < TRAINING_END:
            continue
        with gzip.open(path, "rt", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                key = (e.get("host"), e.get("ch"), int(e.get("rid", -1)))
                n_events += 1
                if labels.get(key) == 1:
                    continue
                n_neg += 1
                if key in alerted:
                    fp.add(key)
    out = {"run": args.run, "test_events": n_events, "negatives": n_neg, "false_positive_events": len(fp),
           "fpr": len(fp) / n_neg if n_neg else None, "alerted_events": len(alerted),
           "alerted_class1": sum(labels.get(k) == 1 for k in alerted)}
    print(json.dumps(out, indent=1))
    (RESULTS / "event_fpr.json").write_text(json.dumps(out, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
