"""
experiments/dedale_host_score.py

Phase 2 scorer (2026-10-11): host-replay runs (experiments/dedale_host_replay.py)
against DEDALE's exact host labels (system_logs_labels: malicious events of
CLIENT1 / CLIENT2, class 1 = malicious, class 2 = malicious-related).  Scorer
side only (design invariant I4); also provides the simulated analyst of the
separate --analyst oracle condition.

    python -m experiments.dedale_host_score [--runs static frozen gated ungated gated_analyst]
    -> experiments/dedale_results/phase2_scores.json
"""
from __future__ import annotations

import argparse
import gzip
import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dedale import data_dir
from experiments.dedale_host_novelty import load_host_labels
from perception.host_detection import DETECTORS

UTC = timezone.utc
TEST_START = datetime(2025, 1, 6, tzinfo=UTC)
TEST_DAYS = 14
RESULTS = Path(__file__).resolve().parent / "dedale_results"
# Published timeline (dedale.inria.fr/attack_scenario.html), steps visible on the Windows clients.
CLIENT_STEPS = [
    ("Initial access on client 2 (phishing macro, dropper)", datetime(2025, 1, 6, 10, 0, tzinfo=UTC), "CLIENT2"),
    ("Lateral movement to client 1 (PrintNightmare)", datetime(2025, 1, 8, 15, 0, tzinfo=UTC), "CLIENT1"),
    ("Collection: client 1 to the internal server over SSH", datetime(2025, 1, 10, 11, 0, tzinfo=UTC), "CLIENT1"),
    ("Exfiltration to the attacker", datetime(2025, 1, 11, 11, 0, tzinfo=UTC), "CLIENT1"),
]


class HostOracle:
    """Simulated analyst: a case is malicious if any of its alerts so far is a labelled event."""

    def __init__(self) -> None:
        self.labels = load_host_labels()
        self._malicious: set[str] = set()

    def observe_alert(self, case, alert: dict) -> None:
        if self.labels.get(tuple(alert["event_ref"])):
            self._malicious.add(case.case_id)

    def __call__(self, case, decision, at) -> str:
        return "malicious" if case.case_id in self._malicious else "benign"


def host_oracle() -> HostOracle:
    return HostOracle()


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def score_run(run: str, labels: dict) -> dict:
    run_dir = data_dir().parent / "runs" / f"dedale_host_{run}"
    with open(run_dir / "cases.jsonl", encoding="utf-8") as f:
        cases = {c["case_id"]: c for c in map(json.loads, f)}
    case_classes: dict[str, set[int]] = defaultdict(set)
    alerted_labelled: Counter[int] = Counter()
    with gzip.open(run_dir / "alerts.jsonl.gz", "rt", encoding="utf-8") as f:
        for case_id, host, ch, rid in map(json.loads, f):
            cls = labels.get((host, ch, rid))
            if cls:
                case_classes[case_id].add(cls)
                alerted_labelled[cls] += 1
    test = [c for c in cases.values() if c.get("outcome")]
    per_day: dict[str, Counter] = defaultdict(Counter)
    for c in test:
        per_day[c["opened"][:10]][c["outcome"]] += 1
    reviews = [per_day[(TEST_START + timedelta(days=i)).date().isoformat()]["REVIEW"] for i in range(TEST_DAYS)]

    def tier(c):
        cls = case_classes.get(c["case_id"], set())
        return "malicious" if 1 in cls else "related" if 2 in cls else "benign"

    by_tier = defaultdict(Counter)
    for c in test:
        by_tier[tier(c)][c["outcome"]] += 1
    steps = []
    for name, t, host in CLIENT_STEPS:
        surfaced = sorted((c for c in test if c["host"] == host and tier(c) != "benign"
                           and c["outcome"] in ("REVIEW", "AUTO_APPROVED")
                           and t - timedelta(minutes=10) <= _t(c["opened"]) <= t + timedelta(hours=24)),
                          key=lambda c: c["opened"])
        first = surfaced[0] if surfaced else None
        steps.append({"step": name, "time": t.isoformat(), "host": host, "surfaced_cases": len(surfaced),
                      "first_after_min": round((_t(first["opened"]) - t).total_seconds() / 60, 1) if first else None,
                      "first": ({k: first[k] for k in ("detector", "process_name", "parent_process", "command_line",
                                                       "outcome")} if first else None)})
    learned_bad = Counter()
    con = sqlite3.connect(data_dir().parent / "ks" / f"dedale_host_{run}.sqlite")
    try:
        for c in test:
            if tier(c) == "benign":
                continue
            e = DETECTORS[c["detector"]].edge(tuple(c["detector_key"]))
            row = con.execute("SELECT learned_from FROM edges WHERE src = ? AND dst = ? AND key = ?",
                              (e.src, e.dst, json.dumps(e.key))).fetchone()
            if row:
                learned_bad[row[0]] += 1
    finally:
        con.close()
    verdicts = Counter()
    if (run_dir / "analyst.jsonl").exists():
        with open(run_dir / "analyst.jsonl", encoding="utf-8") as f:
            verdicts.update(json.loads(line)["verdict"] for line in f)
    return {
        "run": run,
        "test_cases": len(test),
        "outcomes": dict(Counter(c["outcome"] for c in test)),
        "reviews_per_day": {"mean": round(sum(reviews) / TEST_DAYS, 1), "max": max(reviews) if reviews else 0,
                            "week_1_mean": round(sum(reviews[:7]) / 7, 1), "week_2_mean": round(sum(reviews[7:]) / 7, 1),
                            "by_day": reviews},
        "cases_by_ground_truth": {k: dict(v) for k, v in by_tier.items()},
        "labelled_events_alerted": {f"class_{k}": v for k, v in sorted(alerted_labelled.items())},
        "attack_steps": steps,
        "attack_keys_learned_as_routine": dict(learned_bad),
        "analyst_verdicts": dict(verdicts),
        "detectors": json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))["detectors"],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", default=["static", "frozen", "gated", "ungated", "gated_analyst"])
    args = ap.parse_args()
    labels = load_host_labels()
    runs = [r for r in args.runs if (data_dir().parent / "runs" / f"dedale_host_{r}" / "cases.jsonl").exists()]
    results = {"labels": len(labels), "runs": {r: score_run(r, labels) for r in runs}}
    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / "phase2_scores.json"
    out.write_text(json.dumps(results, indent=1, default=str), encoding="utf-8")
    for r, s in results["runs"].items():
        rpd = s["reviews_per_day"]
        print(f"{r:14s} cases {s['test_cases']:6d} | reviews/day {rpd['mean']:7.1f} (wk1 {rpd['week_1_mean']}, "
              f"wk2 {rpd['week_2_mean']}) | by truth {s['cases_by_ground_truth']} | labelled alerted "
              f"{s['labelled_events_alerted']} | bad keys learned {s['attack_keys_learned_as_routine']}")
    print(f"-> {out}")


if __name__ == "__main__":
    main()
