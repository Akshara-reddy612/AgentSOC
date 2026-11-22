"""
experiments/a8_mitigation_score.py

Checklist A8 mitigation (2026-11-23): score cross-host unlearning (experiments/a8_mitigation_runs.py) beside the
per-host B5 runs, plus the default-scope checks against the frozen F_d4 run (byte comparison of cases and alerts).
Offline.

    python -m experiments.a8_mitigation_score   -> prints; writes experiments/dedale_results/a8_mitigation_scores.json
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

from dedale import data_dir
from experiments.dedale_host_novelty import load_host_labels
from experiments.tier1_score import _host

RUNS = data_dir().parent / "runs"
OUT = Path(__file__).resolve().parent / "dedale_results" / "a8_mitigation_scores.json"
ROWS = [  # (label, B5 on the confirmed host only, cross-host)
    ("test-period plants, analyst 4 h", "gated_analyst_A8_test_d4", "gated_analyst_A8x_test_d4"),
    ("test-period plants incl. PowerShell keys", "gated_analyst_A8_test_all_d4", "gated_analyst_A8x_test_all_d4"),
    ("training-week plants, analyst 4 h", "gated_analyst_A8_train_d4", "gated_analyst_A8x_train_d4"),
    ("no attacker, analyst always right", "gated_analyst_F_d4", "gated_analyst_A8x_d4"),
    ("no attacker, analyst misses 20%", "gated_analyst_F_m20", "gated_analyst_A8x_m20"),
    ("no attacker, 5% false alarms", "gated_analyst_F_fa5", "gated_analyst_A8x_fa5"),
]
CHECKS = ("gated_analyst_A8x_check_d4", "gated_analyst_A8x_check_d4_nocs")


def _same(a: str, b: str) -> bool:
    da, db = RUNS / f"dedale_host_{a}", RUNS / f"dedale_host_{b}"
    return ((da / "cases.jsonl").read_bytes() == (db / "cases.jsonl").read_bytes()
            and gzip.decompress((da / "alerts.jsonl.gz").read_bytes()) == gzip.decompress((db / "alerts.jsonl.gz").read_bytes()))


def main() -> None:
    labels = load_host_labels()
    out = {"default_scope_identical_to_F_d4": {c: _same(c, "gated_analyst_F_d4") for c in CHECKS}, "rows": {}}
    for label, host, xh in ROWS:
        out["rows"][label] = {"host": {"run": host, **_host(host, labels)}, "all": {"run": xh, **_host(xh, labels)}}
    print(out["default_scope_identical_to_F_d4"])
    for label, r in out["rows"].items():
        h, x = r["host"], r["all"]
        print(f"{label:42s} cases {h['attack_cases_raised']:3} -> {x['attack_cases_raised']:3} | events "
              f"{h['class1_events_alerted']:3} -> {x['class1_events_alerted']:3} | reviews/day {h['reviews_per_day']} -> "
              f"{x['reviews_per_day']} | TTD {x['time_to_detect_min']}")
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
