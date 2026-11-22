"""
experiments/detection_metrics.py

Paper revision, Tier 1 (decision P10, 2026-11-22; review item A9): standard detection metrics for the
DEDALE host conditions, computed only from the frozen score file
experiments/dedale_results/final_host_scores.json (no replay, no API call).

Per condition, at case level (a case = what an analyst reviews):
  - precision: reviewed attack cases / all reviewed cases (cases holding a labelled class-1 event are
    attack cases; class-2-only cases are counted with the benign ones as not-attack);
  - recall: attack cases reviewed / attack cases raised;
  - benign cases reviewed per day (the false-alarm load) and the share of benign cases dismissed
    without review;
  - time to detect each attack step: minutes from the step's start to the first reviewed case on its host.

    python -m experiments.detection_metrics      (prints a Markdown table; build_results includes it)
"""
from __future__ import annotations

import json
from pathlib import Path

FILE = Path(__file__).resolve().parent / "dedale_results" / "final_host_scores.json"
CONDITIONS = [("static (nothing learned)", "static_F_static"), ("frozen", "frozen_F_frozen"),
              ("gated", "gated_F_gated"), ("ungated", "ungated_F_ungated"),
              ("gated + analyst 4 h", "gated_analyst_F_d4"),
              ("gated + NCE (acting rule)", "gated_nce_F_nce"), ("gated + NCE (asymmetric trust)", "gated_nce_A_nce"),
              ("gated + NCE + analyst (asymmetric trust)", "gated_nce_analyst_A_nce_d4")]
TEST_DAYS = 14


def metrics(r: dict) -> dict:
    by = r["cases_by_ground_truth"]
    attack = by.get("malicious", {})
    other = {}
    for tier in ("benign", "related"):
        for k, v in by.get(tier, {}).items():
            other[k] = other.get(k, 0) + v
    tp, fp = attack.get("REVIEW", 0), other.get("REVIEW", 0)
    benign_total = sum(other.values())
    return {"precision": tp / (tp + fp) if tp + fp else None, "recall": tp / sum(attack.values()) if attack else None,
            "attack_reviewed": f"{tp}/{sum(attack.values())}", "benign_reviews_per_day": round(fp / TEST_DAYS, 1),
            "benign_dismissed": f"{benign_total - fp}/{benign_total}",
            "time_to_detect_min": [s["first_after_min"] for s in r["attack_steps"]]}


def table() -> list[str]:
    runs = json.loads(FILE.read_text(encoding="utf-8"))["runs"]
    lines = ["| Condition | Precision (cases) | Attack cases reviewed / raised (ungated raises only 38: it learned the rest) | Benign reviews / day | Benign cases dismissed unreviewed | "
             "Time to detect per attack step (min) |", "|:--|--:|--:|--:|--:|:--|"]
    for label, run in CONDITIONS:
        if run not in runs:
            continue
        m = metrics(runs[run])
        p = f"{m['precision']:.1%}" if m["precision"] is not None else "-"
        ttd = " / ".join("-" if x is None else f"{x:g}" for x in m["time_to_detect_min"])
        lines.append(f"| {label} | {p} | {m['attack_reviewed']} | {m['benign_reviews_per_day']} | {m['benign_dismissed']} | {ttd} |")
    return lines


if __name__ == "__main__":
    print("\n".join(table()))
