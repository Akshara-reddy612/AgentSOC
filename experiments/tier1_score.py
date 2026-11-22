"""
experiments/tier1_score.py

Scores the Tier 1 replays (experiments/TIER1_EXPERIMENTS_DESIGN.md, decision P10, 2026-11-22) of
experiments/tier1_runs.py.  Scorer side: reads the labels.

    python -m experiments.tier1_score [--check]
    -> experiments/dedale_results/tier1_scores.json
`--check`: the two default-behaviour replays must equal the frozen runs of 2026-10-18 file by file.
"""
from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path

from dedale import data_dir
from experiments.dedale_host_novelty import load_host_labels
from experiments.dedale_host_score import score_run as host_score
from experiments.dedale_score import ground_truth, load_cases, load_label_times, score_run as net_score

RUNS = data_dir().parent / "runs"
OUT = Path(__file__).resolve().parent / "dedale_results" / "tier1_scores.json"
TEST_DAYS = 14


def check() -> None:
    for new, old in (("dedale_host_gated_T1check_gated", "dedale_host_gated_F_gated"),
                     ("dedale_gated_noact_T1check_noact", "dedale_gated_noact_F_noact")):
        for name in ("cases.jsonl", "analyst.jsonl", "watches.jsonl", "alerts.jsonl.gz"):
            a, b = RUNS / new / name, RUNS / old / name
            if a.exists() or b.exists():
                print(f"{'IDENTICAL' if a.exists() and b.exists() and a.read_bytes() == b.read_bytes() else 'DIFFERENT'}  {new} / {name}")
        sa, sb = (json.loads((RUNS / d / "summary.json").read_text(encoding="utf-8")) for d in (new, old))
        diff = sorted(k for k in sa.keys() | sb.keys() if sa.get(k) != sb.get(k) and k not in ("run", "store", "runtime_s"))
        print(f"           summary differs only in run/store/runtime: {not diff} {diff}")


def _host(run: str, labels: dict) -> dict:
    s = host_score(run, labels)
    summ = json.loads((RUNS / f"dedale_host_{run}" / "summary.json").read_text(encoding="utf-8"))
    attack = s["cases_by_ground_truth"].get("malicious", {})
    reviewed_attack = attack.get("REVIEW", 0)
    reviewed = sum(v.get("REVIEW", 0) for v in s["cases_by_ground_truth"].values())
    return {"reviews_per_day": s["reviews_per_day"]["mean"], "test_cases": s["test_cases"],
            "attack_cases_raised": sum(attack.values()), "attack_cases_reviewed": reviewed_attack,
            "precision": round(reviewed_attack / reviewed, 4) if reviewed else None,
            "class1_events_alerted": s["labelled_events_alerted"].get("class_1", 0),
            "attack_cases_learned": sum(s["attack_keys_learned_as_routine"].values()),
            "gate_learned_closed_benign": sum(n for k, n in summ["edges_by_type_and_provenance"].items() if k.endswith("|closed_benign")),
            "gate_dropped": summ.get("gate_dropped"),
            "training_patterns_retracted": summ.get("training_patterns_retracted"),
            "time_to_detect_min": [st["first_after_min"] for st in s["attack_steps"]]}


def _net(run: str, tiers: dict, label_times: dict) -> dict:
    s = net_score(run, tiers, label_times)
    summ = json.loads((RUNS / f"dedale_{run}" / "summary.json").read_text(encoding="utf-8"))
    return {"reviews_per_day": s["reviews_per_day"]["mean"],
            "attack_patterns_learned": s.get("attack_patterns_learned_as_routine"),
            "attack_related_hidden": s.get("attack_related_hidden"),
            "gate_learned_closed_benign": {k: n for k, n in summ["edges_by_type_and_provenance"].items() if k.endswith("|closed_benign")},
            "gate_dropped": summ.get("gate_dropped")}


def _agg(rows: list[dict], keys=("reviews_per_day", "attack_cases_learned", "class1_events_alerted", "attack_cases_reviewed")) -> dict:
    out = {"seeds": len(rows)}
    for k in keys:
        v = [r[k] for r in rows]
        out[k] = {"mean": round(statistics.fmean(v), 2), "sd": round(statistics.stdev(v), 2) if len(v) > 1 else 0.0,
                  "min": min(v), "max": max(v), "values": v}
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.check:
        check()
        return
    labels = load_host_labels()
    out: dict = {}
    # A7: frequency-threshold baseline vs the clean-weeks allowlist (frozen K = 1) and the gated store
    out["A7_min_train_count"] = {f"{mode}_k{k}": _host(f"{mode}_T1_k{k}" if k > 1 else f"{mode}_F_{mode}", labels)
                                 for mode in ("frozen", "gated") for k in (1, 2, 5, 10)}
    # A8: gate delay where the gate learns (host NCE acting rule; network with D7 off); 24 h = frozen
    out["A8_gate_delay_host_nce"] = {f"{h}h": _host(f"gated_nce_T1_gd{h}" if h != 24 else "gated_nce_F_nce", labels)
                                     for h in (1, 24, 72, 168)}
    label_times = load_label_times()
    tiers = ground_truth(load_cases("gated_noact_F_noact"), label_times)
    out["A8_gate_delay_network_noact"] = {f"{h}h": _net(f"gated_noact_T1_gd{h}" if h != 24 else "gated_noact_F_noact", tiers, label_times)
                                          for h in (1, 24, 72, 168)}
    # A11: analyst mistakes over seeds (seed 0 = the frozen run)
    a11 = {}
    for name in ("m5", "m20", "fa5"):
        for b5 in (True, False):
            suffix = "" if b5 else "_nob5"
            runs = [f"gated_analyst_F_{name}{suffix}"] + [f"gated_analyst_T1_{name}{suffix}_s{s}" for s in range(1, 6)]
            a11[f"{name}{suffix}"] = _agg([_host(r, labels) for r in runs])
    out["A11_analyst_seeds"] = a11
    # A8: unlearning lookback (analyst misses 20%, B5 on); 7 days = frozen F_m20 + A11 seeds 1-4
    lb = {"7d": a11["m20"]}
    for d in (1, 3, 14):
        lb[f"{d}d"] = _agg([_host(f"gated_analyst_T1_lb{d}_s{s}", labels) for s in range(5)])
    out["A8_unlearn_lookback_m20"] = lb
    OUT.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    print(json.dumps({k: (v if k != "A11_analyst_seeds" and k != "A8_unlearn_lookback_m20" else
                          {c: {m: x["mean"] if isinstance(x, dict) else x for m, x in r.items() if m != "seeds"} for c, r in v.items()})
                      for k, v in out.items()}, indent=1, default=str)[:6000])
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
