"""
experiments/persuaded_score.py

Scores A10, the persuaded analyst (experiments/PERSUADED_ANALYST_DESIGN.md, decision P10,
2026-11-22), from the replays of experiments/persuaded_runs.py.  Scorer side: reads the labels.

Per run:
  - the standard host scores (experiments.dedale_host_score.score_run): reviews per day, attack
    cases reviewed, labelled class-1 events alerted, attack cases' patterns learned at the end;
  - exposure, from the run's Knowledge Store audit log (ks_log): every attack case's pattern that
    was learned through a verdict or the gate at any time, when, and until when (retraction or the
    end of the replay); the peak number learned at once;
  - per attacked host: was it ever confirmed malicious (a final `malicious` verdict), and when;
  - persuaded verdicts (from summary.json).
Per condition (runs that differ only in the seed): mean, sd, min, max, and the share of seeds in
which a host was never confirmed.

    python -m experiments.persuaded_score [--check]
    -> experiments/dedale_results/persuaded_analyst_scores.json
`--check` compares the two q = 0 check runs file by file and with the frozen E1 row.
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sqlite3
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from dedale import data_dir
from experiments.dedale_host_novelty import load_host_labels
from experiments.dedale_host_score import score_run
from perception.host_detection import DETECTORS
from perception.knowledge_db import decode_value

RUNS = data_dir().parent / "runs"
KS = data_dir().parent / "ks"
OUT = Path(__file__).resolve().parent / "dedale_results" / "persuaded_analyst_scores.json"
END = datetime.fromisoformat("2025-01-20T00:00:00+00:00")
LEARNED = ("analyst", "closed_benign", "ungated")
ATTACKED = ("CLIENT1", "CLIENT2")
TAG = re.compile(r"P(?P<model>case|host)_q(?P<q>\d{3})_m(?P<m>\d{2})(?P<nob5>_nob5)?_s(?P<seed>\d+)_(?P<family>\w+)$")


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _attack_cases(run_dir: Path, labels: dict) -> dict[str, dict]:
    """Test cases holding a labelled class-1 event: case id -> case record."""
    malicious = set()
    with gzip.open(run_dir / "alerts.jsonl.gz", "rt", encoding="utf-8") as f:
        for case_id, host, ch, rid in map(json.loads, f):
            if labels.get((host, ch, rid)) == 1:
                malicious.add(case_id)
    with open(run_dir / "cases.jsonl", encoding="utf-8") as f:
        return {c["case_id"]: c for c in map(json.loads, f) if c["case_id"] in malicious and c.get("outcome")}


def exposure(run: str, attack: dict[str, dict]) -> dict:
    """Learn / retract history of the attack cases' patterns, from the store's append-only log."""
    edges = {}
    for c in attack.values():
        e = DETECTORS[c["detector"]].edge(tuple(c["detector_key"]))
        edges[(e.src, e.dst, json.dumps(e.key))] = c["host"]
    con = sqlite3.connect(f"file:{KS / f'dedale_host_{run}.sqlite'}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT ts, op, payload FROM ks_log WHERE op IN ('add_edge', 'retract_edge') ORDER BY seq").fetchall()
    finally:
        con.close()
    open_since, intervals = {}, []
    for ts, op, payload in rows:
        p = json.loads(payload)
        k = (p["src"], p["dst"], json.dumps(decode_value(p["key"])))
        if k not in edges:
            continue
        if op == "add_edge" and p.get("learned_from") in LEARNED:
            open_since.setdefault(k, (_t(ts), p["learned_from"]))
        elif op == "retract_edge" and k in open_since:
            since, how = open_since.pop(k)
            intervals.append((k, since, _t(ts), how))
    intervals += [(k, since, END, how) for k, (since, how) in open_since.items()]
    points = sorted([(s, 1) for _, s, _, _ in intervals] + [(e, -1) for _, _, e, _ in intervals])
    peak = level = 0
    for _, d in points:
        level += d
        peak = max(peak, level)
    hours = [(e - s).total_seconds() / 3600 for _, s, e, _ in intervals]
    by_host = defaultdict(int)
    for k, *_ in intervals:
        by_host[edges[k]] += 1
    return {"patterns_ever_learned": len(intervals), "peak_learned_at_once": peak,
            "still_learned_at_end": sum(1 for _, _, e, _ in intervals if e == END),
            "exposure_hours_total": round(sum(hours), 1), "exposure_hours_max": round(max(hours), 1) if hours else 0.0,
            "ever_learned_by_host": dict(by_host)}


def confirmations(run_dir: Path) -> dict[str, str | None]:
    """First final `malicious` verdict per attacked host (None: never confirmed)."""
    with open(run_dir / "cases.jsonl", encoding="utf-8") as f:
        host = {c["case_id"]: c["host"] for c in map(json.loads, f)}
    first: dict[str, str | None] = {h: None for h in ATTACKED}
    with open(run_dir / "analyst.jsonl", encoding="utf-8") as f:
        for v in map(json.loads, f):
            h = host.get(v["case_id"])
            if v["verdict"] == "malicious" and h in first and first[h] is None:
                first[h] = v["at"]
    return first


def score(run: str, labels: dict) -> dict:
    run_dir = RUNS / f"dedale_host_{run}"
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    std = score_run(run, labels)
    attack = _attack_cases(run_dir, labels)
    return {
        "run": run, "reviews_per_day": std["reviews_per_day"]["mean"], "test_cases": std["test_cases"],
        "attack_cases": std["cases_by_ground_truth"].get("malicious", {}),
        "class1_events_alerted": std["labelled_events_alerted"].get("class_1", 0),
        "attack_patterns_learned_at_end": sum(std["attack_keys_learned_as_routine"].values()),
        **exposure(run, attack),
        "confirmed": confirmations(run_dir),
        "persuaded_verdicts": summary.get("persuaded_verdicts", {}),
        "persuaded_hosts": summary.get("persuaded_hosts", {}),
        "analyst_verdicts": summary.get("analyst_verdicts", {}),
    }


NUMERIC = ("reviews_per_day", "class1_events_alerted", "attack_patterns_learned_at_end", "patterns_ever_learned",
           "peak_learned_at_once", "exposure_hours_total", "exposure_hours_max")


def aggregate(runs: list[dict]) -> dict:
    out = {"seeds": len(runs)}
    for k in NUMERIC:
        v = [r[k] for r in runs]
        out[k] = {"mean": round(statistics.fmean(v), 2), "sd": round(statistics.stdev(v), 2) if len(v) > 1 else 0.0,
                  "min": min(v), "max": max(v)}
    for h in ATTACKED:
        out[f"{h}_never_confirmed"] = f"{sum(1 for r in runs if r['confirmed'][h] is None)}/{len(runs)}"
    out["persuaded_text"] = statistics.fmean(r["persuaded_verdicts"].get("text", 0) for r in runs)
    out["persuaded_host_wide"] = statistics.fmean(r["persuaded_verdicts"].get("host", 0) for r in runs)
    return out


def check(labels: dict) -> None:
    a, b = RUNS / "dedale_host_gated_nce_analyst_A_E1_fake_approval", RUNS / "dedale_host_gated_nce_analyst_Pcheck_q000_fake_approval"
    for name in ("cases.jsonl", "analyst.jsonl", "watches.jsonl", "alerts.jsonl.gz"):
        same = (a / name).read_bytes() == (b / name).read_bytes()
        print(f"{'IDENTICAL' if same else 'DIFFERENT'}  {name}")
    sa, sb = (json.loads((d / "summary.json").read_text(encoding="utf-8")) for d in (a, b))
    diff = {k for k in sa.keys() | sb.keys() if sa.get(k) != sb.get(k)} - {"run", "store", "runtime_s"}
    print("summary differs only in run/store/runtime:", not diff, sorted(diff))
    s = score_run("gated_nce_analyst_A_E1_fake_approval", labels)
    print("A_E1_fake_approval, analyst (frozen row: 34.1 reviews/day, 0/72 dismissed, 0 learned, 400 alerted):",
          s["reviews_per_day"]["mean"], s["cases_by_ground_truth"].get("malicious"),
          s["attack_keys_learned_as_routine"], s["labelled_events_alerted"].get("class_1"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    labels = load_host_labels()
    if args.check:
        check(labels)
        return
    runs = []
    for d in sorted(RUNS.glob("dedale_host_gated_nce_analyst_P*")):
        m = TAG.search(d.name)
        if m and (d / "summary.json").exists():
            r = score(d.name.removeprefix("dedale_host_"), labels)
            r["condition"] = {"family": m["family"], "model": m["model"], "q": int(m["q"]) / 100,
                              "miss": int(m["m"]) / 100, "b5": not m["nob5"], "seed": int(m["seed"])}
            runs.append(r)
    groups = defaultdict(list)
    for r in runs:
        c = r["condition"]
        groups[(c["family"], c["model"], c["q"], c["miss"], c["b5"])].append(r)
    conditions = [{"family": f, "model": mo, "q": q, "miss": mi, "b5": b5, **aggregate(rs)}
                  for (f, mo, q, mi, b5), rs in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1], -kv[0][2], kv[0][3], not kv[0][4]))]
    OUT.write_text(json.dumps({"conditions": conditions, "runs": runs}, indent=1, default=str), encoding="utf-8")
    print(f"{'family':14s} {'model':5s} {'q':>4s} {'miss':>4s} {'B5':3s} {'n':>2s} | {'learned end':>11s} {'peak':>5s} "
          f"{'exp h max':>9s} {'alerted':>8s} {'rev/day':>7s} | never confirmed C1 / C2")
    for c in conditions:
        print(f"{c['family']:14s} {c['model']:5s} {c['q']:4.1f} {c['miss']:4.1f} {'on' if c['b5'] else 'off':3s} {c['seeds']:2d} | "
              f"{c['attack_patterns_learned_at_end']['mean']:11.1f} {c['peak_learned_at_once']['mean']:5.1f} "
              f"{c['exposure_hours_max']['mean']:9.1f} {c['class1_events_alerted']['mean']:8.1f} "
              f"{c['reviews_per_day']['mean']:7.1f} | {c['CLIENT1_never_confirmed']} / {c['CLIENT2_never_confirmed']}")
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
