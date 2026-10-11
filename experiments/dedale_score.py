"""
experiments/dedale_score.py

Phase 1 scorer (design step S9, 2026-10-11): ground truth for DEDALE's
Suricata cases and metrics for each replay run (experiments/dedale_replay.py).
This is the only module that reads ground truth (design invariant I4).

Ground truth, two tiers (sources in experiments/DEDALE_DATA_NOTES.md):
  confirmed - a case with a published attacker address as an endpoint
              (172.19.1.1 dropper server, 172.19.2.1 reverse shell,
              172.19.0.2 C2 server);
  probable  - a heuristic join, NOT a label: a case on a host the published
              timeline names as compromised, after its compromise time, whose
              key (signature, source, destination) never occurred in the
              training weeks, with a labelled malicious host event
              (system_logs_labels, class 1+2) on that host within 5 minutes
              of the case's alerts.  DEDALE's network labels (Zeek conn.log)
              are not downloaded.
Known false positives: the three attack-window alerts the timeline rules out.

    python -m experiments.dedale_score [--runs static frozen gated ungated gated_noact]
    -> experiments/dedale_results/phase1_scores.json
"""
from __future__ import annotations

import argparse
import bisect
import io
import json
import sqlite3
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dedale import data_dir

UTC = timezone.utc
ATTACKER = {"172.19.1.1": "dropper server", "172.19.2.1": "reverse shell", "172.19.0.2": "C2 server"}
# Published timeline (dedale.inria.fr/attack_scenario.html); the labels' timestamps confirm it is UTC.
COMPROMISED = {   # address -> (host name in the labels, compromised from, until)
    "172.16.1.3": ("CLIENT2", datetime(2025, 1, 6, 10, 0, tzinfo=UTC), datetime(2025, 1, 13, 12, 0, tzinfo=UTC)),
    "172.16.1.2": ("CLIENT1", datetime(2025, 1, 8, 15, 0, tzinfo=UTC), datetime(2025, 1, 13, 12, 0, tzinfo=UTC)),
    "172.16.0.2": ("internalserver", datetime(2025, 1, 10, 11, 0, tzinfo=UTC), datetime(2025, 1, 11, 12, 0, tzinfo=UTC)),
}
ATTACK_STEPS = [   # (step, time, addresses involved)
    ("Initial access: phishing macro on client 2, dropper download", datetime(2025, 1, 6, 10, 0, tzinfo=UTC),
     {"172.16.1.3"}),
    ("Lateral movement client 2 -> client 1 (PrintNightmare)", datetime(2025, 1, 8, 15, 0, tzinfo=UTC),
     {"172.16.1.3", "172.16.1.2"}),
    ("Collection on the internal server (SSH from client 1)", datetime(2025, 1, 10, 11, 0, tzinfo=UTC),
     {"172.16.1.2", "172.16.0.2"}),
    ("Exfiltration to the attacker", datetime(2025, 1, 11, 11, 0, tzinfo=UTC), {"172.16.1.2", "172.16.1.3"}),
]
STEP_WINDOW = (timedelta(minutes=-10), timedelta(hours=2))
KNOWN_FALSE_POSITIVES = [   # (signature fragment, source address)
    ("Suspicious POST with Common Windows Process Names", "172.16.1.15"),
    ("PCRat/Gh0st", "172.16.1.30"),
    ("PCRat/Gh0st", "172.16.1.6"),
]
LABEL_MARGIN = timedelta(minutes=5)
TEST_START = datetime(2025, 1, 6, tzinfo=UTC)
TEST_DAYS = 14
RESULTS = Path(__file__).resolve().parent / "dedale_results"


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_label_times() -> dict[str, list[datetime]]:
    """Malicious host events (class 1+2) per labelled host, sorted."""
    times: dict[str, list[datetime]] = defaultdict(list)
    with zipfile.ZipFile(data_dir() / "system_logs_labels.zip") as z:
        for name in ("system_labels/clients_1_and_2/malicious_events_class_1_and_2.jsonl",
                     "system_labels/internal_server/malicious_events_class_1_and_2.jsonl"):
            with z.open(name) as f:
                for line in io.TextIOWrapper(f, encoding="utf-8"):
                    r = json.loads(line)
                    times[r["agent"]["hostname"]].append(_t(r["@timestamp"]))
    return {h: sorted(ts) for h, ts in times.items()}


def _labelled_near(times: list[datetime], start: datetime, end: datetime) -> bool:
    i = bisect.bisect_left(times, start - LABEL_MARGIN)
    return i < len(times) and times[i] <= end + LABEL_MARGIN


def load_cases(run: str) -> list[dict]:
    path = data_dir().parent / "runs" / f"dedale_{run}" / "cases.jsonl"
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def ground_truth(cases: list[dict], label_times: dict[str, list[datetime]]) -> dict[str, str]:
    """case_id -> "confirmed" / "probable" for the test-window cases that are attack-related."""
    training_keys = {(c["signature_id"], c["src_ip"], c["dst_ip"]) for c in cases if c["training"]}
    tiers = {}
    for c in cases:
        if c["training"]:
            continue
        ends = (c["src_ip"], c["dst_ip"])
        if any(a in ATTACKER for a in ends):
            tiers[c["case_id"]] = "confirmed"
            continue
        if (c["signature_id"], c["src_ip"], c["dst_ip"]) in training_keys:
            continue
        opened, last = _t(c["opened"]), _t(c["last_seen"])
        for a in ends:
            if a in COMPROMISED:
                host, start, end = COMPROMISED[a]
                if start <= opened <= end and _labelled_near(label_times.get(host, []), opened, last):
                    tiers[c["case_id"]] = "probable"
    return tiers


def _nearest_label_s(c: dict, label_times: dict[str, list[datetime]]) -> float | None:
    """Seconds between the case's alerts and the nearest labelled malicious event on a compromised endpoint."""
    best = None
    opened, last = _t(c["opened"]), _t(c["last_seen"])
    for a in (c["src_ip"], c["dst_ip"]):
        if a not in COMPROMISED:
            continue
        ts = label_times.get(COMPROMISED[a][0], [])
        i = bisect.bisect_left(ts, opened)
        for j in (i - 1, i):
            if 0 <= j < len(ts):
                d = 0.0 if opened <= ts[j] <= last else min(abs((ts[j] - opened).total_seconds()),
                                                             abs((ts[j] - last).total_seconds()))
                best = d if best is None else min(best, d)
    return best


def _brief(c: dict) -> dict:
    return {"case_id": c["case_id"], "opened": c["opened"], "signature": c["signature"],
            "flow": f"{c['src_ip']} -> {c['dst_ip']}:{c['dst_port']}", "alerts": c["alert_count"],
            "path": c.get("path"), "outcome": c.get("outcome"), "pipeline_outcome": c.get("pipeline_outcome"),
            "actions": [a for a in c.get("actions", []) if a.get("status") == "AUTO_APPROVED"]}


def learned_patterns(run: str) -> set[tuple[int, str, str]]:
    """(signature id, source node, destination node) of every ALERT_PATTERN edge in the run's store."""
    con = sqlite3.connect(data_dir().parent / "ks" / f"dedale_{run}.sqlite")
    try:
        return {(json.loads(attrs)["signature_id"], src, dst) for src, dst, attrs in
                con.execute("SELECT src, dst, attrs FROM edges WHERE edge_type = 'ALERT_PATTERN'")}
    finally:
        con.close()


def score_run(run: str, tiers: dict[str, str], label_times: dict[str, list[datetime]]) -> dict:
    cases = load_cases(run)
    test = [c for c in cases if not c["training"]]
    outcomes = Counter(c["outcome"] for c in test)
    per_day = defaultdict(Counter)
    for c in test:
        per_day[c["opened"][:10]][c["outcome"]] += 1
    reviews = [per_day[d]["REVIEW"] for d in sorted(per_day)]
    by_id = {c["case_id"]: c for c in test}
    attack = [by_id[cid] for cid in tiers if cid in by_id]

    def is_fp(c):
        return any(frag in c["signature"] and c["src_ip"] == src for frag, src in KNOWN_FALSE_POSITIVES)

    steps = []
    for name, t, addresses in ATTACK_STEPS:
        lo, hi = t + STEP_WINDOW[0], t + STEP_WINDOW[1]
        near = [c for c in test if lo <= _t(c["opened"]) <= hi and {c["src_ip"], c["dst_ip"]} & addresses]
        surfaced = [c for c in near if c["outcome"] in ("REVIEW", "AUTO_APPROVED")]
        steps.append({"step": name, "time": t.isoformat(), "cases_near": len(near),
                      "surfaced": [_brief(c) for c in surfaced]})
    auto = [c for c in test if c["outcome"] == "AUTO_APPROVED"]
    watches = []
    wpath = data_dir().parent / "runs" / f"dedale_{run}" / "watches.jsonl"
    with open(wpath, encoding="utf-8") as f:
        for line in f:
            w = json.loads(line)
            w["target_is_attacker"] = w["target"] in ATTACKER
            watches.append(w)
    return {
        "run": run,
        "test_cases": len(test),
        "outcomes": dict(outcomes),
        "reviews_per_day": {"mean": round(sum(reviews) / TEST_DAYS, 1), "max": max(reviews), "by_day": reviews},
        "low_priority_share": round(outcomes["LOW_PRIORITY"] / len(test), 4),
        "attack_related": [{**_brief(c), "tier": tiers[c["case_id"]],
                            "nearest_label_s": _nearest_label_s(c, label_times)}
                           for c in sorted(attack, key=lambda c: c["opened"])],
        "attack_related_hidden": sum(1 for c in attack if c["outcome"] in ("LOW_PRIORITY", "NO_ACTIONABLE")),
        "attack_steps": steps,
        "known_false_positives": [_brief(c) for c in test if is_fp(c)],
        "auto_approved": {"cases": len(auto),
                          "on_attacker_infrastructure": sum(1 for c in auto if c["dst_ip"] in ATTACKER),
                          "targets": Counter(a["target"] for c in auto for a in c.get("actions", [])
                                             if a.get("status") == "AUTO_APPROVED").most_common()},
        "watches": {"count": len(watches),
                    "would_block_on_attacker": sum(w["would_block"] for w in watches if w["target_is_attacker"]),
                    "would_block_on_benign_targets": sum(w["would_block"] for w in watches
                                                         if not w["target_is_attacker"]),
                    "top_benign": sorted(((w["target"], w["would_block"]) for w in watches if not w["target_is_attacker"]),
                                         key=lambda x: -x[1])[:5]},
        "attack_patterns_learned_as_routine": sorted(
            f"sid {sid} {src} -> {dst}" for sid, src, dst in learned_patterns(run)
            if any(a in dst or a in src for a in ATTACKER)),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", default=["static", "frozen", "gated", "ungated", "gated_noact"])
    ap.add_argument("--explore", action="store_true", help="print the ground-truth case lists of the first run")
    args = ap.parse_args()
    labels = load_label_times()
    tiers = ground_truth(load_cases(args.runs[0]), labels)   # same cases (ids, keys, times) in every run
    if args.explore:
        by_id = {c["case_id"]: c for c in load_cases(args.runs[0])}
        for cid, tier in sorted(tiers.items(), key=lambda kv: by_id[kv[0]]["opened"]):
            c = by_id[cid]
            print(tier, c["opened"][:19], c["src_ip"], "->", f"{c['dst_ip']}:{c['dst_port']}", c["signature"][:70],
                  "| alerts", c["alert_count"], "|", c.get("outcome"), "| nearest label s",
                  _nearest_label_s(c, labels))
        return
    results = {"ground_truth": {"tiers": dict(Counter(tiers.values())), "case_ids": tiers},
               "runs": {run: score_run(run, tiers, labels) for run in args.runs}}
    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / "phase1_scores.json"
    out.write_text(json.dumps(results, indent=1, default=str), encoding="utf-8")
    for run, r in results["runs"].items():
        print(f"{run:12s} reviews/day {r['reviews_per_day']['mean']:6.1f} (max {r['reviews_per_day']['max']:4d}) "
              f"| LOW_PRIORITY {r['low_priority_share']:.1%} | auto {r['auto_approved']['cases']:3d} "
              f"(attacker {r['auto_approved']['on_attacker_infrastructure']}) | attack-related hidden "
              f"{r['attack_related_hidden']}/{len(r['attack_related'])} | would-block benign "
              f"{r['watches']['would_block_on_benign_targets']} attacker {r['watches']['would_block_on_attacker']}")
    print(f"-> {out}")


if __name__ == "__main__":
    main()
