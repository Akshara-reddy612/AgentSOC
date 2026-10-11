"""
experiments/dedale_zeek_labels.py

Exact network ground truth from DEDALE's labelled Zeek flows (router 1;
zeek_router1.zip -> router1/<interface>/<day>/conn_labeled.csv, semicolon
separated; label 0 benign / 1 attack / 2 attack-related, plus attack step,
MITRE tactic and technique, comments).  Scorer-side only (design invariant I4).

    python -m experiments.dedale_zeek_labels
    -> <data root>/dedale/derived/zeek_router1_attack_flows.jsonl (outside the repo)

Router 1 sits between the company and the internet / DMZ, so these labels
cover outbound, inbound and DMZ traffic, not traffic between internal zones
(router 2).
"""
from __future__ import annotations

import collections
import csv
import io
import json
import zipfile
from pathlib import Path

from dedale import data_dir

ZIP = "zeek_router1.zip"
OUT = Path("derived") / "zeek_router1_attack_flows.jsonl"
KEEP = ("ts", "uid", "ip_src", "port_src", "ip_dst", "port_dst", "proto", "service", "duration",
        "label", "step", "attack_step", "tactic", "technique", "comments")


def attack_flows(path: Path | None = None):
    """Every flow labelled 1 or 2 in router 1's conn_labeled.csv files, with the interface it was seen on."""
    path = path or data_dir() / ZIP
    with zipfile.ZipFile(path) as z:
        for name in sorted(n for n in z.namelist() if n.endswith("conn_labeled.csv")):
            interface = name.split("/")[1]
            with z.open(name) as f:
                for row in csv.DictReader(io.TextIOWrapper(f, encoding="utf-8"), delimiter=";"):
                    if row["label"] not in ("0", ""):
                        yield {"interface": interface, **{k: row[k] for k in KEEP}}


def load_attack_flows() -> list[dict]:
    with open(data_dir() / OUT, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def suricata_matches(flows: list[dict], slack_s: float = 60.0) -> list[tuple[dict, dict]]:
    """(Suricata alert, labelled flow) pairs: same 5-tuple in either direction, alert inside the flow's time."""
    from dedale.suricata import iter_alerts

    index = collections.defaultdict(list)
    for fl in flows:
        if fl["port_src"].isdigit() and fl["port_dst"].isdigit():
            a, b = (fl["ip_src"], int(fl["port_src"])), (fl["ip_dst"], int(fl["port_dst"]))
            index[(a, b, fl["proto"])].append(fl)
            index[(b, a, fl["proto"])].append(fl)
    pairs = []
    for alert in iter_alerts():
        key = ((alert["src_ip"], alert["src_port"]), (alert["dst_ip"], alert["dst_port"]), alert["protocol"].lower())
        for fl in index.get(key, ()):
            start = float(fl["ts"])
            dur = float(fl["duration"]) if fl["duration"] not in ("", "-") else 0.0
            t = _epoch(alert["timestamp"])
            if start - slack_s <= t <= start + dur + slack_s:
                pairs.append((alert, fl))
    return pairs


def first_contact_stats(test_start: float = 1736121600.0) -> dict:
    """
    Outbound flows (internal source -> external destination per the DEDALE
    profile) on router 1: how many (source, destination) pairs per test day
    were never seen in the training weeks, and how many of them carry
    attack-labelled flows.  Measures whether "first contact with a never-seen
    external destination" would be a usable detector on this network.
    """
    from datetime import datetime, timezone

    from dedale.environment import DEDALE_PROFILE

    known: set[tuple[str, str]] = set()
    per_day: dict[str, dict] = collections.defaultdict(lambda: {"new_pairs": set(), "attack_pairs": set()})
    with zipfile.ZipFile(data_dir() / ZIP) as z:
        names = sorted((n for n in z.namelist() if n.endswith("conn_labeled.csv")),
                       key=lambda n: n.split("/")[2].split("_")[1])          # by date
        for name in names:
            with z.open(name) as f:
                for row in csv.DictReader(io.TextIOWrapper(f, encoding="utf-8"), delimiter=";"):
                    src, dst = row["ip_src"], row["ip_dst"]
                    if not (DEDALE_PROFILE.is_internal_address(src) and not DEDALE_PROFILE.is_internal_address(dst)):
                        continue
                    ts = float(row["ts"])
                    pair = (src, dst)
                    if ts < test_start:
                        known.add(pair)
                        continue
                    day = datetime.fromtimestamp(ts, timezone.utc).date().isoformat()
                    if pair not in known:
                        per_day[day]["new_pairs"].add(pair)
                        if row["label"] not in ("0", ""):
                            per_day[day]["attack_pairs"].add(pair)
    seen_in_test: set[tuple[str, str]] = set()
    result = {}
    for day in sorted(per_day):
        first = per_day[day]["new_pairs"] - seen_in_test          # first contact in the test weeks
        seen_in_test |= per_day[day]["new_pairs"]
        result[day] = {"first_contact_pairs": len(first),
                       "attack_pairs_first_contact": sorted(per_day[day]["attack_pairs"] & first)}
    return {"training_pairs": len(known), "per_day": result}


def _epoch(ts: str) -> float:
    from datetime import datetime
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def main() -> None:
    out = data_dir() / OUT
    out.parent.mkdir(parents=True, exist_ok=True)
    steps, techniques, pairs, labels = (collections.Counter() for _ in range(4))
    n = 0
    with open(out, "w", encoding="utf-8") as f:
        for flow in attack_flows():
            f.write(json.dumps(flow) + "\n")
            n += 1
            labels[flow["label"]] += 1
            steps[(flow["attack_step"], flow["tactic"])] += 1
            techniques[flow["technique"]] += 1
            pairs[(flow["ip_src"], flow["ip_dst"], flow["port_dst"], flow["proto"])] += 1
    print(f"{n:,} labelled flows -> {out}")
    print("labels:", dict(labels))
    print("attack steps (step, tactic):", steps.most_common(20))
    print("techniques:", techniques.most_common(15))
    print("top (src, dst, dst port, proto):", pairs.most_common(15))


if __name__ == "__main__":
    main()
