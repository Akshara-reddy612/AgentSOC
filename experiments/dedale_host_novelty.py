"""
experiments/dedale_host_novelty.py

Phase 2 step P2-3 (2026-10-11): measure candidate Knowledge-Store novelty
detectors on DEDALE's Windows events before building alerts on any of them.
Scorer-side (reads the host labels).

Each detector maps a compact host event (experiments/dedale_extract_winlogbeat.py)
to a key.  Keys seen in the training weeks are "known"; in the test weeks a key
not known (and not seen earlier in the test weeks) is a novelty.  Reported per
detector: distinct benign novelties per test day, and how many labelled
malicious events (class 1 / class 1+2) fall on a novel key.

    python -m experiments.dedale_host_novelty
    -> experiments/dedale_results/phase2_novelty.json
"""
from __future__ import annotations

import collections
import gzip
import io
import json
import re
import zipfile
from pathlib import Path

from dedale import data_dir
from dedale.winlogbeat import channel_short

DERIVED = data_dir() / "derived" / "winlogbeat"
TEST_START = "2025-01-06"
RESULTS = Path(__file__).resolve().parent / "dedale_results"
_DIGITS = re.compile(r"\d+")


def _norm(s: str | None) -> str:
    return (s or "").lower()


def _shape(text: str | None, n: int = 160) -> str:
    """Command / script text with digits blanked (ports, pids, guids vary) and truncated."""
    return _DIGITS.sub("#", (text or "").lower())[:n]


DETECTORS = {
    "lineage": lambda e: (e["host"], _norm(e.get("parent_image")), _norm(e.get("image")))
    if e["ch"] == "sysmon" and e["code"] == 1 else None,
    "image_on_host": lambda e: (e["host"], _norm(e.get("image")))
    if e["ch"] == "sysmon" and e["code"] == 1 else None,
    "image_anywhere": lambda e: _norm(e.get("image"))
    if e["ch"] == "sysmon" and e["code"] == 1 else None,
    "command_shape": lambda e: (e["host"], _norm(e.get("image")), _shape(e.get("cmd")))
    if e["ch"] == "sysmon" and e["code"] == 1 else None,
    "logon": lambda e: (e["host"], _norm(e.get("user")), e.get("logon_type"), e.get("ip"))
    if e["ch"] == "security" and e["code"] == 4624 else None,
    "powershell": lambda e: (e["host"], _shape(e.get("script") or e.get("cmd")))
    if e["ch"] == "powershell" and e["code"] in (4103, 4104) else None,
    "dns_domain": lambda e: (e["host"], ".".join(_norm(e.get("query")).split(".")[-2:]))
    if e["ch"] == "sysmon" and e["code"] == 22 else None,
    "lsass_access": lambda e: (e["host"], _norm(e.get("image")))
    if e["ch"] == "sysmon" and e["code"] == 10 else None,
    "pipe": lambda e: (e["host"], _norm(e.get("image")), _DIGITS.sub("#", _norm(e.get("pipe"))))
    if e["ch"] == "sysmon" and e["code"] in (17, 18) else None,
    "exec_file_write": lambda e: (e["host"], _norm(e.get("image")), _norm(e.get("file")).rsplit(".", 1)[-1])
    if e["ch"] == "sysmon" and e["code"] == 11 else None,
}


def load_host_labels() -> dict[tuple[str, str, int], int]:
    """(host, channel, record id) -> 1 (malicious) or 2 (malicious-related), Windows clients only."""
    labels: dict[tuple[str, str, int], int] = {}
    with zipfile.ZipFile(data_dir() / "system_logs_labels.zip") as z:
        for name, cls in (("system_labels/clients_1_and_2/malicious_events_class_1_and_2.jsonl", 2),
                          ("system_labels/clients_1_and_2/malicious_events_class_1.jsonl", 1)):
            with z.open(name) as f:
                for line in io.TextIOWrapper(f, encoding="utf-8"):
                    r = json.loads(line)
                    w = r.get("winlog") or {}
                    key = (r["agent"]["hostname"], channel_short(w.get("channel", "")), w.get("record_id"))
                    labels[key] = cls          # class 1 file read last: overrides 2
    return labels


def iter_events():
    for path in sorted(DERIVED.glob("*.jsonl.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as f:
            for line in f:
                yield json.loads(line)


def main() -> None:
    labels = load_host_labels()
    known = {d: set() for d in DETECTORS}
    seen_test = {d: set() for d in DETECTORS}
    benign = {d: collections.Counter() for d in DETECTORS}          # day -> distinct new benign keys
    mal_events = {d: collections.Counter() for d in DETECTORS}      # class -> labelled events on a novel key
    mal_total = collections.Counter()
    labelled_seen = 0
    for e in iter_events():
        day = e["t"][:10]
        cls = labels.get((e["host"], e["ch"], e["rid"]))
        if cls:
            labelled_seen += 1
        for name, fn in DETECTORS.items():
            k = fn(e)
            if k is None:
                continue
            if day < TEST_START:
                known[name].add(k)
                continue
            if cls:
                mal_total[(name, cls)] += 1
                if k not in known[name]:
                    mal_events[name][cls] += 1
            elif k not in known[name] and k not in seen_test[name]:
                benign[name][day] += 1
            if k not in known[name]:
                seen_test[name].add(k)
    out = {"labelled_events_in_extracted_data": labelled_seen, "labels_total": len(labels), "detectors": {}}
    for name in DETECTORS:
        days = benign[name]
        out["detectors"][name] = {
            "known_keys_from_training": len(known[name]),
            "benign_novel_keys_per_day": dict(sorted(days.items())),
            "benign_novel_keys_mean_per_day": round(sum(days.values()) / 14, 1),
            "malicious_events_on_novel_keys": {f"class_{c}": mal_events[name][c] for c in (1, 2)},
            "malicious_events_of_this_type": {f"class_{c}": mal_total[(name, c)] for c in (1, 2)},
        }
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "phase2_novelty.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"labels {len(labels):,}; labelled events found in the extracted data: {labelled_seen:,}")
    for name, d in out["detectors"].items():
        m, tot = d["malicious_events_on_novel_keys"], d["malicious_events_of_this_type"]
        print(f"{name:16s} benign new keys/day {d['benign_novel_keys_mean_per_day']:8.1f} | malicious on novel keys "
              f"class1 {m['class_1']}/{tot['class_1']}  class2 {m['class_2']}/{tot['class_2']} | known {d['known_keys_from_training']:,}")


if __name__ == "__main__":
    main()
