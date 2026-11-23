"""
experiments/dedale_plant.py

Checklist A8 (2026-11-22): low-and-slow poisoning ("conditioning" the store). Design:
experiments/A8_LOW_AND_SLOW_DESIGN.md.

The attacker knows which tools its attack will use. Before each attack step it runs the same tools harmlessly, so
that every detector key the attack will raise is seen first on harmless activity: the same parent and child image
(process lineage), the same image writing the same file type, the same image using the same pipe. The detector keys
carry no command-line text, so a harmless run has the attack's key. A planted event is a copy of the attack event
that first uses the key, with harmless text, a time before the attack, and a record id that no label carries (the
simulated analyst sees nothing malicious in it, which is true).

Not plantable: the PowerShell key is a fingerprint of the script text, so only the attack script itself has it.

  when="test"   in the test period, as early as the data allows (from TRAINING_END, one plant per host every
                10 minutes in order of first use); CLIENT2's attack starts 10 h into the test period
  when="train"  8 days before each key's first use (past B5's 7-day lookback): inside the training weeks, so the
                planted keys are learned as training (an attacker present while the store is trained)

  when="foothold"  inside the threat model: only after the attacker's first labelled event on that host, one plant
                every 10 seconds, and only for keys the attack has not used by then (the others cannot be planted).
                The recorded attack schedule is kept, so this attacker does not pause to let plants be learned

  when="slow"   one plant per host every 3 hours from 2024-12-30 02:00 (with --gate-from 2024-12-30: a week before the
                attack, in a period the learning gate already guards)

Offline; reads the labels only to pick the attack events (as the E1 injector does).
"""
from __future__ import annotations

import gzip
import json
from datetime import datetime, timedelta, timezone

from dedale import data_dir
from experiments.dedale_host_novelty import load_host_labels
from perception.host_detection import _DIGITS, DETECTORS

PLANTABLE = ("lineage", "exec_file_write", "pipe")
TEST_START = datetime(2025, 1, 6, tzinfo=timezone.utc)
TEST_END = datetime(2025, 1, 20, tzinfo=timezone.utc)
SPACING = timedelta(minutes=10)
TRAIN_LEAD = timedelta(days=8)
FOOTHOLD_SPACING = timedelta(seconds=10)
SLOW_START = datetime(2024, 12, 30, 2, tzinfo=timezone.utc)
SLOW_SPACING = timedelta(hours=3)


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def attack_keys(detectors=PLANTABLE) -> dict[tuple, tuple[datetime, dict]]:
    """(detector, key) -> (first use, the class-1 event that first uses it), over the test period."""
    labels, first = load_host_labels(), {}
    for path in sorted((data_dir() / "derived" / "winlogbeat").glob("*.jsonl.gz")):
        hour = _t(path.name.split(".")[0] + ":00:00Z")
        if not TEST_START <= hour < TEST_END:
            continue
        with gzip.open(path, "rt", encoding="utf-8") as f:
            for line in f:
                e = json.loads(line)
                if labels.get((e["host"], e["ch"], e["rid"])) != 1:
                    continue
                for d in detectors:
                    k = DETECTORS[d].key(e)
                    if k is not None and ((d, k) not in first or _t(e["t"]) < first[(d, k)][0]):
                        first[(d, k)] = (_t(e["t"]), e)
    return first


def _harmless(e: dict, detector: str, i: int) -> dict:
    p = dict(e)
    image = (e.get("image") or "").rsplit("\\", 1)[-1]
    for f in ("cmd", "parent_cmd"):
        if p.get(f) and detector != "powershell":   # a PowerShell key is its text: only the attack script itself has it
            p[f] = image if f == "cmd" else (e.get("parent_image") or "")
    if detector == "exec_file_write" and p.get("file"):
        ext = p["file"].rsplit(".", 1)[-1]
        p["file"] = f"C:\\Users\\Public\\Documents\\notes_{i}.{ext}"
    if detector == "powershell":              # a harmless script that shares the fingerprinted 160-character prefix
        field = "script" if p.get("script") else "cmd"
        text, n = p[field], 160
        while n < len(text) and len(_DIGITS.sub("#", text[:n].lower())) < 160:
            n += 1
        if n < len(text):
            p[field] = text[:n] + " harmless"
    p["rid"] = -(i + 1)                       # no label carries a negative record id
    p["planted"] = detector
    return p


def plants(when: str, detectors=PLANTABLE) -> list[tuple[datetime, dict]]:
    """The planted events, in time order, as (time, event)."""
    if when not in ("test", "train", "foothold", "slow"):
        raise ValueError(f"when must be test, train, foothold or slow: {when!r}")
    keys = sorted(attack_keys(detectors).items(), key=lambda kv: kv[1][0])
    footholds: dict[str, datetime] = {}
    if when == "foothold":              # first labelled event with any key on the host, whatever is planted
        for first_use, e in attack_keys(tuple(DETECTORS)).values():
            footholds[e["host"]] = min(first_use, footholds.get(e["host"], first_use))
    out, next_slot = [], {}
    for i, ((detector, _), (first_use, e)) in enumerate(keys):
        if when == "train":
            at = first_use - TRAIN_LEAD
        elif when == "slow":
            at = next_slot.get(e["host"], SLOW_START)
            next_slot[e["host"]] = at + SLOW_SPACING
        elif when == "foothold":
            at = next_slot.get(e["host"], footholds[e["host"]] + FOOTHOLD_SPACING)
            if at >= first_use:             # already used in the attack: too late to plant
                continue
            next_slot[e["host"]] = at + FOOTHOLD_SPACING
        else:
            at = next_slot.get(e["host"], TEST_START + SPACING)
            next_slot[e["host"]] = at + SPACING
        p = _harmless(e, detector, i)
        p["t"] = _iso(at)
        p["planted_for"] = _iso(first_use)
        out.append((at, p))
    return sorted(out, key=lambda x: x[0])
