"""
soc_server/follow.py

Live log ingestion (backend gap, 2026-10-19): follow files a log shipper
appends to, instead of replaying DEDALE.

  - host:    Windows events as winlogbeat / ECS JSON lines, reduced with
             dedale.winlogbeat.compact (events it does not keep are skipped);
  - network: Suricata alerts, as eve.json lines (event_type "alert") or as
             DEDALE's router syslog lines (dedale.suricata.to_alert); other
             eve records are skipped.

A file's position is the byte offset after the last complete line read, so a
restart resumes where the checkpoint stopped.  A partial last line is left
until its newline arrives.  A file that shrinks below the offset was truncated
(copytruncate rotation) and is read again from the start; rotation by renaming
is not detected.  Unparseable lines are skipped and counted.

Several files are polled in turn and their events are used in arrival order:
unlike the replay, events of different files are not merged by time.  When no
file has a new line, the source yields runner.WAIT, so the runner can tick the
loop and react to pause and stop while it waits.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

from soc_server.runner import WAIT

CHUNK = 1 << 20                     # bytes read per poll of one file
_SEVERITY = {1: "high", 2: "medium", 3: "low"}

Parsed = tuple[datetime, dict] | None


class TailSource:
    """Complete lines appended to one file, parsed into (time, event); position = byte offset."""

    def __init__(self, path: str | Path, parse: Callable[[bytes, int], Parsed]) -> None:
        self.path, self.parse = Path(path), parse
        self.skipped = 0                                  # lines that did not parse

    def read(self, offset: int) -> tuple[int, list[tuple[int, datetime, dict]]]:
        """(offset after the last complete line read, [(offset after the line, time, event)])."""
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return offset, []
        if size < offset:                                 # truncated: start again
            offset = 0
        if size == offset:
            return offset, []
        with open(self.path, "rb") as f:
            f.seek(offset)
            data = f.read(CHUNK)
        end = data.rfind(b"\n")
        if end < 0:                                       # no complete line yet
            if len(data) < CHUNK:
                return offset, []
            self.skipped += 1                             # a line longer than CHUNK: skipped in pieces
            return offset + len(data), []
        out, pos = [], offset
        for raw in data[:end].split(b"\n"):
            pos += len(raw) + 1
            if not raw.strip():
                continue
            try:
                parsed = self.parse(raw.strip(), pos)
            except (ValueError, KeyError, TypeError, AttributeError):
                self.skipped += 1
                continue
            if parsed is not None:
                out.append((pos, parsed[0], parsed[1]))
        return offset + end + 1, out


class FollowSource:
    """Several TailSources ({"host": ..., "network": ...}); items are (positions, time, (name, event))."""

    def __init__(self, tails: dict[str, TailSource]) -> None:
        self.tails = tails

    def events(self, after: dict | None) -> Iterator:
        positions = dict(after or {})
        offsets = dict(positions)                         # read so far (skipped lines included)
        while True:
            got = False
            for name, tail in self.tails.items():
                offsets[name], items = tail.read(offsets.get(name, 0))
                for pos, t, ev in items:
                    positions[name] = pos
                    got = True
                    yield dict(positions), t, (name, ev)
            if not got:
                yield WAIT


# -- parsers -------------------------------------------------------------------------------

def parse_winlogbeat(line: bytes, ref: int) -> Parsed:
    from dedale.winlogbeat import compact

    e = compact(json.loads(line))
    if e is None:
        return None
    return _t(e["t"]), e


def parse_suricata(line: bytes, ref: int) -> Parsed:
    """An eve.json alert, or a DEDALE router syslog record; None for other eve records."""
    r = json.loads(line)
    if "event_type" in r:
        if r["event_type"] != "alert":
            return None
        a = eve_alert(r, ref)
    else:
        from dedale.suricata import to_alert

        a = to_alert(r, ref)
        a["alert_id"] = f"live-suricata-{ref}"
    return _t(a["timestamp"]), a


def eve_alert(r: dict, ref: int) -> dict:
    """Suricata eve.json alert record -> the network alert dict dedale.suricata.to_alert produces."""
    a = r["alert"]
    at = _t(r["timestamp"])
    proto, src, dst = str(r["proto"]), str(r["src_ip"]), str(r["dest_ip"])
    sport, dport = int(r.get("src_port") or 0), int(r.get("dest_port") or 0)
    gid, sid, rev, prio = int(a.get("gid", 1)), int(a["signature_id"]), int(a.get("rev", 0)), int(a.get("severity", 3))
    signature, cls = str(a.get("signature", "")), str(a.get("category", ""))
    return {
        "alert_id": f"live-suricata-{ref}",
        "timestamp": at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "event_type": "network_ids_alert",
        "source_system": "SIEM",
        "sensor": r.get("host") or r.get("in_iface"),
        "generator_id": gid, "signature_id": sid, "signature_rev": rev,
        "signature": signature, "classification": cls,
        "priority": prio, "severity": _SEVERITY.get(prio, "low"),
        "protocol": proto,
        "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport,
        "raw_log_line": f"[{gid}:{sid}:{rev}] {signature} [Classification: {cls}] [Priority: {prio}] "
                        f"{{{proto}}} {src}:{sport} -> {dst}:{dport}",
    }


PARSERS = {"host": parse_winlogbeat, "network": parse_suricata}


def _t(s: str) -> datetime:
    t = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
