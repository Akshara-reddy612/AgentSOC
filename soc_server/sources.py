"""
soc_server/sources.py

Replay sources for the live runner (M4.4).  DEDALE host events come from the
hourly files written by experiments/dedale_extract_winlogbeat.py, in time order
within each hour (as in experiments/dedale_host_replay.py); a position is
(hour file name, index in that hour).
"""
from __future__ import annotations

import gzip
import json
from datetime import datetime
from pathlib import Path
from typing import Iterator


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class DedaleHostSource:
    def __init__(self, events_dir: str | Path) -> None:
        self.dir = Path(events_dir)

    def events(self, after: tuple[str, int] | None) -> Iterator[tuple[tuple[str, int], datetime, dict]]:
        for path in sorted(self.dir.glob("*.jsonl.gz")):
            hour = path.name.split(".")[0]
            if after is not None and hour < after[0]:
                continue
            with gzip.open(path, "rt", encoding="utf-8") as f:
                events = sorted((json.loads(line) for line in f), key=lambda e: e["t"])
            start = after[1] + 1 if after is not None and hour == after[0] else 0
            for i in range(start, len(events)):
                yield (hour, i), _t(events[i]["t"]), events[i]


class InjectedSource:
    """
    A source whose events pass through E1's attacker simulation (experiments/dedale_inject.Injector):
    the demo's contamination scenario (PROJECT_PLAN section 5, item 7).  The injector reads labels
    to find the attacker's own commands; the pipeline never does (invariant I4).
    """

    def __init__(self, source, injector) -> None:
        self.source, self.injector = source, injector

    def events(self, after):
        for pos, t, ev in self.source.events(after):
            yield pos, t, self.injector(ev)


class DedaleNetSource:
    """DEDALE Suricata alerts (dedale/suricata.py) in file order (= time order); position = line number."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None

    def events(self, after: int | None) -> Iterator[tuple[int, datetime, dict]]:
        from dedale.suricata import alert_time, iter_alerts

        for alert in iter_alerts(self.path):
            line = int(alert["alert_id"].rsplit("-", 1)[1])
            if after is not None and line <= after:
                continue
            yield line, alert_time(alert), alert


class MergedSource:
    """
    Several sources interleaved by time.  Items are (positions, time, (name, event)); `positions`
    holds the last position consumed from every source, so a resume continues each where it stopped.
    """

    def __init__(self, sources: dict[str, object]) -> None:
        self.sources = sources

    def events(self, after: dict | None) -> Iterator[tuple[dict, datetime, tuple[str, dict]]]:
        import heapq

        positions = dict(after or {})

        def tagged(name, src):                    # binds `name` per stream (a generator expression would not)
            for pos, t, ev in src.events(positions.get(name)):
                yield t, name, pos, ev

        streams = [tagged(name, src) for name, src in self.sources.items()]
        for t, name, pos, ev in heapq.merge(*streams, key=lambda x: (x[0], x[1])):
            positions[name] = pos
            yield dict(positions), t, (name, ev)


def handle_merged(loop, item: tuple[str, dict], at: datetime) -> None:
    """The loop call for an item of a MergedSource of 'host' and 'network' sources."""
    kind, event = item
    if kind == "host":
        loop.process_host_event(event, at)
    else:
        loop.process(event, at)
