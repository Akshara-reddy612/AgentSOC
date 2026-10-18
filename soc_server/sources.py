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
