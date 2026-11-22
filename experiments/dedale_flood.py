"""
experiments/dedale_flood.py

Checklist A3 (flooding, 2026-11-23): escalation flooding. Design: experiments/A3_FLOODING_DESIGN.md.

While it controls a host, the attacker launches harmless programs that the store has never seen, `rate` per hour,
each from a new path. Each has a new process-lineage key, so each opens its own case and goes to review: the review
queue fills with junk on the attacked hosts while the real attack runs there. The attacker controls CLIENT2 from
initial access and CLIENT1 from lateral movement (experiments/dedale_host_score.py CLIENT_STEPS) until the end of the
exfiltration day. Flood events carry record ids no label carries (below the A8 plants' range).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

UTC = timezone.utc
FOOTHOLDS = (("CLIENT2", datetime(2025, 1, 6, 10, 0, tzinfo=UTC)),
             ("CLIENT1", datetime(2025, 1, 8, 15, 0, tzinfo=UTC)))
FLOOD_END = datetime(2025, 1, 12, tzinfo=UTC)
RID_BASE = -1_000_000


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def flood(rate: float) -> list[tuple[datetime, dict]]:
    """The flood events, in time order, as (time, event)."""
    if rate <= 0:
        raise ValueError("rate must be positive")
    step, out, i = timedelta(hours=1 / rate), [], 0
    for host, start in FOOTHOLDS:
        at = start + timedelta(minutes=1)
        while at < FLOOD_END:
            out.append((at, {"t": _iso(at), "host": host, "rid": RID_BASE - i, "ch": "sysmon", "code": 1,
                             "image": f"C:\\Users\\Public\\Tools\\updater_{i}.exe",
                             "parent_image": "C:\\Windows\\explorer.exe",
                             "cmd": f"updater_{i}.exe --check", "user": f"BREACH\\{host.lower()}",
                             "flood": True}))
            at += step
            i += 1
    return sorted(out, key=lambda x: x[0])
