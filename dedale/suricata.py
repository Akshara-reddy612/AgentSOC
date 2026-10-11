"""
dedale/suricata.py

DEDALE's Suricata alerts as AgentSOC network alerts (design step S3).  The file
(suricata_alerts.zip -> suricata_alerts.jsonl) holds syslog records from the two
company routers whose message is Suricata's one-line alert format:

    [gid:sid:rev] <signature> [Classification: <class>] [Priority: <n>] {<proto>} <src>:<port> -> <dst>:<port>

Checked on the full file (2026-10-11): 1,465,627 records, in time order, all
TCP/UDP over IPv4 with ports, every line in this format.

Trust split: the signature, classification and priority come from the IDS rule
set, the addresses and ports from the sensor's own formatting, so they are
structured fields.  The whole line is also kept as raw_log_line, the free-text
evidence NCE may read.  Entity fields (source_host, target_host,
destination_ip) are not set here: the Knowledge Store resolves addresses to
hosts (perception/network_alert.py).  DEDALE has no labels for these alerts.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from dedale import data_dir

_LINE = re.compile(
    r"^\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\] (?P<signature>.*?) "
    r"\[Classification: (?P<classification>[^\]]*)\] \[Priority: (?P<priority>\d+)\] "
    r"\{(?P<protocol>[^}]*)\} (?P<src>\d{1,3}(?:\.\d{1,3}){3}):(?P<src_port>\d+) "
    r"-> (?P<dst>\d{1,3}(?:\.\d{1,3}){3}):(?P<dst_port>\d+)$"
)
_SEVERITY = {1: "high", 2: "medium", 3: "low"}
MEMBER = "suricata_alerts.jsonl"


def to_alert(record: dict, line_no: int) -> dict:
    """One syslog record -> network alert dict (ValueError if the message is not an alert line)."""
    message = str(record.get("message", "")).strip()
    m = _LINE.match(message)
    if not m:
        raise ValueError(f"line {line_no}: not a Suricata alert line: {message[:120]!r}")
    priority = int(m["priority"])
    at = datetime.fromtimestamp(record["@timestamp"] / 1000, timezone.utc)
    return {
        "alert_id": f"dedale-suricata-{line_no}",
        "timestamp": at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "event_type": "network_ids_alert",
        "source_system": "SIEM",
        "sensor": record.get("logsource"),
        "generator_id": int(m["gid"]), "signature_id": int(m["sid"]), "signature_rev": int(m["rev"]),
        "signature": m["signature"], "classification": m["classification"],
        "priority": priority, "severity": _SEVERITY.get(priority, "low"),
        "protocol": m["protocol"],
        "src_ip": m["src"], "src_port": int(m["src_port"]),
        "dst_ip": m["dst"], "dst_port": int(m["dst_port"]),
        "raw_log_line": message,
    }


def alert_time(alert: dict) -> datetime:
    return datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))


def iter_alerts(path: Path | None = None, *, start: datetime | None = None,
                end: datetime | None = None) -> Iterator[dict]:
    """Alerts in file order, which is time order; optionally only those with start <= time < end."""
    path = path or data_dir() / "suricata_alerts.zip"
    start_ms = start.timestamp() * 1000 if start else None
    end_ms = end.timestamp() * 1000 if end else None
    with zipfile.ZipFile(path) as z, z.open(MEMBER) as f:
        for line_no, line in enumerate(io.TextIOWrapper(f, encoding="utf-8"), start=1):
            record = json.loads(line)
            t = record["@timestamp"]
            if start_ms is not None and t < start_ms:
                continue
            if end_ms is not None and t >= end_ms:
                break
            yield to_alert(record, line_no)
