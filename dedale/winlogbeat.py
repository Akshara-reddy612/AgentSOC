"""
dedale/winlogbeat.py

DEDALE's Windows logs (system_logs_winlogbeat.zip: 672 hourly
daily_winlogbeat/*.jsonl.bz2 members, ECS records from the 30 Windows clients)
as compact host events (Phase 2, 2026-10-11).

An hour holds ~650,000 records (~1.7 GB uncompressed), 99.8% Sysmon, so the
whole set (~1 TB uncompressed) is streamed, never extracted.  `compact`
keeps the event types host-based detection and the Knowledge Store need and
drops the rest (DLL loads, file deletions, ...):

  sysmon 1   process creation        image, command line, parent, user, integrity
  sysmon 10  process access          only when the target is lsass.exe (credential access)
  sysmon 11  file creation           only executable / script / macro-document / archive files
  sysmon 17/18 named pipe created / connected
  sysmon 22  DNS query               query, answers, image
  security 4624/4625/4648/4672       logons, failed logons, explicit credentials, special privileges
  powershell 4103/4104/800           command invocation, script block text (truncated), pipeline
  system 7045                        service installed

Trust split, as everywhere in AgentSOC: identifiers, addresses, codes and
times are structured fields; command lines, script text, file paths and DNS
names are attacker-influenced free text.  Labels are never read here.
"""
from __future__ import annotations

import bz2
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Iterator

from dedale import data_dir

ZIP_NAME = "system_logs_winlogbeat.zip"
SCRIPT_LIMIT = 4000
_FILE_EXTENSIONS = (".exe", ".dll", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".hta", ".scr",
                    ".lnk", ".docm", ".xlsm", ".pptm", ".dotm", ".zip", ".7z", ".rar", ".iso")
_CHANNELS = {"Microsoft-Windows-Sysmon/Operational": "sysmon", "Security": "security",
             "Microsoft-Windows-PowerShell/Operational": "powershell", "Windows PowerShell": "powershell",
             "System": "system"}
_KEEP = {("sysmon", 1), ("sysmon", 10), ("sysmon", 11), ("sysmon", 17), ("sysmon", 18), ("sysmon", 22),
         ("security", 4624), ("security", 4625), ("security", 4648), ("security", 4672),
         ("powershell", 4103), ("powershell", 4104), ("powershell", 800), ("system", 7045)}


def hour_of(member: str) -> str:
    """'daily_winlogbeat/D15_H10_2025-01-06T10_winlogbeat_F347.jsonl.bz2' -> '2025-01-06T10'."""
    return member.rsplit("/", 1)[-1].split("_")[2]


def members(path: Path | None = None) -> list[str]:
    """The hourly members, in time order."""
    with zipfile.ZipFile(path or data_dir() / ZIP_NAME) as z:
        names = [n for n in z.namelist() if n.endswith(".jsonl.bz2")]
    return sorted(names, key=hour_of)


def iter_records(member: str, path: Path | None = None) -> Iterator[dict]:
    with zipfile.ZipFile(path or data_dir() / ZIP_NAME) as z, z.open(member) as raw, bz2.open(raw) as f:
        for line in io.TextIOWrapper(f, encoding="utf-8"):
            yield json.loads(line)


def iter_lines(member: str, path: Path | None = None) -> Iterator[bytes]:
    """Raw JSON lines of one hourly member (no parsing)."""
    with zipfile.ZipFile(path or data_dir() / ZIP_NAME) as z, z.open(member) as raw, bz2.open(raw) as f:
        yield from f


# Cheap byte-level look at a raw line, so only candidate lines (~7% of an hour)
# are parsed.  "winlog" is the last top-level key of these records, so its
# channel and event id are found by searching from the end.  A quote inside a
# JSON string is escaped, so the keys cannot match text inside messages.
_KEPT_IDS = frozenset(code for _, code in _KEEP)
_DIGITS_RE = re.compile(rb"\d+")


def line_kind(line: bytes) -> tuple[str, int | None]:
    """(channel, event id) read from a raw line without parsing it."""
    eid = None
    i = line.rfind(b'"event_id": ')
    if i >= 0:
        m = _DIGITS_RE.match(line, i + 12)
        eid = int(m.group(0)) if m else None
    ch = "None"
    c = line.rfind(b'"channel": "')
    if c >= 0:
        ch = line[c + 12:line.find(b'"', c + 12)].decode()
    return ch, eid


def compact_line(line: bytes, kind: tuple[str, int | None] | None = None) -> dict | None:
    """compact() for a raw line; lines whose event id is never kept are not parsed."""
    _, eid = kind or line_kind(line)
    if eid not in _KEPT_IDS:
        return None
    return compact(json.loads(line))


def channel_short(channel: str) -> str | None:
    """'Microsoft-Windows-Sysmon/Operational' -> 'sysmon' (None for channels that are not kept)."""
    return _CHANNELS.get(channel)


def compact(r: dict) -> dict | None:
    """One ECS record -> compact host event, or None for event types that are not kept."""
    w = r.get("winlog") or {}
    ch = channel_short(w.get("channel", ""))
    code = w.get("event_id")
    if (ch, code) not in _KEEP:
        return None
    ed = w.get("event_data") or {}
    p = r.get("process") or {}
    parent = p.get("parent") or {}
    user = r.get("user") or {}
    e = {"t": r["@timestamp"], "host": (r.get("agent") or {}).get("hostname"), "rid": w.get("record_id"),
         "ch": ch, "code": code}
    if ch == "sysmon" and code == 1:
        e.update(image=p.get("executable"), cmd=p.get("command_line"), pid=p.get("pid"), guid=p.get("entity_id"),
                 parent_image=parent.get("executable"), parent_cmd=parent.get("command_line"),
                 parent_guid=parent.get("entity_id"), user=_user(user), integrity=ed.get("IntegrityLevel"))
    elif ch == "sysmon" and code == 10:
        target = ed.get("TargetImage") or ""
        if not target.lower().endswith("\\lsass.exe"):
            return None
        e.update(image=p.get("executable"), target_image=target, access=ed.get("GrantedAccess"))
    elif ch == "sysmon" and code == 11:
        path = (r.get("file") or {}).get("path") or ed.get("TargetFilename") or ""
        if not path.lower().endswith(_FILE_EXTENSIONS):
            return None
        e.update(image=p.get("executable"), file=path)
    elif ch == "sysmon" and code in (17, 18):
        e.update(image=p.get("executable"), pipe=ed.get("PipeName"))
    elif ch == "sysmon" and code == 22:
        dns = r.get("dns") or {}
        e.update(image=p.get("executable"), query=(dns.get("question") or {}).get("name") or ed.get("QueryName"),
                 answers=[a.get("data") for a in dns.get("answers") or [] if a.get("data")],
                 user=ed.get("User"))
    elif ch == "security":
        e.update(user=_join(ed.get("TargetDomainName"), ed.get("TargetUserName")),
                 subject=_join(ed.get("SubjectDomainName"), ed.get("SubjectUserName")),
                 logon_type=ed.get("LogonType"), ip=ed.get("IpAddress"), workstation=ed.get("WorkstationName"),
                 process=ed.get("ProcessName"))
    elif ch == "powershell":
        ps = r.get("powershell") or {}
        script = ((ps.get("file") or {}).get("script_block_text")) or ""
        e.update(user=_user(user), cmd=p.get("command_line"), script=script[:SCRIPT_LIMIT] or None,
                 script_truncated=len(script) > SCRIPT_LIMIT)
    elif ch == "system":
        e.update(service=ed.get("ServiceName"), image=ed.get("ImagePath"), account=ed.get("AccountName"))
    return e


def _user(u: dict) -> str | None:
    return _join(u.get("domain"), u.get("name"))


def _join(domain: str | None, name: str | None) -> str | None:
    if not name or name == "-":
        return None
    return f"{domain}\\{name}" if domain and domain != "-" else name
