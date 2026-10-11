"""Phase 2 step P2-1 (2026-10-11): compact host events from DEDALE's winlogbeat records."""
from __future__ import annotations

import json

from dedale.winlogbeat import SCRIPT_LIMIT, compact, compact_line, hour_of, line_kind


def _rec(channel, event_id, **extra):
    r = {"@timestamp": "2025-01-06T10:01:05.579Z", "agent": {"hostname": "CLIENT2"},
         "winlog": {"channel": channel, "event_id": event_id, "record_id": 12813, "event_data": {}}}
    for k, v in extra.items():
        if k == "event_data":
            r["winlog"]["event_data"] = v
        else:
            r[k] = v
    return r


SYSMON, SECURITY, PS = "Microsoft-Windows-Sysmon/Operational", "Security", "Microsoft-Windows-PowerShell/Operational"


def test_hour_of_member_name():
    assert hour_of("daily_winlogbeat/D15_H10_2025-01-06T10_winlogbeat_F347.jsonl.bz2") == "2025-01-06T10"


def test_process_creation_fields():
    e = compact(_rec(SYSMON, 1, process={
        "executable": "C:\\Windows\\System32\\cmd.exe", "command_line": "cmd /c whoami", "pid": 4, "entity_id": "{g}",
        "parent": {"executable": "C:\\Windows\\explorer.exe", "command_line": "explorer", "entity_id": "{p}"}},
        user={"domain": "BREACH", "name": "client2"}, event_data={"IntegrityLevel": "Medium"}))
    assert (e["host"], e["rid"], e["ch"], e["code"]) == ("CLIENT2", 12813, "sysmon", 1)
    assert (e["image"], e["parent_image"], e["cmd"], e["user"], e["integrity"]) == (
        "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\explorer.exe", "cmd /c whoami", "BREACH\\client2", "Medium")


def test_filters_keep_only_relevant_events():
    assert compact(_rec(SYSMON, 7)) is None                                                    # DLL load
    assert compact(_rec("Application", 1)) is None
    assert compact(_rec(SYSMON, 10, event_data={"TargetImage": "C:\\Windows\\System32\\svchost.exe"})) is None
    lsass = compact(_rec(SYSMON, 10, process={"executable": "C:\\x.exe"},
                         event_data={"TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010"}))
    assert lsass["access"] == "0x1010"
    assert compact(_rec(SYSMON, 11, file={"path": "C:\\Users\\a\\notes.txt"})) is None
    assert compact(_rec(SYSMON, 11, file={"path": "C:\\Users\\a\\AppData\\Local\\Temp\\svcmon.EXE"}))["file"].endswith(".EXE")


def test_logon_and_powershell():
    logon = compact(_rec(SECURITY, 4624, event_data={
        "TargetDomainName": "BREACH", "TargetUserName": "client1", "LogonType": "3", "IpAddress": "172.16.1.3",
        "SubjectUserName": "-", "WorkstationName": "CLIENT2"}))
    assert (logon["user"], logon["logon_type"], logon["ip"], logon["subject"]) == ("BREACH\\client1", "3", "172.16.1.3", None)
    long_script = "Invoke-WebRequest " + "x" * (SCRIPT_LIMIT + 10)
    ps = compact(_rec(PS, 4104, powershell={"file": {"script_block_text": long_script}}))
    assert len(ps["script"]) == SCRIPT_LIMIT and ps["script_truncated"] is True


def test_raw_line_prefilter_matches_the_parsed_decision():
    for rec in (_rec(SYSMON, 1, process={"executable": "a.exe"}), _rec(SYSMON, 7), _rec(SECURITY, 4672),
                _rec(SYSMON, 17, process={"executable": "a.exe"}, event_data={"PipeName": "\\x"})):
        line = json.dumps(rec).encode()            # dataset formatting: '"key": value'
        assert line_kind(line) == (rec["winlog"]["channel"], rec["winlog"]["event_id"])
        assert compact_line(line) == compact(rec)
