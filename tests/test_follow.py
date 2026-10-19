"""
Live log ingestion (2026-10-19): following files as they grow -- complete
lines only, resume by byte offset, truncation, unparseable lines skipped --
the eve.json / DEDALE syslog / winlogbeat parsers, and a runner that follows a
file, waits without blocking pause or stop, and resumes after a restart.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from dedale.environment import DEDALE_PROFILE, seed_store
from perception.soc_loop import SocLoop
from soc_server.follow import FollowSource, TailSource, eve_alert, parse_suricata, parse_winlogbeat
from soc_server.runner import WAIT, LiveRunner, stream_after

START = datetime(2024, 12, 30, tzinfo=timezone.utc)
TRAIN_END = datetime(2025, 1, 6, tzinfo=timezone.utc)


def _eve(n, event_type="alert"):
    r = {"timestamp": f"2025-01-06T10:00:{n:02d}.250000+0000", "event_type": event_type, "proto": "UDP",
         "src_ip": "172.17.0.5", "src_port": 40000 + n, "dest_ip": "185.208.37.90", "dest_port": 3478,
         "host": "companyrouter"}
    if event_type == "alert":
        r["alert"] = {"gid": 1, "signature_id": 2016149, "rev": 2, "severity": 3, "category": "Misc activity",
                      "signature": "ET INFO Session Traversal Utilities for NAT (STUN Binding Request)"}
    return json.dumps(r) + "\n"


def test_tail_reads_complete_lines_resumes_and_restarts_after_truncation(tmp_path):
    f = tmp_path / "eve.json"
    tail = TailSource(f, parse_suricata)
    assert tail.read(0) == (0, [])                                   # no file yet
    third = _eve(3)
    f.write_text(_eve(1) + _eve(2, "flow") + "not json\n" + _eve(4) + third[:20])
    offset, items = tail.read(0)
    assert [i[2]["src_port"] for i in items] == [40001, 40004]      # flow record and bad line skipped
    assert tail.skipped == 1 and offset == f.stat().st_size - 20     # partial line left for later
    assert items[-1][0] == offset                                    # position = offset after the line
    with open(f, "a") as out:
        out.write(third[20:])
    offset2, items = tail.read(offset)
    assert [i[2]["src_port"] for i in items] == [40003] and offset2 == f.stat().st_size
    assert tail.read(offset2) == (offset2, [])
    f.write_text(_eve(5))                                            # truncated (copytruncate rotation)
    _, items = tail.read(offset2)
    assert [i[2]["src_port"] for i in items] == [40005]


def test_parsers():
    a = eve_alert(json.loads(_eve(7)), 99)
    assert a["alert_id"] == "live-suricata-99" and a["signature_id"] == 2016149 and a["dst_port"] == 3478
    assert a["timestamp"] == "2025-01-06T10:00:07.250Z" and a["severity"] == "low"
    assert a["raw_log_line"].endswith("{UDP} 172.17.0.5:40007 -> 185.208.37.90:3478")
    syslog = {"@timestamp": 1736157600000, "logsource": "companyrouter", "message":
              "[1:2016149:2] ET INFO STUN Binding Request [Classification: Misc activity] [Priority: 3] "
              "{UDP} 172.17.0.5:40007 -> 185.208.37.90:3478"}
    t, b = parse_suricata(json.dumps(syslog).encode(), 12)
    assert t == datetime(2025, 1, 6, 10, tzinfo=timezone.utc) and b["alert_id"] == "live-suricata-12"
    assert b["src_ip"] == "172.17.0.5" and b["signature_id"] == 2016149
    ecs = {"@timestamp": "2025-01-06T10:00:00.000Z", "agent": {"hostname": "CLIENT2"},
           "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1, "record_id": 5,
                      "event_data": {"IntegrityLevel": "Medium"}},
           "process": {"executable": "C:\\x\\a.exe", "command_line": "a.exe", "parent": {"executable": "C:\\e.exe"}},
           "user": {"domain": "BREACH", "name": "client2"}}
    t, e = parse_winlogbeat(json.dumps(ecs).encode(), 1)
    assert t == datetime(2025, 1, 6, 10, tzinfo=timezone.utc)
    assert (e["host"], e["ch"], e["code"], e["image"], e["user"]) == ("CLIENT2", "sysmon", 1, "C:\\x\\a.exe",
                                                                        "BREACH\\client2")
    ecs["winlog"]["event_id"] = 7                                    # DLL load: not kept
    assert parse_winlogbeat(json.dumps(ecs).encode(), 2) is None


def test_follow_source_yields_wait_when_quiet(tmp_path):
    f = tmp_path / "eve.json"
    f.write_text(_eve(1))
    it = FollowSource({"network": TailSource(f, parse_suricata)}).events(None)
    pos, _, (name, alert) = next(it)
    assert name == "network" and pos == {"network": f.stat().st_size}
    assert next(it) is WAIT
    with open(f, "a") as out:
        out.write(_eve(2))
    assert next(it)[2][1]["src_port"] == 40002


# -- the runner following a file -------------------------------------------------------------

def _proc(t, image, rid):
    return {"t": t.isoformat().replace("+00:00", "Z"), "host": "CLIENT2", "rid": rid, "ch": "sysmon", "code": 1,
            "image": image, "parent_image": "C:\\Windows\\explorer.exe", "cmd": "x", "user": "BREACH\\client2"}


def _training():
    out, rid = [], 0
    for day in range(7):
        for hour in (9, 13, 17):
            t = START + timedelta(days=day, hours=hour)
            for image in ("C:\\x\\word.exe", f"C:\\x\\tool{(day * 3 + hour) % 7}.exe"):
                rid += 1
                out.append((t, _proc(t, image, rid)))
    return out


class _Replay:                         # items shaped like FollowSource's: (name, event)
    def events(self, after):
        return stream_after([(t, ("host", e)) for t, e in _training()], after)


def _compact(line, ref):
    e = json.loads(line)
    return datetime.fromisoformat(e["t"].replace("Z", "+00:00")), e


def _runner(home, path):
    return LiveRunner(home, FollowSource({"host": TailSource(path, _compact)}), profile=DEDALE_PROFILE, start=START,
                      make_loop=lambda db, cs: SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs),
                      handle=lambda loop, item, at: loop.process_host_event(item[1], at),
                      seed=lambda db: seed_store(db, START), source_id="follow:test", paced=False,
                      checkpoint_every=0.2)


def _wait_for(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while not cond():
        assert time.monotonic() < end, "timed out"
        time.sleep(0.05)


def _append(path, t, image, rid):
    with open(path, "a") as f:
        f.write(json.dumps(_proc(t, image, rid)) + "\n")


def test_runner_follows_a_growing_file_and_resumes_after_restart(tmp_path):
    log = tmp_path / "host.ndjson"
    r = _runner(tmp_path / "home", log)
    trained = r.run_until(TRAIN_END, source=_Replay())
    assert trained == len(_training()) and r.pos is None
    r.start()
    assert r.status()["mode"] == "follow"
    t = TRAIN_END + timedelta(hours=9)
    _append(log, t, "C:\\x\\word.exe", 1001)                          # learned in training: no alert
    _append(log, t + timedelta(minutes=1), "C:\\x\\new.exe", 1002)    # novel: alerts
    _wait_for(lambda: r.events_processed == trained + 2)
    assert r.loop.counts["alerts"] == 1 and r.now() == t + timedelta(minutes=1)
    began = time.monotonic()
    r.pause()                                                         # not blocked by the waiting source
    _wait_for(lambda: r.status()["state"] == "paused")
    r.stop()
    assert time.monotonic() - began < 5

    again = _runner(tmp_path / "home", log)
    assert again.restored and again.pos == {"host": log.stat().st_size}
    again.start()
    _append(log, t + timedelta(minutes=2), "C:\\x\\other.exe", 1003)
    _wait_for(lambda: again.events_processed == trained + 3)
    assert again.loop.counts["alerts"] == 2                           # the first two lines were not re-read
    again.stop()
