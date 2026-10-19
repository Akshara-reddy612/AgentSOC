"""
M4.2 (2026-10-18): the live runner -- fast-forward, paced replay with
pause / speed, analysts' commands applied while paused, and checkpoint /
restore giving exactly the state of an uninterrupted run.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from dedale.environment import DEDALE_PROFILE, seed_store
from perception.knowledge_db import graph_signature
from perception.soc_loop import SocLoop
from soc_server.runner import LiveRunner, stream_after

START = datetime(2024, 12, 30, tzinfo=timezone.utc)
TRAIN_END = datetime(2025, 1, 6, tzinfo=timezone.utc)


def _proc(t, image, host="CLIENT2", rid=1):
    return {"t": t.isoformat().replace("+00:00", "Z"), "host": host, "rid": rid, "ch": "sysmon", "code": 1,
            "image": image, "parent_image": "C:\\Windows\\explorer.exe", "cmd": "x", "user": "BREACH\\client2"}


def _events():
    out, rid = [], 0
    for day in range(10):                             # 6 training days, 4 test days
        for hour in (9, 13, 17):
            t = START + timedelta(days=day, hours=hour)
            novel = f"C:\\x\\new{day}.exe" if t >= TRAIN_END else f"C:\\x\\tool{(day * 3 + hour) % 7}.exe"
            for image in ("C:\\x\\word.exe", novel):
                rid += 1
                out.append((t, _proc(t, image, rid=rid)))
    return out


class _Src:
    def __init__(self, events):
        self.list = events

    def events(self, after):
        return stream_after(self.list, after)


def _runner(home, **kw):
    return LiveRunner(home, _Src(_events()), profile=DEDALE_PROFILE, start=START,
                      make_loop=lambda db, cs: SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs),
                      handle=lambda loop, ev, at: loop.process_host_event(ev, at),
                      seed=lambda db: seed_store(db, START), **kw)


def _snapshot(r):
    return (graph_signature(r.db.graph.graph),
            [(c["case_id"], c["title"], c["review_status"], c["alert_count"]) for c in r.cases.cases()])


def test_restore_gives_the_state_of_an_uninterrupted_run(tmp_path):
    end = START + timedelta(days=11)
    whole = _runner(tmp_path / "a")
    whole.run_until(end)
    expected = _snapshot(whole)
    whole.stop()

    first = _runner(tmp_path / "b")
    first.run_until(START + timedelta(days=7, hours=12))       # mid test window, open cases in memory
    first.stop()                                               # final checkpoint
    again = _runner(tmp_path / "b")
    assert again.restored and again.pos is not None
    again.run_until(end)
    assert _snapshot(again) == expected
    again.stop()


def test_paced_run_pause_speed_and_commands_while_paused(tmp_path):
    r = _runner(tmp_path / "c", speed=86_400, checkpoint_every=0.2)
    r.run_until(TRAIN_END + timedelta(hours=10))                # fast-forward through training
    (case,) = [c for c in r.cases.cases() if c["review_status"] == "open"][:1]
    r.cases.submit_verdict(case["case_id"], "benign", "alice", r.now())
    r.start()
    r.pause()
    deadline = time.monotonic() + 10
    while not r.cases.commands()[0]["applied_at"] and time.monotonic() < deadline:
        time.sleep(0.05)
    assert r.cases.commands()[0]["applied_at"] is not None       # applied while paused
    r.set_speed(43_200)
    r.start()                                                    # resume
    while r.status()["state"] != "finished" and time.monotonic() < deadline + 20:
        time.sleep(0.05)
    st = r.status()
    assert st["state"] == "finished" and st["events_processed"] == len(_events())
    r.stop()
    assert (tmp_path / "c" / "checkpoint" / "state.pkl").exists()


def test_commands_apply_before_the_replay_is_started(tmp_path):
    r = _runner(tmp_path / "d", speed=86_400, checkpoint_every=0.2)
    r.run_until(TRAIN_END + timedelta(hours=10))
    (case,) = [c for c in r.cases.cases() if c["review_status"] == "open"][:1]
    r.start(paused=True)                                         # server start: thread up, replay paused
    r.cases.submit_verdict(case["case_id"], "benign", "alice", r.now())
    deadline = time.monotonic() + 10
    while not r.cases.commands()[0]["applied_at"] and time.monotonic() < deadline:
        time.sleep(0.05)
    assert r.cases.commands()[0]["applied_at"] is not None and r.status()["state"] == "paused"
    r.stop()
