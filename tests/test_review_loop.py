"""
Analyst review loop, step 2 (2026-10-11): one path for verdicts.  Analysts
submit verdicts to the case store; the loop applies them (single writer of the
Knowledge Store) once its clock reaches them; the simulated analyst of the
experiments goes through the same inbox when a case store is attached.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from dedale.environment import DEDALE_PROFILE, seed_store
from perception.case_store import CaseStore, ReviewError
from perception.host_detection import image_node_id
from perception.knowledge_db import KnowledgeDB
from perception.soc_loop import SocLoop

TRAIN_END = datetime(2025, 1, 6, tzinfo=timezone.utc)
T = TRAIN_END + timedelta(hours=10)


def _proc(t, image="C:\\Tools\\backup.exe", host="CLIENT2", rid=1):
    return {"t": t.isoformat().replace("+00:00", "Z"), "host": host, "rid": rid, "ch": "sysmon", "code": 1,
            "image": image, "parent_image": "C:\\Windows\\explorer.exe", "cmd": "backup.exe /all",
            "user": "BREACH\\client2"}


@pytest.fixture()
def db(tmp_path):
    with KnowledgeDB(tmp_path / "ks.sqlite", DEDALE_PROFILE, created_at=TRAIN_END - timedelta(days=14)) as store:
        seed_store(store, TRAIN_END - timedelta(days=14))
        yield store


@pytest.fixture()
def cs(tmp_path):
    with CaseStore(tmp_path / "cases.sqlite", created_at=TRAIN_END) as store:
        yield store


def _learned(db, image="C:\\Tools\\backup.exe"):
    return db.edge_learned_from(image_node_id("C:\\Windows\\explorer.exe"), image_node_id(image), "host:client2")


def _open_case(loop, cs, image="C:\\Tools\\backup.exe", rid=1, t=T):
    loop.process_host_event(_proc(t, image, rid=rid), t)
    return [c for c in cs.cases() if c["title"].startswith("explorer.exe starting " + image.split("\\")[-1].lower())][0]


def test_human_verdict_is_applied_when_the_loop_reaches_it(db, cs):
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs)
    case = _open_case(loop, cs)
    cs.claim(case["case_id"], "alice", T + timedelta(minutes=5))
    cmd = cs.submit_verdict(case["case_id"], "benign", "alice", T + timedelta(minutes=30))
    assert _learned(db) is None                                    # analysts never write the Knowledge Store
    loop.process_host_event(_proc(T + timedelta(minutes=20), "C:\\x\\a.exe", rid=2), T + timedelta(minutes=20))
    assert _learned(db) is None and len(cs.pending_commands(T + timedelta(hours=1))) == 1   # not yet its time
    loop.process_host_event(_proc(T + timedelta(hours=1), "C:\\x\\b.exe", rid=3), T + timedelta(hours=1))
    assert _learned(db) == "analyst"
    (applied,) = cs.commands(case["case_id"])
    assert applied["cmd_id"] == cmd and applied["result"] == {"applied": True, "verdict": "benign", "learned": True}
    assert applied["applied_at"] == "2025-01-06T11:00:00.000000Z"
    assert [e["writer"] for e in db.audit_log()][-1] == "analyst:alice"


def test_benign_once_lifts_the_hold_without_learning(db, cs):
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs)
    case = _open_case(loop, cs)
    cs.submit_verdict(case["case_id"], "benign_once", "alice", T + timedelta(minutes=10))
    loop.process_host_event(_proc(T + timedelta(hours=2), "C:\\x\\a.exe", rid=2), T + timedelta(hours=2))
    assert _learned(db) is None
    assert loop.updater._escalations["CLIENT2"].keys() == {"case-2"}        # case-1's hold lifted, a.exe's remains
    loop.process_host_event(_proc(T + timedelta(days=1), rid=3), T + timedelta(days=1))
    assert loop.counts["alerts"] == 3                                         # backup.exe alerts again


def test_malicious_verdict_contains_and_flags(db, cs):
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs)
    case = _open_case(loop, cs, image="C:\\Users\\client2\\AppData\\Local\\Temp\\svcmon.exe")
    cs.submit_verdict(case["case_id"], "malicious", "bob", T + timedelta(minutes=10))
    loop.process_host_event(_proc(T + timedelta(hours=1), "C:\\x\\a.exe", rid=2), T + timedelta(hours=1))
    (cmd,) = cs.commands(case["case_id"])
    assert cmd["result"]["flagged_host"] == "CLIENT2" and cmd["result"]["applied"] is True
    loop.finish(T + timedelta(hours=2))
    assert any(w.action == "ANALYST_CONFIRMED" and w.target == "CLIENT2" for w in loop.monitor.finished)


def test_frozen_mode_does_not_learn_from_verdicts(db, cs):
    loop = SocLoop(db, mode="frozen", training_end=TRAIN_END, case_store=cs)
    case = _open_case(loop, cs)
    cs.submit_verdict(case["case_id"], "benign", "alice", T)
    loop.process_host_event(_proc(T + timedelta(hours=1), "C:\\x\\a.exe", rid=2), T + timedelta(hours=1))
    assert _learned(db) is None and cs.commands()[0]["result"]["learned"] is False


def test_simulated_analyst_goes_through_the_inbox(db, cs):
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs,
                   analyst=lambda case, d, at: "benign")
    case = _open_case(loop, cs)
    loop.process_host_event(_proc(T + timedelta(hours=5), "C:\\x\\a.exe", rid=2), T + timedelta(hours=5))
    c = cs.case(case["case_id"])
    assert (c["review_status"], c["verdict"], c["claimed_by"]) == ("closed", "benign", "oracle")
    (cmd,) = cs.commands(case["case_id"])
    assert cmd["actor"] == "analyst:oracle" and cmd["at"] == "2025-01-06T14:00:00.000000Z"       # T + 4 h
    assert _learned(db) == "analyst"
    assert [v for _, _, v in loop.verdicts] == ["benign"]


def test_apply_verdict_guards(db):
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END)
    with pytest.raises(ValueError):
        loop.apply_verdict("case-1", "needs_info", "alice", T)
    assert loop.apply_verdict("case-404", "benign", "alice", T) == {
        "applied": False, "reason": "case is not awaiting a verdict in this loop"}


def test_a_closed_case_takes_no_second_verdict(db, cs):
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs)
    case = _open_case(loop, cs)
    cs.submit_verdict(case["case_id"], "benign", "alice", T)
    with pytest.raises(ReviewError):
        cs.submit_verdict(case["case_id"], "malicious", "bob", T)
