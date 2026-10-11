"""
Analyst review loop, step 4 (2026-10-11): proposed responses -- approval
(four-eyes, decision B4), rejection, execution by the loop (simulated, I5),
rollback; a verdict never executes containment by itself.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from dedale.environment import DEDALE_PROFILE, seed_store
from perception.case_builder import Case
from perception.case_store import CaseStore, ReviewError, approvals_needed
from perception.host_detection import DETECTORS, host_alert
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_graph import host_node_id
from perception.review_service import ReviewService
from perception.soc_loop import SocLoop
from perception.triage_gate import Decision

TRAIN_END = datetime(2025, 1, 6, tzinfo=timezone.utc)
T = TRAIN_END + timedelta(hours=10)
QUARANTINE_SERVER = {"technique_id": "T1021.004", "sse_verdict": "CONDITIONALLY_FEASIBLE",
                     "top_action": "QUARANTINE_ACCESS", "top_target_host": "internalserver",
                     "top_target_account": None, "playbook_status": "PENDING_ANALYST_REVIEW"}
QUARANTINE_CLIENT = dict(QUARANTINE_SERVER, top_target_host="CLIENT1")


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture()
def db(tmp_path):
    with KnowledgeDB(tmp_path / "ks.sqlite", DEDALE_PROFILE, created_at=TRAIN_END - timedelta(days=14)) as store:
        seed_store(store, TRAIN_END - timedelta(days=14))
        yield store


@pytest.fixture()
def cs(tmp_path):
    with CaseStore(tmp_path / "cases.sqlite", created_at=TRAIN_END) as store:
        yield store


def _event(t, rid=1, image="C:\\Windows\\System32\\OpenSSH\\scp.exe"):
    return {"t": t.isoformat().replace("+00:00", "Z"), "host": "CLIENT1", "rid": rid, "ch": "sysmon", "code": 1,
            "image": image, "parent_image": "C:\\Windows\\System32\\cmd.exe", "cmd": "scp x y",
            "user": "BREACH\\client1"}


def _record(db, cs, rows, n=1, outcome="REVIEW"):
    e = _event(T, rid=n)
    a = host_alert(e, "lineage", DETECTORS["lineage"].key(e), db)
    case = Case(f"m-{n}", ("host", "lineage", *a["detector_key"]), T, T, a)
    d = Decision(case.case_id, T, "pipeline", outcome, outcome, [], "ran", [dict(r) for r in rows], 1)
    cs.case_opened(case, a, T, d, approvals=lambda r: approvals_needed(db, r))
    return case


def _tick(loop, t, rid):
    loop.process_host_event(_event(t, rid=rid, image=f"C:\\x\\{rid}.exe"), t)


def test_one_approval_executes_through_the_loop(db, cs):
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs)
    _record(db, cs, [QUARANTINE_CLIENT])
    svc = ReviewService(cs, clock=Clock(T + timedelta(minutes=5)))
    (act,) = cs.actions("m-1")
    assert act["approvals_needed"] == 1
    cmd = svc.approve(act["action_id"], "alice")
    assert cmd is not None and cs.action(act["action_id"])["status"] == "approved"
    assert db.graph.graph.nodes[host_node_id("CLIENT1")].get("response") is None        # not executed yet
    _tick(loop, T + timedelta(minutes=10), 2)
    act = cs.action(act["action_id"])
    assert act["status"] == "executed" and act["watch_id"]
    response = db.graph.graph.nodes[host_node_id("CLIENT1")]["response"].value
    assert (response["action"], response["status"], response["mode"]) == ("QUARANTINE_ACCESS", "active", "simulated")


def test_four_eyes_needs_two_different_analysts(db, cs):
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs)
    _record(db, cs, [QUARANTINE_SERVER])
    svc = ReviewService(cs, clock=Clock(T + timedelta(minutes=5)))
    (act,) = cs.actions("m-1")
    assert act["approvals_needed"] == 2                                   # internalserver, tier 3
    assert svc.approve(act["action_id"], "alice") is None
    with pytest.raises(ReviewError, match="different analyst"):
        svc.approve(act["action_id"], "alice")
    _tick(loop, T + timedelta(minutes=10), 2)
    assert cs.action(act["action_id"])["status"] == "proposed"            # one approval is not enough
    assert svc.approve(act["action_id"], "bob") is not None
    _tick(loop, T + timedelta(minutes=20), 3)
    assert cs.action(act["action_id"])["status"] == "executed"
    approvals = [e["payload"]["approvals"] for e in cs.audit(case_id="m-1") if e["op"] == "action_approval"]
    assert approvals == ["1/2", "2/2"]


def test_reject_and_invalid_transitions(db, cs):
    _record(db, cs, [QUARANTINE_CLIENT])
    svc = ReviewService(cs, clock=Clock(T))
    (act,) = cs.actions("m-1")
    with pytest.raises(ReviewError, match="reason"):
        svc.reject(act["action_id"], "alice", "  ")
    svc.reject(act["action_id"], "alice", "business-critical laptop, monitor instead")
    with pytest.raises(ReviewError, match="rejected, not proposed"):
        svc.approve(act["action_id"], "bob")
    with pytest.raises(ReviewError, match="only an executed action"):
        svc.rollback(act["action_id"], "bob", "undo")
    with pytest.raises(ReviewError, match="no action"):
        svc.approve("m-1:a99", "bob")


def test_rollback_ends_the_watch(db, cs):
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs)
    _record(db, cs, [QUARANTINE_CLIENT])
    clock = Clock(T)
    svc = ReviewService(cs, clock=clock)
    (act,) = cs.actions("m-1")
    svc.approve(act["action_id"], "alice")
    _tick(loop, T + timedelta(minutes=1), 2)
    clock.t = T + timedelta(hours=1)
    svc.rollback(act["action_id"], "bob", "wrong host; the user was travelling")
    with pytest.raises(ReviewError):
        svc.rollback(act["action_id"], "bob", "again")                    # already requested
    _tick(loop, T + timedelta(hours=2), 3)
    act = cs.action(act["action_id"])
    assert act["status"] == "rolled_back"
    response = db.graph.graph.nodes[host_node_id("CLIENT1")]["response"].value
    assert response["status"] == "rolled_back" and response["until"] == T + timedelta(hours=1)
    loop.finish(T + timedelta(days=10))
    (w,) = [w for w in loop.monitor.finished if w.watch_id == act["watch_id"]]
    assert w.status == "rolled_back" and w.until == T + timedelta(hours=1)


def test_a_malicious_verdict_does_not_execute_containment(db, cs):
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs)
    loop.process_host_event(_event(T), T)                                  # a real REVIEW case via the loop
    (c,) = cs.cases()
    cs.submit_verdict(c["case_id"], "malicious", "alice", T + timedelta(minutes=5))
    _tick(loop, T + timedelta(minutes=10), 2)
    (cmd,) = cs.commands(c["case_id"])
    assert cmd["result"]["flagged_host"] == "CLIENT1" and "watches" not in cmd["result"]


def test_auto_approved_responses_are_recorded_with_their_watch(db, cs):
    auto = dict(QUARANTINE_CLIENT, playbook_status="AUTO_APPROVED")
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs)
    d = Decision("m-1", T, "pipeline", "AUTO_APPROVED", "AUTO_APPROVED", [], "ran", [auto], 1)
    started = loop.monitor.register(d, T)
    e = _event(T)
    a = host_alert(e, "lineage", DETECTORS["lineage"].key(e), db)
    cs.case_opened(Case("m-1", ("k",), T, T, a), a, T, d, watch_ids={0: started[0].watch_id})
    (act,) = cs.actions("m-1")
    assert (act["status"], act["approvals"], act["watch_id"]) == ("executed", ["auto"], started[0].watch_id)
    ReviewService(cs, clock=Clock(T)).rollback(act["action_id"], "alice", "false positive")
    _tick(loop, T + timedelta(minutes=1), 2)
    assert cs.action(act["action_id"])["status"] == "rolled_back"


def test_monitor_roll_back_guards(db):
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END)
    w = loop.monitor.start("m-1", "QUARANTINE_ACCESS", "CLIENT1", "host", T)
    assert loop.monitor.roll_back("watch-404", T) is None
    assert loop.monitor.roll_back(w.watch_id, T + timedelta(hours=1)) is w
    assert loop.monitor.roll_back(w.watch_id, T + timedelta(hours=2)) is None          # once
    assert loop.monitor.advance(T + timedelta(days=30)) == []                          # skipped at expiry
