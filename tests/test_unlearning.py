"""
Decision B5 (a), 2026-10-11: a host confirmed compromised gets the patterns
learned on it recently retracted (they alert again), and while it stays
confirmed a benign verdict on it is not learned.  The retraction is a logged
store operation, so every earlier state can still be rebuilt.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from dedale.environment import DEDALE_PROFILE, seed_store
from perception.case_store import CaseStore, ReviewError
from perception.host_detection import DETECTORS, image_node_id, learn_key
from perception.knowledge_db import KnowledgeDB, graph_signature
from perception.knowledge_updater import KnowledgeUpdater
from perception.soc_loop import SocLoop

TRAIN_END = datetime(2025, 1, 6, tzinfo=timezone.utc)
T = TRAIN_END + timedelta(hours=10)
EXPLORER = "C:\\Windows\\explorer.exe"


def _proc(t, image, host="CLIENT2", rid=1):
    return {"t": t.isoformat().replace("+00:00", "Z"), "host": host, "rid": rid, "ch": "sysmon", "code": 1,
            "image": image, "parent_image": EXPLORER, "cmd": "x", "user": "BREACH\\client2"}


def _edge(image, host="CLIENT2"):
    return image_node_id(EXPLORER), image_node_id(image), f"host:{host.lower()}"


@pytest.fixture()
def db(tmp_path):
    with KnowledgeDB(tmp_path / "ks.sqlite", DEDALE_PROFILE, created_at=TRAIN_END - timedelta(days=14)) as store:
        seed_store(store, TRAIN_END - timedelta(days=14))
        yield store


@pytest.fixture()
def cs(tmp_path):
    with CaseStore(tmp_path / "cases.sqlite", created_at=TRAIN_END) as store:
        yield store


def test_retract_edge_is_logged_and_replayable(db):
    key = DETECTORS["lineage"].key(_proc(T, "C:\\x\\tool.exe"))
    learn_key(db, "lineage", key, provenance="analyst", at=T, writer="analyst:alice")
    before = graph_signature(db.graph.graph)
    seq = db.last_seq()
    db.retract_edge(*_edge("C:\\x\\tool.exe"), writer="updater", at=T + timedelta(hours=1), reason="test")
    assert not db.graph.graph.has_edge(*_edge("C:\\x\\tool.exe"))
    assert graph_signature(db.replay_log()) == graph_signature(db.graph.graph)          # the log rebuilds now
    assert graph_signature(db.replay_log(upto_seq=seq)) == before                        # ... and before
    assert db.projection_matches_store()
    with pytest.raises(KeyError):
        db.retract_edge(*_edge("C:\\x\\tool.exe"), writer="updater", at=T, reason="again")
    (src, dst, k, _), = [(u, v, k, d) for u, v, k, d in db.graph.graph.edges(keys=True, data=True)
                         if d.get("edge_type") == "HOSTED_IN"][:1]
    with pytest.raises(ValueError, match="configuration"):
        db.retract_edge(src, dst, k, writer="updater", at=T, reason="no")


def test_retract_host_learning_scope(db):
    up = KnowledgeUpdater(db)
    for image, prov, at, host in (("C:\\x\\old.exe", "training", T - timedelta(days=3), "CLIENT2"),
                                  ("C:\\x\\early.exe", "analyst", T - timedelta(days=9), "CLIENT2"),
                                  ("C:\\x\\a.exe", "analyst", T, "CLIENT2"),
                                  ("C:\\x\\b.exe", "closed_benign", T + timedelta(hours=1), "CLIENT2"),
                                  ("C:\\x\\c.exe", "analyst", T, "CLIENT9")):
        learn_key(db, "lineage", DETECTORS["lineage"].key(_proc(at, image, host)), provenance=prov, at=at,
                  writer="test")
    gone = up.retract_host_learning("CLIENT2", T - timedelta(days=7), T + timedelta(hours=2), "analyst:bob")
    assert sorted(g["src"] for g in gone) == [image_node_id(EXPLORER)] * 2 and len(gone) == 2
    g = db.graph.graph
    assert not g.has_edge(*_edge("C:\\x\\a.exe")) and not g.has_edge(*_edge("C:\\x\\b.exe"))
    assert g.has_edge(*_edge("C:\\x\\old.exe"))                       # training: kept
    assert g.has_edge(*_edge("C:\\x\\early.exe"))                     # before the window: kept
    assert g.has_edge(*_edge("C:\\x\\c.exe", "CLIENT9"))              # other host: kept


def _loop(db, cs, **kw):
    return SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs, **kw)


def _case_for(cs, image):
    name = image.split("\\")[-1].lower()
    return [c for c in cs.cases() if c["title"] == f"explorer.exe starting {name} on CLIENT2"][-1]


def test_a_confirmed_host_unlearns_and_learns_nothing_new(db, cs):
    loop = _loop(db, cs)
    loop.process_host_event(_proc(T, "C:\\x\\dropper.exe"), T)
    cs.submit_verdict(_case_for(cs, "C:\\x\\dropper.exe")["case_id"], "benign", "alice", T + timedelta(minutes=5))
    loop.process_host_event(_proc(T + timedelta(hours=1), "C:\\x\\beacon.exe", rid=2), T + timedelta(hours=1))
    assert db.edge_learned_from(*_edge("C:\\x\\dropper.exe")) == "analyst"              # the missed attack
    cs.submit_verdict(_case_for(cs, "C:\\x\\beacon.exe")["case_id"], "malicious", "bob", T + timedelta(hours=2))
    loop.process_host_event(_proc(T + timedelta(hours=3), "C:\\x\\c2.exe", rid=3), T + timedelta(hours=3))
    result = cs.commands(_case_for(cs, "C:\\x\\beacon.exe")["case_id"])[0]["result"]
    assert result["flagged_host"] == "CLIENT2" and len(result["retracted"]) == 1
    assert db.edge_learned_from(*_edge("C:\\x\\dropper.exe")) is None                  # retracted
    cs.submit_verdict(_case_for(cs, "C:\\x\\c2.exe")["case_id"], "benign", "carol", T + timedelta(hours=4))
    loop.process_host_event(_proc(T + timedelta(hours=5), "C:\\x\\dropper.exe", rid=4), T + timedelta(hours=5))
    assert db.edge_learned_from(*_edge("C:\\x\\c2.exe")) is None                       # not learned on the host
    c2 = cs.commands(_case_for(cs, "C:\\x\\c2.exe")["case_id"])[0]["result"]
    assert c2["learned"] is False and "confirmed compromised" in c2["reason"]
    assert _case_for(cs, "C:\\x\\dropper.exe")["opened"].startswith("2025-01-06T15:00")   # dropper alerts again


def test_policy_can_be_switched_off(db, cs):
    loop = _loop(db, cs, unlearn_on_confirm=False)
    loop.process_host_event(_proc(T, "C:\\x\\dropper.exe"), T)
    cs.submit_verdict(_case_for(cs, "C:\\x\\dropper.exe")["case_id"], "benign", "alice", T + timedelta(minutes=5))
    loop.process_host_event(_proc(T + timedelta(hours=1), "C:\\x\\beacon.exe", rid=2), T + timedelta(hours=1))
    cs.submit_verdict(_case_for(cs, "C:\\x\\beacon.exe")["case_id"], "malicious", "bob", T + timedelta(hours=2))
    loop.process_host_event(_proc(T + timedelta(hours=3), "C:\\x\\c2.exe", rid=3), T + timedelta(hours=3))
    assert db.edge_learned_from(*_edge("C:\\x\\dropper.exe")) == "analyst"


def test_withdrawing_a_wrong_malicious_verdict_undoes_its_effects(db, cs):
    loop = _loop(db, cs)
    loop.process_host_event(_proc(T, "C:\\x\\backup.exe"), T)
    cs.submit_verdict(_case_for(cs, "C:\\x\\backup.exe")["case_id"], "benign", "alice", T + timedelta(minutes=5))
    loop.process_host_event(_proc(T + timedelta(hours=1), "C:\\x\\admin_tool.exe", rid=2), T + timedelta(hours=1))
    assert db.edge_learned_from(*_edge("C:\\x\\backup.exe")) == "analyst"
    tool = _case_for(cs, "C:\\x\\admin_tool.exe")["case_id"]
    cs.submit_verdict(tool, "malicious", "bob", T + timedelta(hours=2))          # a false alarm
    loop.process_host_event(_proc(T + timedelta(hours=3), "C:\\x\\c.exe", rid=3), T + timedelta(hours=3))
    assert db.edge_learned_from(*_edge("C:\\x\\backup.exe")) is None            # retracted by the confirmation
    assert loop.monitor.host_confirmed("CLIENT2", T + timedelta(hours=3))

    with pytest.raises(ReviewError, match="reason"):
        cs.withdraw_verdict(tool, "lena", T + timedelta(hours=4), " ")
    cs.withdraw_verdict(tool, "lena", T + timedelta(hours=4), "admin tool, change ticket 1182")
    assert cs.case(tool)["review_status"] == "open" and cs.case(tool)["verdict"] is None
    loop.process_host_event(_proc(T + timedelta(hours=5), "C:\\x\\d.exe", rid=4), T + timedelta(hours=5))
    result = [c for c in cs.commands(tool) if c["kind"] == "withdraw"][0]["result"]
    assert result["applied"] and result["restored"] == 1 and len(result["ended_watches"]) == 1
    assert db.edge_learned_from(*_edge("C:\\x\\backup.exe")) == "analyst"      # restored, original provenance
    assert not loop.monitor.host_confirmed("CLIENT2", T + timedelta(hours=5))   # learning on the host resumes
    assert graph_signature(db.replay_log()) == graph_signature(db.graph.graph)     # still rebuildable from the log
    cs.submit_verdict(tool, "benign", "lena", T + timedelta(hours=6))            # re-review
    loop.process_host_event(_proc(T + timedelta(hours=7), "C:\\x\\e.exe", rid=5), T + timedelta(hours=7))
    assert db.edge_learned_from(*_edge("C:\\x\\admin_tool.exe")) == "analyst"
    with pytest.raises(ReviewError, match="no 'malicious' verdict"):
        cs.withdraw_verdict(tool, "lena", T + timedelta(hours=8), "again")
