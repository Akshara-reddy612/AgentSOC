"""
Design step S8 (2026-10-11): the store-backed SOC loop over a time-ordered
stream — shadow learning in the training window, triage afterwards, learning
modes static / frozen / gated / ungated.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from dedale.environment import DEDALE_PROFILE, seed_store
from dedale.suricata import to_alert
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_graph import destination_node_id, host_node_id
from perception.nce_contract import NCEHypothesis
from perception.soc_loop import SocLoop

TRAIN_END = datetime(2025, 1, 6, tzinfo=timezone.utc)
RESOLVER = "172.18.0.1"


def _alert(at: datetime, src: str, dst: str, port: int, sid: int, n: int) -> dict:
    line = (f"[1:{sid}:1] ET INFO Example {sid} [Classification: Misc activity] [Priority: 3] "
            f"{{TCP}} {src}:40000 -> {dst}:{port}")
    return to_alert({"@timestamp": int(at.timestamp() * 1000), "logsource": "companyrouter2", "message": line}, n)


def _stream():
    d_train, d_test = datetime(2024, 12, 30, tzinfo=timezone.utc), TRAIN_END
    items = [
        (d_train + timedelta(hours=10), "172.16.1.3", "172.16.0.3", 9200, 1),            # P (training)
        (d_train + timedelta(hours=10, minutes=5), "172.16.1.3", "172.16.0.3", 9200, 1),
        (d_train + timedelta(hours=11), "172.16.1.4", RESOLVER, 53, 2),                    # R (training)
        (d_test + timedelta(hours=9), "172.16.1.3", "172.16.0.3", 9200, 1),                # P (test)
        (d_test + timedelta(hours=9, minutes=10), "172.16.1.4", RESOLVER, 53, 2),          # R (test)
        (d_test + timedelta(hours=10, minutes=30), "172.16.1.3", "172.19.0.77", 80, 3),    # N: novel outbound
        (d_test + timedelta(hours=11, minutes=45), "172.16.1.3", "172.19.0.77", 443, 4),   # N2: same destination
        (d_test + timedelta(days=1, hours=12), "172.16.1.5", "172.16.0.3", 9200, 5),       # later: releases the gate
    ]
    return [_alert(at, s, d, p, sid, i) for i, (at, s, d, p, sid) in enumerate(items, 1)]


def _reasoned_c2(alert):
    """Stand-in for NCE: names C2 for every outbound alert."""
    if not alert.get("destination_ip"):
        return []
    return [NCEHypothesis(technique_id="T1071", source_account="", source_host=alert["source_host"],
                          target_host=alert["destination_ip"], nce_confidence=0.7,
                          supporting_evidence_refs=["raw_log_line"])]


def _run(tmp_path, mode, nce=None):
    records = []
    db = KnowledgeDB(tmp_path / f"{mode}.sqlite", DEDALE_PROFILE, created_at=TRAIN_END - timedelta(days=14))
    seed_store(db, TRAIN_END - timedelta(days=14))
    loop = SocLoop(db, mode=mode, training_end=TRAIN_END, gate_options={"nce": nce},
                   on_case=lambda case, d, training: records.append((case, d, training)))
    last = None
    for a in _stream():
        last = datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00"))
        loop.process(a, last)
    loop.finish(last)
    by_sid = {}
    for case, d, training in records:
        if not training:
            by_sid.setdefault(case.first_alert["signature_id"], d)
    return db, loop, records, by_sid


def test_training_is_shadow_and_learned(tmp_path):
    db, loop, records, _ = _run(tmp_path, "gated")
    training = [(c, d) for c, d, t in records if t]
    assert len(training) == 2 and all(d is None for _, d in training)
    assert {c.close_reason for c, _ in training} == {"end_of_training"}
    assert loop.counts["cases_training"] == 2 and loop.counts["cases_test"] == 5
    assert db.edge_learned_from(host_node_id("CLIENT2"), host_node_id("logserver"), "sid:1") == "training"


def test_gated_run_decisions_without_reasoning(tmp_path):
    _, loop, _, d = _run(tmp_path, "gated")
    assert (d[1].path, d[1].outcome) == ("baseline", "LOW_PRIORITY")
    assert (d[2].path, d[2].outcome) == ("baseline", "LOW_PRIORITY")          # routine DNS resolver: not blocked
    assert d[3].outcome == "REVIEW" and d[3].hypotheses[0]["top_action"] == "BLOCK_DESTINATION"
    assert "telemetry alone" in d[3].hypotheses[0]["guardrail_reason"]       # proposed, not executed (policy)
    assert d[5].outcome == "REVIEW"                                            # novel, not reasoned about (NCE off)
    assert loop.monitor.finished == []                                         # nothing was executed


def test_reasoned_c2_is_contained_and_watched(tmp_path):
    _, loop, _, d = _run(tmp_path, "gated", nce=_reasoned_c2)
    assert d[3].outcome == "AUTO_APPROVED" and d[3].hypotheses[0]["top_action"] == "BLOCK_DESTINATION"
    assert d[4].outcome == "REVIEW" and "under watch" in d[4].reasons[0]      # contained destination contacted again
    assert [w.would_block for w in loop.monitor.finished] == [1]


def test_static_store_reviews_routine_traffic_and_does_not_block_on_telemetry_alone(tmp_path):
    _, _, _, d = _run(tmp_path, "static")
    assert d[1].outcome == "REVIEW"
    assert d[2].outcome == "REVIEW" and d[2].hypotheses[0]["playbook_status"] == "PENDING_ANALYST_REVIEW"


def test_analyst_verdicts_teach_the_store(tmp_path):
    """Benign verdict -> the pattern is learned (provenance analyst); malicious -> known-bad + approved block."""
    db = KnowledgeDB(tmp_path / "a.sqlite", DEDALE_PROFILE, created_at=TRAIN_END - timedelta(days=14))
    seed_store(db, TRAIN_END - timedelta(days=14))
    analyst = lambda case, d, at: "malicious" if case.first_alert["dst_ip"] == "172.19.0.77" else "benign"  # noqa: E731
    decisions = {}
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, analyst=analyst,
                   on_case=lambda case, d, training: decisions.setdefault(case.first_alert["alert_id"], d))
    day = TRAIN_END
    stream = [(day + timedelta(hours=9), "172.16.1.5", "172.16.0.3", 9200, 7),       # novel internal: REVIEW
              (day + timedelta(hours=10), "172.16.1.3", "172.19.0.77", 80, 8),        # telemetry C2: REVIEW
              (day + timedelta(days=1, hours=9), "172.16.1.5", "172.16.0.3", 9200, 7)]  # after the verdicts
    for i, (at, s, dst, port, sid) in enumerate(stream, 1):
        loop.process(_alert(at, s, dst, port, sid, i), at)
    loop.finish(day + timedelta(days=1, hours=10))
    assert [v for _, _, v in loop.verdicts] == ["benign", "malicious"]
    assert db.edge_learned_from(host_node_id("CLIENT4"), host_node_id("logserver"), "sid:7") == "analyst"
    assert decisions["dedale-suricata-3"].outcome == "LOW_PRIORITY"            # learned from the verdict
    assert db.graph.get_destination_reputation("172.19.0.77")[0] == "known_bad"
    assert sorted((w.action, w.target) for w in loop.monitor.finished) == [
        ("ANALYST_CONFIRMED", "CLIENT2"), ("BLOCK_DESTINATION", "172.19.0.77")]


@pytest.mark.parametrize("mode, expected", [("frozen", 1), ("gated", 2)])
def test_learning_continues_only_when_not_frozen(tmp_path, mode, expected):
    db, loop, _, _ = _run(tmp_path, mode)
    resolver_pattern = db.edge_attrs(host_node_id("CLIENT3"), destination_node_id(RESOLVER), "sid:2")
    assert resolver_pattern["case_count"] == expected
    if mode == "gated":   # P shares CLIENT2 with the escalated outbound case, so its update is dropped
        assert loop.updater.dropped == 1
