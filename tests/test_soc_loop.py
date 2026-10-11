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


def _run(tmp_path, mode):
    records = []
    db = KnowledgeDB(tmp_path / f"{mode}.sqlite", DEDALE_PROFILE, created_at=TRAIN_END - timedelta(days=14))
    seed_store(db, TRAIN_END - timedelta(days=14))
    loop = SocLoop(db, mode=mode, training_end=TRAIN_END,
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


def test_gated_run_decisions(tmp_path):
    _, loop, _, d = _run(tmp_path, "gated")
    assert (d[1].path, d[1].outcome) == ("baseline", "LOW_PRIORITY")
    assert (d[2].path, d[2].outcome) == ("baseline", "LOW_PRIORITY")          # routine DNS resolver: not blocked
    assert d[3].outcome == "AUTO_APPROVED" and d[3].hypotheses[0]["top_action"] == "BLOCK_DESTINATION"
    assert d[4].outcome == "REVIEW" and "under watch" in d[4].reasons[0]      # contained destination contacted again
    assert d[5].outcome == "REVIEW"                                            # novel, not reasoned about (NCE off)
    assert [w.would_block for w in loop.monitor.finished] == [1]


def test_static_store_blocks_a_routine_destination_and_reviews_routine_traffic(tmp_path):
    """A client (criticality 0) contacting the resolver; in the real data that DNS comes from forwarders."""
    _, _, _, d = _run(tmp_path, "static")
    assert d[1].outcome == "REVIEW"
    assert d[2].outcome == "AUTO_APPROVED" and d[2].hypotheses[0]["top_action"] == "BLOCK_DESTINATION"


@pytest.mark.parametrize("mode, expected", [("frozen", 1), ("gated", 2)])
def test_learning_continues_only_when_not_frozen(tmp_path, mode, expected):
    db, loop, _, _ = _run(tmp_path, mode)
    resolver_pattern = db.edge_attrs(host_node_id("CLIENT3"), destination_node_id(RESOLVER), "sid:2")
    assert resolver_pattern["case_count"] == expected
    if mode == "gated":   # P shares CLIENT2 with the escalated outbound case, so its update is dropped
        assert loop.updater.dropped == 1
