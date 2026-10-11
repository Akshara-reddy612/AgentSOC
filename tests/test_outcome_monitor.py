"""
Design step S7 (2026-10-11): outcome monitor — watches the targets of
auto-approved responses, counts what the (dry-run) response would have
stopped, escalates new activity on contained targets, and writes the result
back to the Knowledge Store.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from dedale.environment import DEDALE_PROFILE, seed_store
from dedale.suricata import to_alert
from perception.case_builder import Case, network_case_key
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_graph import destination_node_id
from perception.nce_contract import NCEHypothesis
from perception.network_alert import with_entities
from perception.outcome_monitor import OutcomeMonitor
from perception.triage_gate import Decision, TriageGate

T0 = datetime(2025, 1, 6, 10, 0, tzinfo=timezone.utc)
EXT, OTHER = "172.19.0.77", "172.19.0.88"


@pytest.fixture()
def db(tmp_path):
    with KnowledgeDB(tmp_path / "ks.sqlite", DEDALE_PROFILE, created_at=T0) as store:
        seed_store(store, T0)
        yield store


def _alert(db, src="172.16.1.3", dst=EXT, port=80, sid=2027262, n=1):
    line = (f"[1:{sid}:3] ET INFO Example [Classification: Potentially Bad Traffic] [Priority: 2] "
            f"{{TCP}} {src}:50000 -> {dst}:{port}")
    return with_entities(to_alert({"@timestamp": int(T0.timestamp() * 1000), "message": line}, n), db)


def _reasoned_c2(alert):
    return [NCEHypothesis(technique_id="T1071", source_account="", source_host=alert["source_host"],
                          target_host=alert["destination_ip"], nce_confidence=0.7,
                          supporting_evidence_refs=["raw_log_line"])]


def _blocked(db):
    """A reasoned C2 case whose BLOCK_DESTINATION is auto-approved (telemetry alone would go to review)."""
    a = _alert(db)
    case = Case("case-1", network_case_key(a), T0, T0, a)
    decision = TriageGate(db, nce=_reasoned_c2).triage(case, a, T0)
    assert decision.outcome == "AUTO_APPROVED"
    monitor = OutcomeMonitor(db)
    return monitor, monitor.register(decision, T0)


def test_auto_approved_block_starts_a_watch_and_is_written_back(db):
    _, watches = _blocked(db)
    assert [(w.action, w.target, w.target_kind) for w in watches] == [("BLOCK_DESTINATION", EXT, "destination")]
    fact = db.graph.graph.nodes[destination_node_id(EXT)]["response"]
    assert fact.value["mode"] == "simulated" and fact.value["status"] == "active"
    assert db.graph.get_destination_reputation(EXT)[0] == "unknown"        # observed facts untouched


def test_later_alerts_are_counted_and_new_cases_escalated(db):
    monitor, (w,) = _blocked(db)
    monitor.observe(_alert(db, n=2), T0 + timedelta(hours=1))                      # would have been blocked
    monitor.observe(_alert(db, dst=OTHER, n=3), T0 + timedelta(hours=1))           # another destination
    monitor.observe(_alert(db, dst="172.16.0.3", port=9200, n=4), T0 + timedelta(hours=1))
    assert (w.hits, w.would_block) == (1, 1)
    gate = TriageGate(db, watch=monitor.reasons)
    a = _alert(db, sid=2000002, n=5)
    d = gate.triage(Case("case-2", network_case_key(a), T0, T0, a), a, T0 + timedelta(hours=2))
    assert d.outcome == "REVIEW" and "under watch" in d.reasons[0]


def test_watch_ends_and_records_its_result(db):
    monitor, (w,) = _blocked(db)
    monitor.observe(_alert(db, n=2), T0 + timedelta(days=1))
    assert monitor.advance(T0 + timedelta(days=7)) == [w]
    value = db.graph.graph.nodes[destination_node_id(EXT)]["response"].value
    assert (value["status"], value["hits"], value["would_block"]) == ("ended", 1, 1)
    assert monitor.reasons(_alert(db, n=3), T0 + timedelta(days=8)) == []


def test_investigation_flag_escalates_only_new_activity_of_the_host(db):
    from perception.case_builder import Case as _Case
    from perception.knowledge_updater import KnowledgeUpdater
    routine = _alert(db, dst="172.16.0.3", port=9200, sid=2017515, n=2)
    KnowledgeUpdater(db).case_closed(_Case("case-0", network_case_key(routine), T0 - timedelta(days=7),
                                           T0 - timedelta(days=7), routine, closed=T0 - timedelta(days=6)),
                                     "NO_ACTIONABLE", training=True)
    monitor = OutcomeMonitor(db)
    monitor.flag_host("CLIENT2", "case-5", T0)
    assert monitor.reasons(routine, T0 + timedelta(hours=1)) == []                       # learned routine
    novel = _alert(db, dst="172.16.0.2", port=445, sid=2025699, n=3)
    assert monitor.reasons(novel, T0 + timedelta(hours=1))[0].startswith("Host CLIENT2 is under watch")


def test_only_executed_responses_are_watched(db):
    monitor = OutcomeMonitor(db)
    row = {"top_action": "BLOCK_DESTINATION", "playbook_status": "AUTO_APPROVED", "top_target_host": EXT}
    review = Decision("case-9", T0, "pipeline", "REVIEW", "AUTO_APPROVED", ["escalated"], "disabled", [row])
    assert monitor.register(review, T0) == []


def test_host_egress_block_semantics(db):
    monitor = OutcomeMonitor(db)
    row = {"top_action": "BLOCK_EGRESS", "playbook_status": "AUTO_APPROVED", "top_target_host": "CLIENT2"}
    (w,) = monitor.register(Decision("case-7", T0, "pipeline", "AUTO_APPROVED", "AUTO_APPROVED", [], "ran", [row]),
                            T0)
    monitor.observe(_alert(db, dst=OTHER, n=2), T0 + timedelta(hours=1))                  # outbound: stopped
    monitor.observe(_alert(db, dst="172.16.0.3", port=9200, n=3), T0 + timedelta(hours=1))  # internal: not
    assert (w.hits, w.would_block) == (2, 1)
    assert monitor.finish(T0 + timedelta(days=2)) == [w] and w in monitor.finished
