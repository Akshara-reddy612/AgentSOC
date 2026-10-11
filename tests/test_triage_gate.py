"""
Design step S6 (2026-10-11): triage gate — escalation rules first, learned
patterns -> LOW_PRIORITY without pipeline or LLM, decision cache keyed on the
store's view of the endpoints, NCE behind a daily budget, policy for
unreasoned novel cases (open decision D7).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from dedale.environment import DEDALE_PROFILE, seed_store
from dedale.suricata import to_alert
from perception.case_builder import Case, network_case_key
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_graph import destination_node_id, host_node_id
from perception.knowledge_updater import KnowledgeUpdater
from perception.nce_contract import NCEHypothesis
from perception.network_alert import with_entities
from perception.source_systems import SourceSystem
from perception.triage_gate import DailyBudget, TriageGate

T0 = datetime(2025, 1, 6, 9, 0, tzinfo=timezone.utc)
EXT = "172.19.0.77"


@pytest.fixture()
def db(tmp_path):
    with KnowledgeDB(tmp_path / "ks.sqlite", DEDALE_PROFILE, created_at=T0) as store:
        seed_store(store, T0)
        yield store


def _alert(db, src="172.16.1.3", dst="172.16.0.2", sid=2016922, port=445, n=1):
    line = (f"[1:{sid}:14] ET TROJAN Example [Classification: A Network Trojan was Detected] [Priority: 1] "
            f"{{TCP}} {src}:50000 -> {dst}:{port}")
    return with_entities(to_alert({"@timestamp": int(T0.timestamp() * 1000), "message": line}, n), db)


def _case(alert, n=1, at=T0):
    return Case(case_id=f"case-{n}", key=network_case_key(alert), opened=at, last_seen=at, first_alert=alert,
                closed=at + timedelta(hours=1), close_reason="idle")


def _learn(db, alert):
    KnowledgeUpdater(db).case_closed(_case(alert, 99, T0 - timedelta(days=7)), "NO_ACTIONABLE", training=True)


def test_novel_case_without_reasoning_goes_to_an_analyst(db):
    a = _alert(db)
    d = TriageGate(db).triage(_case(a), a, T0)
    assert (d.path, d.pipeline_outcome, d.outcome, d.nce) == ("pipeline", "NO_ACTIONABLE", "REVIEW", "disabled")
    d2 = TriageGate(db, unreasoned="no_actionable").triage(_case(a), a, T0)
    assert d2.outcome == "NO_ACTIONABLE"


def test_learned_pattern_is_low_priority_without_running_the_pipeline(db):
    a = _alert(db)
    _learn(db, a)
    d = TriageGate(db).triage(_case(a), a, T0)
    assert (d.path, d.outcome, d.pipeline_outcome, d.hypotheses) == ("baseline", "LOW_PRIORITY", None, [])


def reasoned_c2(alert):
    """Stand-in for NCE: names C2 from the alert's source host to its destination."""
    if not alert.get("destination_ip"):
        return []
    return [NCEHypothesis(technique_id="T1071", source_account="", source_host=alert["source_host"],
                          target_host=alert["destination_ip"], nce_confidence=0.7,
                          supporting_evidence_refs=["raw_log_line"])]


def test_outbound_to_unknown_destination_versus_routine_destination(db):
    a = _alert(db, dst=EXT, sid=2027262, port=80)
    d = TriageGate(db).triage(_case(a), a, T0)                    # telemetry alone: block proposed, not executed
    assert d.outcome == "REVIEW" and d.hypotheses[0]["top_action"] == "BLOCK_DESTINATION"
    assert d.hypotheses[0]["playbook_status"] == "PENDING_ANALYST_REVIEW"
    assert TriageGate(db, nce=reasoned_c2).triage(_case(a), a, T0).outcome == "AUTO_APPROVED"
    _learn(db, a)
    assert TriageGate(db).triage(_case(a, 2), a, T0).outcome == "LOW_PRIORITY"


def test_known_bad_destination_is_never_hidden_by_a_learned_pattern(db):
    a = _alert(db, dst=EXT, sid=2027262, port=80)
    _learn(db, a)
    db.set_fact(destination_node_id(EXT), "reputation", "known_bad", confidence=0.9,
                source=SourceSystem.KNOWLEDGE_STORE, writer="analyst:test", at=T0)
    d = TriageGate(db).triage(_case(a), a, T0)
    assert d.path == "pipeline" and d.outcome == "REVIEW"
    assert any("known-bad" in r for r in d.reasons)


def test_decision_cache_reuses_until_the_store_changes(db):
    gate = TriageGate(db)
    a = _alert(db)
    first = gate.triage(_case(a, 1), a, T0)
    again = gate.triage(_case(a, 2), a, T0 + timedelta(hours=2))
    assert again.path == "cache" and again.outcome == first.outcome
    db.set_fact(host_node_id("CLIENT2"), "criticality_tier", 2, confidence=1.0,
                source=SourceSystem.KNOWLEDGE_STORE, writer="analyst:test", at=T0 + timedelta(hours=3))
    assert gate.triage(_case(a, 3), a, T0 + timedelta(hours=4)).path == "pipeline"


def test_nce_budget_backlog_and_reuse(db):
    calls = []
    gate = TriageGate(db, nce=lambda alert: calls.append(alert["alert_id"]) or [], budget=DailyBudget(1))
    a, b = _alert(db, n=1), _alert(db, dst="172.16.0.3", sid=2000001, port=9200, n=2)
    assert gate.triage(_case(a, 1), a, T0).nce == "ran"
    d = gate.triage(_case(b, 2), b, T0 + timedelta(hours=1))
    assert d.nce == "budget_exhausted" and d.outcome == "REVIEW" and gate.backlog == 1
    assert gate.triage(_case(b, 3), b, T0 + timedelta(hours=2)).path == "cache"       # still no budget today
    next_day = gate.triage(_case(b, 4), b, T0 + timedelta(days=1))
    assert (next_day.path, next_day.nce) == ("pipeline", "ran") and len(calls) == 2


def test_watch_escalation_and_nce_failure(db):
    a = _alert(db)
    _learn(db, a)
    watched = TriageGate(db, watch=lambda alert, at: ["Entity under watch after an earlier response."])
    d = watched.triage(_case(a), a, T0)
    assert d.path == "pipeline" and d.outcome == "REVIEW" and d.reasons[0].startswith("Entity under watch")

    def broken(alert):
        raise RuntimeError("model unavailable")
    b = _alert(db, dst="172.16.0.3", sid=2000001, port=9200)
    gate = TriageGate(db, nce=broken)
    d = gate.triage(_case(b, 1), b, T0)
    assert (d.nce, d.outcome) == ("error", "REVIEW")
    assert gate.triage(_case(b, 2), b, T0).path == "pipeline"          # failures are not cached
