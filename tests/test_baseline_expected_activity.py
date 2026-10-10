"""
Phase 4 step 4.0 (2026-10-11): paths made only of the account's normal access
are logged as expected activity; privileged accounts and critical hosts are
never auto-approved.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from perception.action_playbook import (
    PlaybookExecutionStatus,
    build_candidate_actions,
    build_playbook,
    evaluate_guardrails,
    execute_playbook_dry_run,
)
from perception.enterprise_model import INVENTORY
from perception.entity_binding import attach_alert_context
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import NCEHypothesis
from perception.nce_rsem_integration import rank_validated_hypotheses
from perception.nce_sse_integration import validate_hypothesis_with_sse
from perception.outcome import LOW_PRIORITY, decide
from perception.sse import StructuralSimulationEngine

USER = next(a for a in INVENTORY.by_role("standard_user") if not a.local_admin)
HD = INVENTORY.by_role("helpdesk_admin")[0]
ALERT = {"source_user": USER.account_id, "source_host": USER.home_host, "target_host": USER.home_host}


@pytest.fixture(autouse=True)
def _tmp_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("perception.action_playbook.AUDIT_LOG_PATH", tmp_path / "audit.jsonl")


def _playbook(tech, acct, src, tgt, alert=ALERT, with_graph=True):
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    h = NCEHypothesis(technique_id=tech, source_account=acct, source_host=src, target_host=tgt,
                      nce_confidence=0.7, supporting_evidence_refs=["raw_log_line"])
    h = attach_alert_context([h], alert)[0]
    vh = validate_hypothesis_with_sse(h, sse)
    rhr = rank_validated_hypotheses([vh], kg, sse, build_candidate_actions(h)).ranked[0]
    return kg, evaluate_guardrails(build_playbook(rhr, kg), kg if with_graph else None)


def test_own_device_valid_account_is_logged_not_acted_on():
    kg, pb = _playbook("T1078", USER.account_id, USER.home_host, USER.home_host)
    assert pb.overall_status == PlaybookExecutionStatus.LOGGED_EXPECTED_ACTIVITY
    assert "expected activity" in pb.guardrail_decision_reason
    assert execute_playbook_dry_run(pb, kg).dry_run_report.startswith("REFUSED")
    assert decide(ALERT, [pb.overall_status.value], kg).label == LOW_PRIORITY


def test_department_share_is_baseline():
    share = next(g.host_id for g in INVENTORY.grants
                 if g.principal == f"account:{USER.account_id}" and g.host_id.startswith("SRV-FILE"))
    alert = {**ALERT, "target_host": share}
    _, pb = _playbook("T1078", USER.account_id, USER.home_host, share, alert)
    assert pb.overall_status == PlaybookExecutionStatus.LOGGED_EXPECTED_ACTIVITY


def test_without_graph_store_previous_behaviour():
    _, pb = _playbook("T1078", USER.account_id, USER.home_host, USER.home_host, with_graph=False)
    assert pb.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW


def test_steered_entity_is_never_baseline():
    steered = INVENTORY.by_role("domain_admin")[0].account_id
    _, pb = _playbook("T1078", steered, USER.home_host, "SRV-DC01")
    assert pb.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW


def test_group_mediated_admin_is_not_baseline_and_privileged_needs_review():
    alert = {"source_user": HD.account_id, "source_host": USER.home_host, "target_host": USER.home_host}
    _, pb = _playbook("T1550", HD.account_id, USER.home_host, USER.home_host, alert)
    assert pb.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
    assert "privileged account" in pb.guardrail_decision_reason


def test_privileged_restrict_never_auto_approved():
    svc = INVENTORY.account("svc_sql")
    alert = {"source_user": svc.account_id, "source_host": svc.home_host, "target_host": svc.home_host}
    _, pb = _playbook("T1078", svc.account_id, svc.home_host, svc.home_host, alert)
    assert pb.overall_status != PlaybookExecutionStatus.AUTO_APPROVED
