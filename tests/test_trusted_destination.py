"""
Phase 3 step 3.3 (2026-10-11): trusted destination telemetry reaches SSE and
RSEM, BLOCK_DESTINATION, and the known-bad-contact escalation.
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
from perception.knowledge_graph import KnowledgeStoreGraph, destination_node_id
from perception.nce_contract import NCEHypothesis
from perception.nce_rsem_integration import rank_validated_hypotheses
from perception.nce_sse_integration import validate_hypothesis_with_sse
from perception.network_model import SYNTHETIC_DESTINATIONS
from perception.outcome import NO_ACTIONABLE, REVIEW, AUTO_APPROVED, decide
from perception.rsem import ActionType
from perception.sse import SSEVerdict, StructuralSimulationEngine

USER = INVENTORY.by_role("standard_user")[0]
KNOWN_BAD = next(d["address"] for d in SYNTHETIC_DESTINATIONS if d["reputation"] == "known_bad" and d["kind"] == "domain")
SANCTIONED = next(d["address"] for d in SYNTHETIC_DESTINATIONS if d["reputation"] == "sanctioned" and d["kind"] == "domain")
UNKNOWN = "cdn123.example"


@pytest.fixture(autouse=True)
def _tmp_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("perception.action_playbook.AUDIT_LOG_PATH", tmp_path / "audit.jsonl")


def _alert(dest):
    return {"alert_id": "t", "source_user": USER.account_id, "source_host": USER.home_host,
            "target_host": USER.home_host, "destination_domain": dest, "destination_ip": "192.0.2.250"}


def _run(dest, nce_target=None):
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    h = NCEHypothesis(technique_id="T1071", source_account=USER.account_id, source_host=USER.home_host,
                      target_host=nce_target or dest, nce_confidence=0.7,
                      supporting_evidence_refs=["raw_log_line"], evidence_grounding="grounded")
    h = attach_alert_context([h], _alert(dest))[0]
    vh = validate_hypothesis_with_sse(h, sse)
    pb = None
    if vh.best_sse_verdict != SSEVerdict.INFEASIBLE:
        rhr = rank_validated_hypotheses([vh], kg, sse, build_candidate_actions(h)).ranked[0]
        pb = evaluate_guardrails(build_playbook(rhr, kg))
    return kg, h, vh, pb


def test_destination_attached_only_from_trusted_fields():
    _, h, vh, _ = _run(UNKNOWN)
    assert h.trusted_destination == UNKNOWN
    assert vh.sse_results[0].destination_status == "verified"


def test_unknown_destination_block_destination_auto_approved():
    kg, h, vh, pb = _run(UNKNOWN)
    assert vh.best_sse_verdict == SSEVerdict.FEASIBLE
    top = pb.hypothesis.ranked_actions[0]
    assert top.action.action_type == ActionType.BLOCK_DESTINATION
    assert top.containment == 1.0 and top.business_impact == pytest.approx(0.1)
    assert pb.overall_status == PlaybookExecutionStatus.AUTO_APPROVED
    done = execute_playbook_dry_run(pb, kg)
    assert done.overall_status == PlaybookExecutionStatus.DRY_RUN_COMPLETE
    assert destination_node_id(UNKNOWN) not in kg.graph          # live graph untouched
    assert decide(_alert(UNKNOWN), [done.overall_status.value], kg).label == AUTO_APPROVED


def test_sanctioned_destination_prefers_host_block_and_reviews():
    _, _, _, pb = _run(SANCTIONED)
    assert pb.hypothesis.ranked_actions[0].action.action_type == ActionType.BLOCK_EGRESS
    assert pb.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW


def test_known_bad_blocked_by_proxy_still_escalates():
    kg, _, vh, pb = _run(KNOWN_BAD)
    assert vh.best_sse_verdict == SSEVerdict.INFEASIBLE and pb is None
    out = decide(_alert(KNOWN_BAD), [], kg)
    assert out.label == REVIEW and "known-bad" in out.reasons[0]
    assert decide(_alert(None) | {"destination_ip": None}, [], kg).label == NO_ACTIONABLE


def test_spoofed_destination_in_text_is_unbound_and_block_targets_trusted_one():
    _, h, _, pb = _run(UNKNOWN, nce_target=SANCTIONED)
    assert h.entity_binding == "unbound"
    blocks = [a for a in build_candidate_actions(h) if a.action_type == ActionType.BLOCK_DESTINATION]
    assert [b.target_host_id for b in blocks] == [UNKNOWN]
    assert pb.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
