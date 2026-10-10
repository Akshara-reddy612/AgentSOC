"""
Phase 2 step 2.5 (2026-10-10): BLOCK_EGRESS gives T1071 real containment, the
shared candidate builder is technique-aware, and the guardrail routes ties,
ungrounded T1071 and CONDITIONALLY_FEASIBLE hypotheses to analyst review.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from perception.action_playbook import (
    HARD_FLOOR_ACTIONS,
    PlaybookExecutionStatus,
    build_candidate_actions,
    build_playbook,
    evaluate_guardrails,
)
from perception.knowledge_graph import KnowledgeStoreGraph, host_node_id
from perception.nce_contract import NCEHypothesis
from perception.nce_rsem_integration import rank_validated_hypotheses
from perception.nce_sse_integration import validate_hypothesis_with_sse
from perception.rsem import ActionType, ProposedAction, compute_business_impact, rank_actions
from perception.sse import StructuralSimulationEngine


@pytest.fixture(autouse=True)
def _tmp_audit_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("perception.action_playbook.AUDIT_LOG_PATH", tmp_path / "audit.jsonl")


def _hyp(technique="T1071", src="WKSTN-4520", tgt="203.0.113.9", account="m.chen", grounding=None):
    return NCEHypothesis(technique_id=technique, source_account=account, source_host=src,
                         target_host=tgt, nce_confidence=0.8, supporting_evidence_refs=["raw_log_line"],
                         evidence_grounding=grounding)


def _ranked(kg, sse, hyp):
    vh = validate_hypothesis_with_sse(hyp, sse)
    return rank_validated_hypotheses([vh], kg, sse, build_candidate_actions(hyp)).ranked[0]


def test_candidates_for_t1071_block_source_host_not_quarantine_target():
    acts = build_candidate_actions(_hyp())
    types = [a.action_type for a in acts]
    assert ActionType.BLOCK_EGRESS in types and ActionType.QUARANTINE_ACCESS not in types
    block = next(a for a in acts if a.action_type == ActionType.BLOCK_EGRESS)
    assert block.target_host_id == "WKSTN-4520"


def test_candidates_for_lateral_technique_quarantine_target():
    acts = build_candidate_actions(_hyp("T1550", "workstation-01", "server-db01", "svc_backup"))
    types = [a.action_type for a in acts]
    assert ActionType.QUARANTINE_ACCESS in types and ActionType.BLOCK_EGRESS not in types


def test_block_egress_contains_t1071_and_breaks_tie():
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    hyp = _hyp()
    ranked = rank_actions(kg, sse, build_candidate_actions(hyp), [hyp])
    top = ranked[0]
    assert top.action.action_type == ActionType.BLOCK_EGRESS
    assert top.containment == 1.0
    assert top.business_impact == pytest.approx(0.25)  # workstation-class host, tier 0
    assert top.composite_score > ranked[1].composite_score
    # Live graph untouched.
    assert host_node_id("WKSTN-4520") not in kg.graph


def test_business_impact_fallback_for_unknown_targets():
    kg = KnowledgeStoreGraph()
    assert compute_business_impact(kg, ProposedAction(ActionType.QUARANTINE_ACCESS, target_host_id="SRV-FILE77")) == pytest.approx(0.5)
    assert compute_business_impact(kg, ProposedAction(ActionType.QUARANTINE_ACCESS, target_host_id="203.0.113.9")) == 0.0


def test_block_egress_is_hard_floor():
    assert ActionType.BLOCK_EGRESS in HARD_FLOOR_ACTIONS
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    pb = evaluate_guardrails(build_playbook(_ranked(kg, sse, _hyp(grounding="grounded")), kg))
    assert pb.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
    assert "BLOCK_EGRESS" in pb.guardrail_decision_reason


def test_tie_at_top_routes_to_review():
    """Old harness candidate set (no BLOCK_EGRESS) ties at 0.0 -> must not auto-approve."""
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    hyp = _hyp(grounding="grounded")
    vh = validate_hypothesis_with_sse(hyp, sse)
    cands = [ProposedAction(ActionType.MONITOR_ONLY, target_account_id="m.chen"),
             ProposedAction(ActionType.RESTRICT_PRIVILEGES, target_account_id="m.chen")]
    ranked = rank_validated_hypotheses([vh], kg, sse, cands).ranked[0]
    pb = evaluate_guardrails(build_playbook(ranked, kg))
    assert pb.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
    assert "tie" in pb.guardrail_decision_reason.lower()


def test_ungrounded_t1071_never_auto_approved():
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    hyp = _hyp(grounding="ungrounded")
    vh = validate_hypothesis_with_sse(hyp, sse)
    ranked = rank_validated_hypotheses(
        [vh], kg, sse, [ProposedAction(ActionType.MONITOR_ONLY, target_account_id="m.chen")]
    ).ranked[0]
    pb = evaluate_guardrails(build_playbook(ranked, kg))
    assert pb.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
    assert "ungrounded" in pb.guardrail_decision_reason


def test_unresolved_host_routes_to_review():
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    hyp = _hyp(src="unknown", grounding="grounded")
    vh = validate_hypothesis_with_sse(hyp, sse)
    ranked = rank_validated_hypotheses(
        [vh], kg, sse, [ProposedAction(ActionType.MONITOR_ONLY, target_account_id="m.chen")]
    ).ranked[0]
    pb = evaluate_guardrails(build_playbook(ranked, kg))
    assert pb.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
    assert "CONDITIONALLY_FEASIBLE" in pb.guardrail_decision_reason
