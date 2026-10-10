"""
Phase 2 step 2.7 (2026-10-10): entity binding of hypothesis entities against the
alert's structured entity fields, and the guardrail review reason for "unbound".
"""
from __future__ import annotations

from pathlib import Path

import pytest

from perception.action_playbook import (
    PlaybookExecutionStatus,
    build_playbook,
    evaluate_guardrails,
)
from perception.entity_binding import (
    BOUND,
    BOUND_OTHER_ROLE,
    UNBOUND,
    UNKNOWN,
    UNVERIFIABLE,
    bind_entities,
    label_entity_binding,
)
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import NCEHypothesis
from perception.nce_rsem_integration import rank_validated_hypotheses
from perception.nce_sse_integration import validate_hypothesis_with_sse
from perception.rsem import ActionType, ProposedAction
from perception.sse import StructuralSimulationEngine

ALERT = {"alert_id": "1", "source_user": "jsmith", "source_host": "LT-3357-CORP", "target_host": "SRV-FILE7412"}


def _h(tech="T1078", acct="jsmith", src="LT-3357-CORP", tgt="SRV-FILE7412"):
    return NCEHypothesis(technique_id=tech, source_account=acct, source_host=src, target_host=tgt,
                         nce_confidence=0.5, supporting_evidence_refs=["raw_log_line"])


def test_all_bound_with_normalisation():
    b = bind_entities(_h(acct=r"CORP\JSmith", src="lt-3357-corp.corp.local"), ALERT)
    assert b.roles == {"source_account": BOUND, "source_host": BOUND, "target_host": BOUND}
    assert b.summary == "bound"


def test_role_swap_is_bound_other_role():
    b = bind_entities(_h(src="SRV-FILE7412", tgt="LT-3357-CORP"), ALERT)
    assert b.roles["source_host"] == BOUND_OTHER_ROLE and b.summary == "bound"


def test_unknown_is_its_own_category():
    b = bind_entities(_h(src="unknown", tgt=""), ALERT)
    assert b.roles["source_host"] == UNKNOWN and b.roles["target_host"] == UNKNOWN
    assert b.summary == "partial"


def test_injected_identity_is_unbound():
    """Steering: free text names graph entities the telemetry never saw."""
    b = bind_entities(_h(acct="svc_backup", src="workstation-01", tgt="server-db01"), ALERT)
    assert set(b.roles.values()) == {UNBOUND}
    assert b.summary == "unbound" and len(b.notes) == 3


def test_t1071_external_destination_unverifiable_without_trusted_field():
    b = bind_entities(_h("T1071", tgt="203.0.113.9"), ALERT)
    assert b.roles["target_host"] == UNVERIFIABLE and b.summary == "partial"


def test_t1071_destination_checked_when_trusted_field_exists():
    alert = {**ALERT, "destination_ip": "203.0.113.9"}
    assert bind_entities(_h("T1071", tgt="203.0.113.9"), alert).roles["target_host"] == BOUND
    assert bind_entities(_h("T1071", tgt="198.51.100.7"), alert).roles["target_host"] == UNBOUND


def test_non_t1071_external_target_is_unbound():
    assert bind_entities(_h("T1078", tgt="203.0.113.9"), ALERT).roles["target_host"] == UNBOUND


def test_alert_without_entity_fields_is_unverifiable():
    b = bind_entities(_h(), {"alert_id": "2"})
    assert set(b.roles.values()) == {UNVERIFIABLE} and b.summary == "partial"


def test_label_sets_field_and_rejects_bad_value():
    out = label_entity_binding([_h(), _h(acct="svc_backup")], ALERT)
    assert [h.entity_binding for h in out] == ["bound", "unbound"]
    with pytest.raises(ValueError):
        NCEHypothesis(technique_id="T1078", source_account="a", source_host="b", target_host="c",
                      nce_confidence=0.5, supporting_evidence_refs=[], entity_binding="maybe")


def test_unbound_hypothesis_routes_to_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """svc_backup -> server-db01 is FEASIBLE in the seeded graph; RESTRICT alone would auto-approve."""
    monkeypatch.setattr("perception.action_playbook.AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    cands = [ProposedAction(ActionType.RESTRICT_PRIVILEGES, target_account_id="svc_backup")]
    results = {}
    for label in (None, "unbound"):
        h = label_entity_binding([_h("T1078", "svc_backup", "workstation-01", "server-db01")], ALERT)[0] if label else \
            _h("T1078", "svc_backup", "workstation-01", "server-db01")
        vh = validate_hypothesis_with_sse(h, sse)
        pb = evaluate_guardrails(build_playbook(rank_validated_hypotheses([vh], kg, sse, cands).ranked[0], kg))
        results[label] = pb
    assert results["unbound"].overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
    assert "identity steering" in results["unbound"].guardrail_decision_reason
    assert "identity steering" not in results[None].guardrail_decision_reason
