"""
tests/test_rsem_seeded_scenarios.py

Formalized regression test suite for RSEM ranking and guardrail routing
across all MITRE ATT&CK techniques defined in Table I:
  - 6 non-T1071 techniques (T1078, T1021.001, T1021.002, T1550, T1484, T1562)
    evaluated on enterprise accounts with standing graph edges.
  - 1 explicit architectural tie regression test for T1071 (network egress).

Regression Guarantees:
  1. For every non-T1071 technique, standing graph edges make the hypothesis
     structurally FEASIBLE in SSE (unlike unseeded synthetic GUIDE alerts).
  2. For every non-T1071 technique, RSEM's top-ranked defensive action achieves
     a STRICTLY HIGHER composite score than MONITOR_ONLY (composite > 0.0000).
     This guarantees non-T1071 techniques do NOT suffer from tie-blindness.
  3. The top action triggers the correct deterministic guardrail outcome
     (AUTO_APPROVED vs PENDING_ANALYST_REVIEW).
  4. For T1071, MONITOR_ONLY, REVOKE_SESSION, and RESTRICT_PRIVILEGES strictly
     tie at composite = 0.0000, documenting the architectural limitation where
     identity actions cannot contain zone-level egress.
"""

import datetime
from pathlib import Path
import pytest

from perception.knowledge_graph import (
    KnowledgeStoreGraph,
    KnowledgeFact,
    SourceSystem,
)
from perception.sse import StructuralSimulationEngine, AccessLevel, SSEVerdict
from perception.nce_engine import NCEHypothesis, HypothesisStatus
from perception.nce_sse_integration import validate_hypothesis_with_sse
from perception.nce_rsem_integration import rank_validated_hypotheses
from perception.rsem import ProposedAction, ActionType, RiskWeights
from perception.action_playbook import (
    build_playbook,
    evaluate_guardrails,
    PlaybookExecutionStatus,
)


@pytest.fixture
def base_kg() -> KnowledgeStoreGraph:
    """Fresh baseline KnowledgeStoreGraph with default seeded enterprise topology."""
    return KnowledgeStoreGraph()


@pytest.fixture
def audit_log_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect action playbook audit log to tempfile."""
    tmp_log = tmp_path / "test_audit_log.jsonl"
    monkeypatch.setattr("perception.action_playbook.AUDIT_LOG_PATH", tmp_log)
    return tmp_log


# =========================================================================
# 1. T1078: Valid Accounts (Legitimate Credentials)
# =========================================================================

def test_t1078_valid_accounts_seeded(base_kg: KnowledgeStoreGraph, audit_log_path: Path):
    """
    T1078 requires HAS_PRIOR_ACCESS or GRANTS.
    account:alice has standing HAS_PRIOR_ACCESS and GRANTS(READ) on host:workstation-01.
    """
    sse = StructuralSimulationEngine(base_kg)
    hypothesis = NCEHypothesis(
        technique_id="T1078",
        source_account="alice",
        source_host="workstation-01",
        target_host="workstation-01",
        nce_confidence=0.85,
        supporting_evidence_refs=["raw_log_line"],
        status=HypothesisStatus.GENERATED,
    )

    # 1. SSE feasibility
    vh = validate_hypothesis_with_sse(hypothesis, sse)
    assert vh.best_sse_verdict == SSEVerdict.FEASIBLE

    # 2. RSEM ranking
    candidate_actions = [
        ProposedAction(action_type=ActionType.MONITOR_ONLY, target_account_id="alice"),
        ProposedAction(action_type=ActionType.REVOKE_SESSION, target_account_id="alice"),
        ProposedAction(action_type=ActionType.RESTRICT_PRIVILEGES, target_account_id="alice"),
        ProposedAction(action_type=ActionType.QUARANTINE_ACCESS, target_host_id="workstation-01"),
    ]
    pipeline_res = rank_validated_hypotheses([vh], base_kg, sse, candidate_actions, RiskWeights())
    ranked_hyp = pipeline_res.ranked[0]
    top_action = ranked_hyp.ranked_actions[0]
    monitor_action = next(
        sa for sa in ranked_hyp.ranked_actions
        if sa.action.action_type == ActionType.MONITOR_ONLY
    )

    # Assert top action strictly beats MONITOR_ONLY
    assert top_action.composite_score > monitor_action.composite_score
    assert top_action.containment > 0.0
    assert top_action.action.action_type in (ActionType.REVOKE_SESSION, ActionType.RESTRICT_PRIVILEGES)

    # 3. Guardrail outcome
    playbook = build_playbook(ranked_hyp, base_kg)
    guarded = evaluate_guardrails(playbook)
    # REVOKE_SESSION is in the hard-floor review set
    assert guarded.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
    assert "hard floor rule" in guarded.guardrail_decision_reason.lower()


# =========================================================================
# 2. T1021.001: Remote Desktop Protocol (RDP Lateral Movement)
# =========================================================================

def test_t1021_001_rdp_lateral_movement_seeded(base_kg: KnowledgeStoreGraph, audit_log_path: Path):
    """
    T1021.001 requires GRANTS(min_access_level=RDP) AND zone egress on port 3389.
    zone:WEB -> zone:DATABASE allows port 3389 (RDP).
    We seed GRANTS(AccessLevel.RDP) from svc_backup to server-db01.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    base_kg.graph.add_edge(
        "account:svc_backup",
        "host:server-db01",
        edge_type="GRANTS",
        access_level=KnowledgeFact(
            value=AccessLevel.RDP,
            version=1,
            confidence=1.0,
            source=SourceSystem.KNOWLEDGE_STORE,
            timestamp=now,
            audit_history=[],
        ),
    )

    sse = StructuralSimulationEngine(base_kg)
    hypothesis = NCEHypothesis(
        technique_id="T1021.001",
        source_account="svc_backup",
        source_host="server-web01",
        target_host="server-db01",
        nce_confidence=0.85,
        supporting_evidence_refs=["raw_log_line"],
        status=HypothesisStatus.GENERATED,
    )

    # 1. SSE feasibility
    vh = validate_hypothesis_with_sse(hypothesis, sse)
    assert vh.best_sse_verdict == SSEVerdict.FEASIBLE

    # 2. RSEM ranking
    candidate_actions = [
        ProposedAction(action_type=ActionType.MONITOR_ONLY, target_account_id="svc_backup"),
        ProposedAction(action_type=ActionType.REVOKE_SESSION, target_account_id="svc_backup"),
        ProposedAction(action_type=ActionType.RESTRICT_PRIVILEGES, target_account_id="svc_backup"),
        ProposedAction(action_type=ActionType.QUARANTINE_ACCESS, target_host_id="server-db01"),
    ]
    pipeline_res = rank_validated_hypotheses([vh], base_kg, sse, candidate_actions, RiskWeights())
    ranked_hyp = pipeline_res.ranked[0]
    top_action = ranked_hyp.ranked_actions[0]
    monitor_action = next(
        sa for sa in ranked_hyp.ranked_actions
        if sa.action.action_type == ActionType.MONITOR_ONLY
    )

    # Assert top action strictly beats MONITOR_ONLY
    assert top_action.composite_score > monitor_action.composite_score
    assert top_action.containment == 1.0
    assert top_action.action.action_type == ActionType.RESTRICT_PRIVILEGES

    # 3. Guardrail outcome: RESTRICT_PRIVILEGES with BI=0.00 is auto-approved
    playbook = build_playbook(ranked_hyp, base_kg)
    guarded = evaluate_guardrails(playbook)
    assert guarded.overall_status == PlaybookExecutionStatus.AUTO_APPROVED
    assert "auto-approved" in guarded.guardrail_decision_reason.lower()


# =========================================================================
# 3. T1021.002: SMB/Windows Admin Shares
# =========================================================================

def test_t1021_002_smb_lateral_movement_seeded(base_kg: KnowledgeStoreGraph, audit_log_path: Path):
    """
    T1021.002 requires GRANTS(min_access_level=READ) AND zone egress on port 445.
    zone:WEB -> zone:DATABASE allows port 445 (SMB).
    account:svc_backup has default GRANTS(ADMIN) on server-db01 (satisfies READ).
    """
    sse = StructuralSimulationEngine(base_kg)
    hypothesis = NCEHypothesis(
        technique_id="T1021.002",
        source_account="svc_backup",
        source_host="server-web01",
        target_host="server-db01",
        nce_confidence=0.85,
        supporting_evidence_refs=["raw_log_line"],
        status=HypothesisStatus.GENERATED,
    )

    # 1. SSE feasibility
    vh = validate_hypothesis_with_sse(hypothesis, sse)
    assert vh.best_sse_verdict == SSEVerdict.FEASIBLE

    # 2. RSEM ranking
    candidate_actions = [
        ProposedAction(action_type=ActionType.MONITOR_ONLY, target_account_id="svc_backup"),
        ProposedAction(action_type=ActionType.REVOKE_SESSION, target_account_id="svc_backup"),
        ProposedAction(action_type=ActionType.RESTRICT_PRIVILEGES, target_account_id="svc_backup"),
        ProposedAction(action_type=ActionType.QUARANTINE_ACCESS, target_host_id="server-db01"),
    ]
    pipeline_res = rank_validated_hypotheses([vh], base_kg, sse, candidate_actions, RiskWeights())
    ranked_hyp = pipeline_res.ranked[0]
    top_action = ranked_hyp.ranked_actions[0]
    monitor_action = next(
        sa for sa in ranked_hyp.ranked_actions
        if sa.action.action_type == ActionType.MONITOR_ONLY
    )

    # Assert top action strictly beats MONITOR_ONLY
    assert top_action.composite_score > monitor_action.composite_score
    assert top_action.containment == 1.0
    assert top_action.action.action_type == ActionType.RESTRICT_PRIVILEGES

    # 3. Guardrail outcome
    playbook = build_playbook(ranked_hyp, base_kg)
    guarded = evaluate_guardrails(playbook)
    assert guarded.overall_status == PlaybookExecutionStatus.AUTO_APPROVED


# =========================================================================
# 4. T1550: Use Alternate Authentication Material (Pass-the-Hash)
# =========================================================================

def test_t1550_pass_the_hash_seeded(base_kg: KnowledgeStoreGraph, audit_log_path: Path):
    """
    T1550 requires GRANTS(ADMIN) or MEMBER_OF -> GRANTS(ADMIN).
    account:svc_backup has standing GRANTS(ADMIN) on server-db01.
    """
    sse = StructuralSimulationEngine(base_kg)
    hypothesis = NCEHypothesis(
        technique_id="T1550",
        source_account="svc_backup",
        source_host="workstation-01",
        target_host="server-db01",
        nce_confidence=0.85,
        supporting_evidence_refs=["raw_log_line"],
        status=HypothesisStatus.GENERATED,
    )

    # 1. SSE feasibility
    vh = validate_hypothesis_with_sse(hypothesis, sse)
    assert vh.best_sse_verdict == SSEVerdict.FEASIBLE

    # 2. RSEM ranking
    candidate_actions = [
        ProposedAction(action_type=ActionType.MONITOR_ONLY, target_account_id="svc_backup"),
        ProposedAction(action_type=ActionType.REVOKE_SESSION, target_account_id="svc_backup"),
        ProposedAction(action_type=ActionType.RESTRICT_PRIVILEGES, target_account_id="svc_backup"),
        ProposedAction(action_type=ActionType.QUARANTINE_ACCESS, target_host_id="server-db01"),
    ]
    pipeline_res = rank_validated_hypotheses([vh], base_kg, sse, candidate_actions, RiskWeights())
    ranked_hyp = pipeline_res.ranked[0]
    top_action = ranked_hyp.ranked_actions[0]
    monitor_action = next(
        sa for sa in ranked_hyp.ranked_actions
        if sa.action.action_type == ActionType.MONITOR_ONLY
    )

    # Assert top action strictly beats MONITOR_ONLY
    assert top_action.composite_score > monitor_action.composite_score
    assert top_action.containment == 1.0
    assert top_action.action.action_type == ActionType.RESTRICT_PRIVILEGES

    # 3. Guardrail outcome (plus ENABLE_MFA step appended for credential-relevant technique)
    playbook = build_playbook(ranked_hyp, base_kg)
    assert any(step.action.action.action_type == ActionType.ENABLE_MFA for step in playbook.steps)
    guarded = evaluate_guardrails(playbook)
    assert guarded.overall_status == PlaybookExecutionStatus.AUTO_APPROVED


# =========================================================================
# 5. T1484: Domain Policy Modification (GPO Abuse)
# =========================================================================

def test_t1484_domain_policy_modification_seeded(base_kg: KnowledgeStoreGraph, audit_log_path: Path):
    """
    T1484 requires GRANTS(DOMAIN_ADMIN) or MEMBER_OF -> GRANTS(DOMAIN_ADMIN).
    account:bob is MEMBER_OF group:domain-admins, which has DOMAIN_ADMIN on server-dc01.
    """
    sse = StructuralSimulationEngine(base_kg)
    hypothesis = NCEHypothesis(
        technique_id="T1484",
        source_account="bob",
        source_host="server-dc01",
        target_host="server-dc01",
        nce_confidence=0.85,
        supporting_evidence_refs=["raw_log_line"],
        status=HypothesisStatus.GENERATED,
    )

    # 1. SSE feasibility
    vh = validate_hypothesis_with_sse(hypothesis, sse)
    assert vh.best_sse_verdict == SSEVerdict.FEASIBLE

    # 2. RSEM ranking
    candidate_actions = [
        ProposedAction(action_type=ActionType.MONITOR_ONLY, target_account_id="bob"),
        ProposedAction(action_type=ActionType.REVOKE_SESSION, target_account_id="bob"),
        ProposedAction(action_type=ActionType.RESTRICT_PRIVILEGES, target_account_id="bob"),
        ProposedAction(action_type=ActionType.QUARANTINE_ACCESS, target_host_id="server-dc01"),
    ]
    pipeline_res = rank_validated_hypotheses([vh], base_kg, sse, candidate_actions, RiskWeights())
    ranked_hyp = pipeline_res.ranked[0]
    top_action = ranked_hyp.ranked_actions[0]
    monitor_action = next(
        sa for sa in ranked_hyp.ranked_actions
        if sa.action.action_type == ActionType.MONITOR_ONLY
    )

    # Assert top action strictly beats MONITOR_ONLY
    assert top_action.composite_score > monitor_action.composite_score
    assert top_action.containment == 1.0
    assert top_action.action.action_type == ActionType.RESTRICT_PRIVILEGES

    # 3. Guardrail outcome
    playbook = build_playbook(ranked_hyp, base_kg)
    assert any(step.action.action.action_type == ActionType.ENABLE_MFA for step in playbook.steps)
    guarded = evaluate_guardrails(playbook)
    assert guarded.overall_status == PlaybookExecutionStatus.AUTO_APPROVED


# =========================================================================
# 6. T1562: Impair Defenses (Security Tool Tampering)
# =========================================================================

def test_t1562_impair_defenses_seeded(base_kg: KnowledgeStoreGraph, audit_log_path: Path):
    """
    T1562 requires local ADMIN on target host.
    account:svc_backup has GRANTS(ADMIN) on server-db01.
    """
    sse = StructuralSimulationEngine(base_kg)
    hypothesis = NCEHypothesis(
        technique_id="T1562",
        source_account="svc_backup",
        source_host="server-db01",
        target_host="server-db01",
        nce_confidence=0.85,
        supporting_evidence_refs=["raw_log_line"],
        status=HypothesisStatus.GENERATED,
    )

    # 1. SSE feasibility
    vh = validate_hypothesis_with_sse(hypothesis, sse)
    assert vh.best_sse_verdict == SSEVerdict.FEASIBLE

    # 2. RSEM ranking
    candidate_actions = [
        ProposedAction(action_type=ActionType.MONITOR_ONLY, target_account_id="svc_backup"),
        ProposedAction(action_type=ActionType.REVOKE_SESSION, target_account_id="svc_backup"),
        ProposedAction(action_type=ActionType.RESTRICT_PRIVILEGES, target_account_id="svc_backup"),
        ProposedAction(action_type=ActionType.QUARANTINE_ACCESS, target_host_id="server-db01"),
    ]
    pipeline_res = rank_validated_hypotheses([vh], base_kg, sse, candidate_actions, RiskWeights())
    ranked_hyp = pipeline_res.ranked[0]
    top_action = ranked_hyp.ranked_actions[0]
    monitor_action = next(
        sa for sa in ranked_hyp.ranked_actions
        if sa.action.action_type == ActionType.MONITOR_ONLY
    )

    # Assert top action strictly beats MONITOR_ONLY
    assert top_action.composite_score > monitor_action.composite_score
    assert top_action.containment == 1.0
    assert top_action.action.action_type == ActionType.RESTRICT_PRIVILEGES

    # 3. Guardrail outcome (non-credential, no MFA step)
    playbook = build_playbook(ranked_hyp, base_kg)
    assert not any(step.action.action.action_type == ActionType.ENABLE_MFA for step in playbook.steps)
    guarded = evaluate_guardrails(playbook)
    assert guarded.overall_status == PlaybookExecutionStatus.AUTO_APPROVED


# =========================================================================
# 7. T1071: Architectural Three-Way Tie Regression Guard
# =========================================================================

@pytest.mark.parametrize(
    "account,source_host,target_host",
    [
        ("alice", "workstation-01", "server-web01"),  # Seeded account with graph edges
        ("jsmith", "WKSTN-7363", "185.220.101.5"),   # Unseeded synthetic GUIDE account
    ],
)
def test_t1071_architectural_three_way_tie(
    base_kg: KnowledgeStoreGraph,
    account: str,
    source_host: str,
    target_host: str,
    audit_log_path: Path,
):
    """
    Regression guard for T1071 (Application Layer Protocol — Network Egress).

    Confirms that MONITOR_ONLY, REVOKE_SESSION, and RESTRICT_PRIVILEGES tie
    at composite = 0.0000 on ANY account (seeded or unseeded).

    Architectural cause: T1071 depends strictly on zone egress, not identity
    access edges. REVOKE_SESSION and RESTRICT_PRIVILEGES remove 0 egress edges,
    cutting 0 paths (containment = 0.0000).

    If a code change inadvertently alters RSEM scoring so these actions do
    not tie at 0.0000, this regression test will immediately catch it.
    """
    sse = StructuralSimulationEngine(base_kg)
    hypothesis = NCEHypothesis(
        technique_id="T1071",
        source_account=account,
        source_host=source_host,
        target_host=target_host,
        nce_confidence=0.85,
        supporting_evidence_refs=["raw_log_line"],
        status=HypothesisStatus.GENERATED,
    )

    vh = validate_hypothesis_with_sse(hypothesis, sse)
    assert vh.best_sse_verdict == SSEVerdict.FEASIBLE

    candidate_actions = [
        ProposedAction(action_type=ActionType.MONITOR_ONLY, target_account_id=account),
        ProposedAction(action_type=ActionType.REVOKE_SESSION, target_account_id=account),
        ProposedAction(action_type=ActionType.RESTRICT_PRIVILEGES, target_account_id=account),
        ProposedAction(action_type=ActionType.QUARANTINE_ACCESS, target_host_id=target_host),
    ]
    pipeline_res = rank_validated_hypotheses([vh], base_kg, sse, candidate_actions, RiskWeights())
    ranked_hyp = pipeline_res.ranked[0]

    scores_by_type = {
        sa.action.action_type: sa
        for sa in ranked_hyp.ranked_actions
    }

    monitor_sa = scores_by_type[ActionType.MONITOR_ONLY]
    revoke_sa = scores_by_type[ActionType.REVOKE_SESSION]
    restrict_sa = scores_by_type[ActionType.RESTRICT_PRIVILEGES]
    quarantine_sa = scores_by_type[ActionType.QUARANTINE_ACCESS]

    # All three must score containment = 0.0000
    assert monitor_sa.containment == 0.0
    assert revoke_sa.containment == 0.0
    assert restrict_sa.containment == 0.0

    # All three must have composite score exactly 0.0000
    assert monitor_sa.composite_score == 0.0
    assert revoke_sa.composite_score == 0.0
    assert restrict_sa.composite_score == 0.0

    # Exact three-way tie invariant
    assert monitor_sa.composite_score == revoke_sa.composite_score == restrict_sa.composite_score == 0.0

    # QUARANTINE_ACCESS has non-positive score due to host isolation business impact
    assert quarantine_sa.composite_score <= 0.0
