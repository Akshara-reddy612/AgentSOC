"""
tests/test_action_playbook.py

Tests for the Action/Playbook Layer (perception/action_playbook.py).

Covers:
1. Adaptive Playbook Generator — ENABLE_MFA appended for credential-relevant
   techniques, not appended for others.
2. Policy and Safety Guardrails — hard floor for QUARANTINE_ACCESS/REVOKE_SESSION,
   threshold on business_impact, ENABLE_MFA always auto-approved.
3. Execution Interface — refuses non-approved playbooks, produces real state
   diffs, does NOT mutate the live graph, writes valid audit log entries.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from perception.action_playbook import (
    AUDIT_LOG_PATH,
    CREDENTIAL_RELEVANT_TECHNIQUES,
    GUARDRAIL_BUSINESS_IMPACT_THRESHOLD,
    Playbook,
    PlaybookExecutionStatus,
    PlaybookStep,
    build_playbook,
    evaluate_guardrails,
    execute_playbook_dry_run,
)
from perception.knowledge_graph import (
    KnowledgeStoreGraph,
    account_node_id,
    host_node_id,
)
from perception.knowledge_store import KnowledgeFact
from perception.nce_contract import (
    HypothesisStatus,
    NCEHypothesis,
)
from perception.nce_rsem_integration import (
    RankedHypothesisResult,
    rank_validated_hypotheses,
)
from perception.nce_sse_integration import (
    ValidatedHypothesis,
    validate_hypothesis_with_sse,
)
from perception.rsem import (
    ActionType,
    ProposedAction,
    RiskWeights,
    ScoredAction,
    StructuralSimulationEngine,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def kg() -> KnowledgeStoreGraph:
    """Fresh KnowledgeStoreGraph with full seed data."""
    return KnowledgeStoreGraph()


@pytest.fixture
def sse(kg: KnowledgeStoreGraph) -> StructuralSimulationEngine:
    """SSE backed by the seeded KnowledgeStoreGraph."""
    return StructuralSimulationEngine(kg)


@pytest.fixture
def candidate_actions() -> list[ProposedAction]:
    """Standard candidate defensive actions for svc_backup."""
    return [
        ProposedAction(
            action_type=ActionType.REVOKE_SESSION,
            target_account_id="svc_backup",
        ),
        ProposedAction(
            action_type=ActionType.RESTRICT_PRIVILEGES,
            target_account_id="svc_backup",
        ),
        ProposedAction(
            action_type=ActionType.QUARANTINE_ACCESS,
            target_host_id="server-db01",
        ),
        ProposedAction(
            action_type=ActionType.MONITOR_ONLY,
            target_account_id="svc_backup",
        ),
    ]


def _make_ranked_result(
    kg: KnowledgeStoreGraph,
    sse: StructuralSimulationEngine,
    candidate_actions: list[ProposedAction],
    technique_id: str = "T1550",
    source_account: str = "svc_backup",
    source_host: str = "workstation-01",
    target_host: str = "server-db01",
) -> RankedHypothesisResult:
    """
    Helper to produce a real RankedHypothesisResult through the full
    NCE → SSE → RSEM pipeline for a given technique.
    """
    hypothesis = NCEHypothesis(
        technique_id=technique_id,
        source_account=source_account,
        source_host=source_host,
        target_host=target_host,
        nce_confidence=0.85,
        supporting_evidence_refs=["raw_log_line", "event_timestamp"],
        missing_context_flags=[],
        status=HypothesisStatus.GENERATED,
    )
    validated = validate_hypothesis_with_sse(hypothesis, sse)
    result = rank_validated_hypotheses(
        [validated], kg, sse, candidate_actions,
    )
    assert len(result.ranked) == 1, (
        f"Expected 1 ranked hypothesis for {technique_id}, got "
        f"{len(result.ranked)} (sse_rejected={len(result.sse_rejected)})"
    )
    return result.ranked[0]


@pytest.fixture
def t1550_ranked(
    kg: KnowledgeStoreGraph,
    sse: StructuralSimulationEngine,
    candidate_actions: list[ProposedAction],
) -> RankedHypothesisResult:
    """RankedHypothesisResult for svc_backup T1550 (credential-relevant)."""
    return _make_ranked_result(kg, sse, candidate_actions, technique_id="T1550")


@pytest.fixture
def t1078_ranked(
    kg: KnowledgeStoreGraph,
    sse: StructuralSimulationEngine,
    candidate_actions: list[ProposedAction],
) -> RankedHypothesisResult:
    """RankedHypothesisResult for svc_backup T1078 (credential-relevant)."""
    return _make_ranked_result(kg, sse, candidate_actions, technique_id="T1078")


@pytest.fixture
def t1562_ranked(
    kg: KnowledgeStoreGraph,
    sse: StructuralSimulationEngine,
    candidate_actions: list[ProposedAction],
) -> RankedHypothesisResult:
    """RankedHypothesisResult for svc_backup T1562 (NOT credential-relevant)."""
    return _make_ranked_result(kg, sse, candidate_actions, technique_id="T1562")


@pytest.fixture
def audit_log_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """
    Redirect audit log to a temp file so tests don't pollute the real log.
    """
    tmp_log = tmp_path / "test_audit_log.jsonl"
    monkeypatch.setattr(
        "perception.action_playbook.AUDIT_LOG_PATH", tmp_log
    )
    return tmp_log


# =========================================================================
# PART 1 — Adaptive Playbook Generator (build_playbook)
# =========================================================================

class TestBuildPlaybook:
    """Tests for the Adaptive Playbook Generator."""

    def test_appends_mfa_for_t1550(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """T1550 is credential-relevant — playbook should have 2 steps."""
        playbook = build_playbook(t1550_ranked, kg)

        assert len(playbook.steps) == 2
        assert playbook.steps[0].is_policy_action is False
        assert playbook.steps[1].is_policy_action is True
        assert playbook.steps[1].action.action.action_type == ActionType.ENABLE_MFA

    def test_appends_mfa_for_t1078(
        self,
        t1078_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """T1078 is credential-relevant — playbook should have 2 steps."""
        playbook = build_playbook(t1078_ranked, kg)

        assert len(playbook.steps) == 2
        assert playbook.steps[1].is_policy_action is True
        assert playbook.steps[1].action.action.action_type == ActionType.ENABLE_MFA

    def test_appends_mfa_for_t1484(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
    ) -> None:
        """T1484 is credential-relevant — playbook should have 2 steps."""
        # T1484 requires domain admin — bob has it via domain-admins → server-dc01
        t1484_actions = [
            ProposedAction(action_type=ActionType.REVOKE_SESSION, target_account_id="bob"),
            ProposedAction(action_type=ActionType.RESTRICT_PRIVILEGES, target_account_id="bob"),
            ProposedAction(action_type=ActionType.QUARANTINE_ACCESS, target_host_id="server-dc01"),
            ProposedAction(action_type=ActionType.MONITOR_ONLY, target_account_id="bob"),
        ]
        ranked = _make_ranked_result(
            kg, sse, t1484_actions,
            technique_id="T1484",
            source_account="bob",
            source_host="workstation-01",
            target_host="server-dc01",
        )
        playbook = build_playbook(ranked, kg)

        assert len(playbook.steps) == 2
        assert playbook.steps[1].action.action.action_type == ActionType.ENABLE_MFA

    def test_no_mfa_for_t1562(
        self,
        t1562_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """T1562 is NOT credential-relevant — playbook should have 1 step."""
        playbook = build_playbook(t1562_ranked, kg)

        assert len(playbook.steps) == 1
        assert playbook.steps[0].is_policy_action is False

    def test_no_mfa_for_t1071(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
        candidate_actions: list[ProposedAction],
    ) -> None:
        """T1071 is NOT credential-relevant — playbook should have 1 step."""
        ranked = _make_ranked_result(
            kg, sse, candidate_actions, technique_id="T1071",
        )
        playbook = build_playbook(ranked, kg)

        assert len(playbook.steps) == 1

    def test_initial_status_is_pending_guardrail(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """Newly built playbook must start at PENDING_GUARDRAIL_CHECK."""
        playbook = build_playbook(t1550_ranked, kg)

        assert playbook.overall_status == PlaybookExecutionStatus.PENDING_GUARDRAIL_CHECK
        for step in playbook.steps:
            assert step.status == PlaybookExecutionStatus.PENDING_GUARDRAIL_CHECK

    def test_mfa_step_targets_same_as_step1(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """ENABLE_MFA step targets the same account/host as Step 1."""
        playbook = build_playbook(t1550_ranked, kg)

        step1_action = playbook.steps[0].action.action
        mfa_action = playbook.steps[1].action.action

        assert mfa_action.target_account_id == step1_action.target_account_id
        assert mfa_action.target_host_id == step1_action.target_host_id

    def test_mfa_step_has_zero_scores(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """ENABLE_MFA policy step has all-zero RSEM scores (not graph-scored)."""
        playbook = build_playbook(t1550_ranked, kg)

        mfa_scored = playbook.steps[1].action
        assert mfa_scored.containment == 0.0
        assert mfa_scored.business_impact == 0.0
        assert mfa_scored.composite_score == 0.0
        assert mfa_scored.paths_cut == 0


# =========================================================================
# PART 2 — Policy and Safety Guardrails (evaluate_guardrails)
# =========================================================================

class TestEvaluateGuardrails:
    """Tests for the Policy and Safety Guardrails."""

    def _build_playbook_with_specific_top_action(
        self,
        ranked_result: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
        action_type: ActionType,
        business_impact: float,
    ) -> Playbook:
        """
        Helper: build a playbook and replace Step 1's action with
        a specific action_type and business_impact for guardrail testing.
        """
        playbook = build_playbook(ranked_result, kg)

        # Replace step 1 with a controlled ScoredAction
        original = playbook.steps[0].action
        controlled_action = ScoredAction(
            action=ProposedAction(
                action_type=action_type,
                target_account_id=original.action.target_account_id
                or "test_account",
                target_host_id=original.action.target_host_id,
            ),
            containment=original.containment,
            business_impact=business_impact,
            composite_score=original.composite_score,
            paths_cut=original.paths_cut,
            paths_total_before=original.paths_total_before,
        )
        playbook.steps[0] = PlaybookStep(
            step_number=1,
            action=controlled_action,
            is_policy_action=False,
            status=PlaybookExecutionStatus.PENDING_GUARDRAIL_CHECK,
        )
        return playbook

    def test_hard_floor_quarantine_access(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """
        QUARANTINE_ACCESS → PENDING_ANALYST_REVIEW regardless of low
        business_impact (hard floor rule).
        """
        playbook = self._build_playbook_with_specific_top_action(
            t1550_ranked, kg,
            action_type=ActionType.QUARANTINE_ACCESS,
            business_impact=0.1,  # Well below threshold
        )
        result = evaluate_guardrails(playbook)

        assert result.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
        assert "QUARANTINE_ACCESS" in result.guardrail_decision_reason
        assert "hard floor" in result.guardrail_decision_reason.lower()

    def test_hard_floor_revoke_session(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """
        REVOKE_SESSION → PENDING_ANALYST_REVIEW regardless of low
        business_impact (hard floor rule).
        """
        playbook = self._build_playbook_with_specific_top_action(
            t1550_ranked, kg,
            action_type=ActionType.REVOKE_SESSION,
            business_impact=0.0,  # Zero impact — still routed to review
        )
        result = evaluate_guardrails(playbook)

        assert result.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
        assert "REVOKE_SESSION" in result.guardrail_decision_reason

    def test_threshold_high_impact_routed_to_review(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """
        RESTRICT_PRIVILEGES with business_impact > 0.35 →
        PENDING_ANALYST_REVIEW via threshold rule.
        """
        playbook = self._build_playbook_with_specific_top_action(
            t1550_ranked, kg,
            action_type=ActionType.RESTRICT_PRIVILEGES,
            business_impact=0.50,  # Above 0.35 threshold
        )
        result = evaluate_guardrails(playbook)

        assert result.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
        assert "0.50" in result.guardrail_decision_reason
        assert str(GUARDRAIL_BUSINESS_IMPACT_THRESHOLD) in result.guardrail_decision_reason

    def test_threshold_low_impact_auto_approved(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """
        MONITOR_ONLY with business_impact < 0.35 → AUTO_APPROVED.
        """
        playbook = self._build_playbook_with_specific_top_action(
            t1550_ranked, kg,
            action_type=ActionType.MONITOR_ONLY,
            business_impact=0.15,  # Well below threshold
        )
        result = evaluate_guardrails(playbook)

        assert result.overall_status == PlaybookExecutionStatus.AUTO_APPROVED
        assert "Auto-approved" in result.guardrail_decision_reason
        assert "0.15" in result.guardrail_decision_reason

    def test_restrict_privileges_below_threshold_auto_approved(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """
        RESTRICT_PRIVILEGES with business_impact = 0.25 (below 0.35) →
        AUTO_APPROVED (not caught by hard floor, below threshold).
        """
        playbook = self._build_playbook_with_specific_top_action(
            t1550_ranked, kg,
            action_type=ActionType.RESTRICT_PRIVILEGES,
            business_impact=0.25,
        )
        result = evaluate_guardrails(playbook)

        assert result.overall_status == PlaybookExecutionStatus.AUTO_APPROVED

    def test_mfa_step_always_auto_approved(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """
        ENABLE_MFA policy step always gets AUTO_APPROVED even when Step 1
        is PENDING_ANALYST_REVIEW (hard floor).
        """
        playbook = self._build_playbook_with_specific_top_action(
            t1550_ranked, kg,
            action_type=ActionType.QUARANTINE_ACCESS,
            business_impact=0.9,
        )
        result = evaluate_guardrails(playbook)

        # Overall routed to review because of Step 1
        assert result.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW

        # But the MFA step (Step 2) should be auto-approved
        mfa_steps = [s for s in result.steps if s.is_policy_action]
        assert len(mfa_steps) == 1
        assert mfa_steps[0].status == PlaybookExecutionStatus.AUTO_APPROVED

    def test_guardrail_reason_is_human_readable(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
    ) -> None:
        """guardrail_decision_reason must be non-empty and descriptive."""
        playbook = self._build_playbook_with_specific_top_action(
            t1550_ranked, kg,
            action_type=ActionType.MONITOR_ONLY,
            business_impact=0.10,
        )
        result = evaluate_guardrails(playbook)

        assert len(result.guardrail_decision_reason) > 20
        assert "MONITOR_ONLY" in result.guardrail_decision_reason


# =========================================================================
# PART 3 — Execution Interface (execute_playbook_dry_run)
# =========================================================================

class TestExecutePlaybookDryRun:
    """Tests for the Execution Interface (dry-run mode)."""

    def test_refuses_pending_analyst_review(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
        audit_log_path: Path,
    ) -> None:
        """
        execute_playbook_dry_run() REFUSES to execute a
        PENDING_ANALYST_REVIEW playbook and returns it unchanged.
        """
        playbook = build_playbook(t1550_ranked, kg)
        playbook = evaluate_guardrails(playbook)

        # Force it to PENDING_ANALYST_REVIEW for this test
        forced = Playbook(
            hypothesis=playbook.hypothesis,
            steps=playbook.steps,
            overall_status=PlaybookExecutionStatus.PENDING_ANALYST_REVIEW,
            guardrail_decision_reason=playbook.guardrail_decision_reason,
        )
        result = execute_playbook_dry_run(forced, kg)

        assert result.overall_status == PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
        assert result.dry_run_report is not None
        assert "REFUSED" in result.dry_run_report
        assert "AUTO_APPROVED" in result.dry_run_report

    def test_produces_real_state_diff(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
        audit_log_path: Path,
    ) -> None:
        """
        An approved playbook dry-run produces a real before/after state diff
        with actual graph edge descriptions (not just "report exists").
        """
        playbook = build_playbook(t1550_ranked, kg)

        # Force AUTO_APPROVED with a low-impact, non-hard-floor action
        step1_action = playbook.steps[0].action
        controlled = ScoredAction(
            action=ProposedAction(
                action_type=ActionType.RESTRICT_PRIVILEGES,
                target_account_id="svc_backup",
            ),
            containment=step1_action.containment,
            business_impact=0.10,
            composite_score=step1_action.composite_score,
            paths_cut=step1_action.paths_cut,
            paths_total_before=step1_action.paths_total_before,
        )
        playbook.steps[0] = PlaybookStep(
            step_number=1,
            action=controlled,
            is_policy_action=False,
            status=PlaybookExecutionStatus.PENDING_GUARDRAIL_CHECK,
        )
        playbook = evaluate_guardrails(playbook)
        assert playbook.overall_status == PlaybookExecutionStatus.AUTO_APPROVED

        result = execute_playbook_dry_run(playbook, kg)

        assert result.overall_status == PlaybookExecutionStatus.DRY_RUN_COMPLETE
        assert result.dry_run_report is not None

        # Verify actual graph state values appear in the report
        report = result.dry_run_report
        assert "GRANTS" in report
        assert "svc_backup" in report.lower() or "account:svc_backup" in report
        assert "ACTIVE" in report or "REMOVED" in report or "modified" in report.lower()
        assert "Rollback" in report

    def test_does_not_mutate_live_graph(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
        audit_log_path: Path,
    ) -> None:
        """
        THE MOST IMPORTANT TEST: The live graph_store must be completely
        unchanged after dry-run execution.
        """
        # Snapshot the live graph before
        edges_before = set(
            (u, v, k) for u, v, k in kg.graph.edges(keys=True)
        )
        edge_count_before = kg.graph.number_of_edges()
        node_count_before = kg.graph.number_of_nodes()

        # Snapshot specific edge data (GRANTS confidence for svc_backup)
        svc_node = account_node_id("svc_backup")
        grants_data_before: dict[tuple, dict] = {}
        for u, v, key, data in kg.graph.edges(keys=True, data=True):
            if u == svc_node and data.get("edge_type") == "GRANTS":
                grants_data_before[(u, v, key)] = dict(data)

        # Build and execute a dry-run
        playbook = build_playbook(t1550_ranked, kg)

        # Force AUTO_APPROVED
        controlled = ScoredAction(
            action=ProposedAction(
                action_type=ActionType.RESTRICT_PRIVILEGES,
                target_account_id="svc_backup",
            ),
            containment=0.5,
            business_impact=0.10,
            composite_score=0.4,
            paths_cut=1,
            paths_total_before=2,
        )
        playbook.steps[0] = PlaybookStep(
            step_number=1,
            action=controlled,
            is_policy_action=False,
            status=PlaybookExecutionStatus.PENDING_GUARDRAIL_CHECK,
        )
        playbook = evaluate_guardrails(playbook)
        result = execute_playbook_dry_run(playbook, kg)

        assert result.overall_status == PlaybookExecutionStatus.DRY_RUN_COMPLETE

        # Verify the live graph is UNCHANGED
        edges_after = set(
            (u, v, k) for u, v, k in kg.graph.edges(keys=True)
        )
        assert edges_after == edges_before, (
            f"Live graph edges changed! "
            f"Before: {edge_count_before}, After: {kg.graph.number_of_edges()}"
        )
        assert kg.graph.number_of_edges() == edge_count_before
        assert kg.graph.number_of_nodes() == node_count_before

        # Verify specific GRANTS edge data unchanged
        for edge_key, data_before in grants_data_before.items():
            u, v, k = edge_key
            data_after = kg.graph.edges[u, v, k]
            al_before = data_before.get("access_level")
            al_after = data_after.get("access_level")
            if isinstance(al_before, KnowledgeFact):
                assert isinstance(al_after, KnowledgeFact)
                assert al_after.confidence == al_before.confidence, (
                    f"GRANTS confidence changed for {edge_key}! "
                    f"Before: {al_before.confidence}, After: {al_after.confidence}"
                )

    def test_mfa_policy_step_simulation_report(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
        audit_log_path: Path,
    ) -> None:
        """
        ENABLE_MFA policy step produces an honest simulation report stating
        no MFA state is modeled in the graph schema.
        """
        playbook = build_playbook(t1550_ranked, kg)
        assert len(playbook.steps) == 2  # T1550 should have MFA step

        # Force AUTO_APPROVED
        controlled = ScoredAction(
            action=ProposedAction(
                action_type=ActionType.RESTRICT_PRIVILEGES,
                target_account_id="svc_backup",
            ),
            containment=0.5,
            business_impact=0.10,
            composite_score=0.4,
            paths_cut=1,
            paths_total_before=2,
        )
        playbook.steps[0] = PlaybookStep(
            step_number=1,
            action=controlled,
            is_policy_action=False,
            status=PlaybookExecutionStatus.PENDING_GUARDRAIL_CHECK,
        )
        playbook = evaluate_guardrails(playbook)
        result = execute_playbook_dry_run(playbook, kg)

        assert result.dry_run_report is not None
        report = result.dry_run_report
        assert "SIMULATED" in report
        assert "MFA" in report
        assert "no MFA state currently modeled" in report

    def test_audit_log_valid_json(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
        audit_log_path: Path,
    ) -> None:
        """
        Each playbook execution appends a valid JSON line to the audit log.
        """
        # Ensure log doesn't exist yet
        assert not audit_log_path.exists()

        playbook = build_playbook(t1550_ranked, kg)
        controlled = ScoredAction(
            action=ProposedAction(
                action_type=ActionType.RESTRICT_PRIVILEGES,
                target_account_id="svc_backup",
            ),
            containment=0.5,
            business_impact=0.10,
            composite_score=0.4,
            paths_cut=1,
            paths_total_before=2,
        )
        playbook.steps[0] = PlaybookStep(
            step_number=1,
            action=controlled,
            is_policy_action=False,
            status=PlaybookExecutionStatus.PENDING_GUARDRAIL_CHECK,
        )
        playbook = evaluate_guardrails(playbook)

        # Execute twice to verify append behavior
        execute_playbook_dry_run(playbook, kg)
        execute_playbook_dry_run(playbook, kg)

        assert audit_log_path.exists()

        lines = audit_log_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2  # Two executions = two lines

        for line in lines:
            entry = json.loads(line)  # Must parse as valid JSON
            assert "timestamp" in entry
            assert "technique_id" in entry
            assert "action_types" in entry
            assert "guardrail_decision" in entry
            assert "overall_status" in entry
            assert entry["overall_status"] == "DRY_RUN_COMPLETE"

    def test_audit_log_accumulates(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
        audit_log_path: Path,
    ) -> None:
        """Audit log entries accumulate across executions (append-only)."""
        playbook = build_playbook(t1550_ranked, kg)
        controlled = ScoredAction(
            action=ProposedAction(
                action_type=ActionType.MONITOR_ONLY,
                target_account_id="svc_backup",
            ),
            containment=0.0,
            business_impact=0.0,
            composite_score=0.0,
            paths_cut=0,
            paths_total_before=0,
        )
        playbook.steps[0] = PlaybookStep(
            step_number=1,
            action=controlled,
            is_policy_action=False,
            status=PlaybookExecutionStatus.PENDING_GUARDRAIL_CHECK,
        )
        playbook = evaluate_guardrails(playbook)

        for _ in range(3):
            execute_playbook_dry_run(playbook, kg)

        lines = audit_log_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3


# =========================================================================
# PART 4 — End-to-end integration
# =========================================================================

class TestEndToEndIntegration:
    """Full pipeline integration tests: NCE → SSE → RSEM → Playbook."""

    def test_full_pipeline_t1550_credential_relevant(
        self,
        t1550_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
        audit_log_path: Path,
    ) -> None:
        """
        Complete end-to-end: T1550 svc_backup → server-db01 through all
        four stages.  Validates the full chain works without errors.
        """
        playbook = build_playbook(t1550_ranked, kg)
        assert len(playbook.steps) == 2  # RSEM step + ENABLE_MFA

        playbook = evaluate_guardrails(playbook)
        # The top action from RSEM will determine guardrail routing —
        # just verify it processed without error
        assert playbook.guardrail_decision_reason != ""

        if playbook.overall_status == PlaybookExecutionStatus.AUTO_APPROVED:
            result = execute_playbook_dry_run(playbook, kg)
            assert result.overall_status == PlaybookExecutionStatus.DRY_RUN_COMPLETE
            assert result.dry_run_report is not None
        else:
            # If routed to review (e.g., QUARANTINE_ACCESS topped),
            # dry-run should refuse
            result = execute_playbook_dry_run(playbook, kg)
            assert "REFUSED" in result.dry_run_report

    def test_full_pipeline_t1562_non_credential(
        self,
        t1562_ranked: RankedHypothesisResult,
        kg: KnowledgeStoreGraph,
        audit_log_path: Path,
    ) -> None:
        """
        T1562 (non-credential) through the full pipeline — should NOT
        have an ENABLE_MFA step.
        """
        playbook = build_playbook(t1562_ranked, kg)
        assert len(playbook.steps) == 1  # No MFA step

        playbook = evaluate_guardrails(playbook)
        assert playbook.guardrail_decision_reason != ""
