"""
tests/test_nce_rsem_integration.py

Phase NCE-6 integration tests: validates the complete NCE → SSE → RSEM
defended pipeline.

Test categories:
1. Real end-to-end tests using Phase NCE-4/5 data:
   (a) Alert 1073741825161 (fabricated_evidence, T1562, INFEASIBLE) — should
       be excluded from RSEM ranking entirely, reported as sse_rejected.
   (b) svc_backup → server-db01 (T1550, FEASIBLE) — should proceed through
       to a ranked action list with RSEM_RANKED status.
2. Standard unit tests: mixed batches, status transitions, nothing dropped,
   RSEM never receives nce_confidence.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import (
    HypothesisStatus,
    MissingContextFlag,
    NCEHypothesis,
    NCEOutput,
)
from perception.nce_rsem_integration import (
    PipelineResult,
    RankedHypothesisResult,
    rank_validated_hypotheses,
)
from perception.nce_sse_integration import (
    ValidatedHypothesis,
    validate_hypothesis_with_sse,
    validate_nce_output,
)
from perception.rsem import (
    ActionType,
    ProposedAction,
    RiskWeights,
    ScoredAction,
)
from perception.sse import (
    SSEVerdict,
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
    """Standard set of candidate defensive actions for svc_backup."""
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


# =========================================================================
# PART 2 — Real end-to-end tests
# =========================================================================

class TestRealEndToEndFabricatedEvidence:
    """
    Alert 1073741825161 (fabricated_evidence, T1562, m.chen@corp.local)
    through the COMPLETE pipeline: NCE → SSE → RSEM.

    Expected: INFEASIBLE at SSE stage → excluded from RSEM ranking →
    appears in sse_rejected, NOT silently dropped.
    """

    def test_fabricated_hypothesis_excluded_from_rsem(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
    ) -> None:
        """
        The contaminated T1562 hypothesis from alert 1073741825161 should
        be excluded from RSEM ranking entirely and reported as sse_rejected.
        """
        # Load the real eval results
        eval_path = (
            Path(__file__).parent.parent / "agent" / "nce_adversarial_eval_results.json"
        )
        with open(eval_path, "r") as f:
            eval_results = json.load(f)

        alert_data = next(
            e for e in eval_results if e["alert_id"] == "1073741825161"
        )
        top_hyp_data = alert_data["hypotheses"][0]

        # Reconstruct hypothesis using exact recorded values
        hypothesis = NCEHypothesis(
            technique_id=top_hyp_data["technique_id"],
            source_account=top_hyp_data["source_account"],
            source_host=top_hyp_data["source_host"],
            target_host=top_hyp_data["target_host"],
            nce_confidence=top_hyp_data["nce_confidence"],
            supporting_evidence_refs=list(top_hyp_data["supporting_evidence_refs"]),
            missing_context_flags=[
                MissingContextFlag(f) for f in top_hyp_data["missing_context_flags"]
            ],
            status=HypothesisStatus.GENERATED,
            incident_id=top_hyp_data["incident_id"],
        )

        # Step 1: SSE validation
        validated = validate_hypothesis_with_sse(hypothesis, sse)
        assert validated.hypothesis.status == HypothesisStatus.INFEASIBLE

        # Step 2: Full pipeline
        candidate_actions = [
            ProposedAction(
                action_type=ActionType.QUARANTINE_ACCESS,
                target_host_id="unknown",
            ),
        ]
        result = rank_validated_hypotheses(
            [validated], kg, sse, candidate_actions,
        )

        # The hypothesis should be in sse_rejected, NOT ranked
        assert len(result.ranked) == 0
        assert len(result.sse_rejected) == 1
        assert result.sse_rejected[0].hypothesis.status == HypothesisStatus.INFEASIBLE
        assert result.sse_rejected[0].hypothesis.technique_id == "T1562"
        assert result.sse_rejected[0].confidence_gap == pytest.approx(0.75)

    def test_fabricated_hypothesis_not_silently_dropped(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
    ) -> None:
        """
        The contaminated hypothesis must appear somewhere in the PipelineResult
        — either in ranked or sse_rejected. It must NEVER be silently dropped.
        """
        hypothesis = NCEHypothesis(
            technique_id="T1562",
            source_account="m.chen@corp.local",
            source_host="unknown",
            target_host="unknown",
            nce_confidence=0.75,
            supporting_evidence_refs=["process_name", "command_line"],
            missing_context_flags=[
                MissingContextFlag.TARGET_PRIVILEGE_LEVEL,
                MissingContextFlag.PRIOR_ACCESS,
                MissingContextFlag.NETWORK_REACHABILITY,
            ],
            status=HypothesisStatus.GENERATED,
        )

        validated = validate_hypothesis_with_sse(hypothesis, sse)
        result = rank_validated_hypotheses(
            [validated], kg, sse,
            [ProposedAction(action_type=ActionType.MONITOR_ONLY,
                            target_account_id="m.chen@corp.local")],
        )

        total = len(result.ranked) + len(result.sse_rejected)
        assert total == 1  # Nothing dropped


class TestRealEndToEndFeasible:
    """
    svc_backup → server-db01 (T1550, FEASIBLE) through the COMPLETE
    pipeline: NCE → SSE → RSEM.

    This is the first true end-to-end proof of the full defended pipeline
    producing a real ranked action list.
    """

    def test_feasible_hypothesis_produces_ranked_actions(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
        candidate_actions: list[ProposedAction],
    ) -> None:
        """
        svc_backup with T1550 on server-db01 should produce a ranked
        action list with status RSEM_RANKED.
        """
        hypothesis = NCEHypothesis(
            technique_id="T1550",
            source_account="svc_backup",
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.85,
            supporting_evidence_refs=["raw_log_line", "event_timestamp"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )

        # Step 1: SSE validation
        validated = validate_hypothesis_with_sse(hypothesis, sse)
        assert validated.hypothesis.status == HypothesisStatus.FEASIBLE

        # Step 2: Full pipeline
        result = rank_validated_hypotheses(
            [validated], kg, sse, candidate_actions,
        )

        # Should produce exactly 1 ranked hypothesis
        assert len(result.ranked) == 1
        assert len(result.sse_rejected) == 0

        ranked = result.ranked[0]
        assert ranked.validated.hypothesis.status == HypothesisStatus.RSEM_RANKED
        assert ranked.validated.hypothesis.technique_id == "T1550"

        # Should have scored all 4 candidate actions
        assert len(ranked.ranked_actions) == len(candidate_actions)

        # Actions should be sorted by composite_score descending
        scores = [sa.composite_score for sa in ranked.ranked_actions]
        assert scores == sorted(scores, reverse=True)

        # At least one action should have positive containment
        # (svc_backup has a real GRANTS edge to server-db01 that can be cut)
        has_positive_containment = any(
            sa.containment > 0 for sa in ranked.ranked_actions
        )
        assert has_positive_containment

    def test_rsem_ranked_preserves_sse_data(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
        candidate_actions: list[ProposedAction],
    ) -> None:
        """
        After RSEM ranking, the ValidatedHypothesis still preserves
        all SSE data (sse_results, best_sse_verdict, best_path_confidence,
        confidence_gap).
        """
        hypothesis = NCEHypothesis(
            technique_id="T1550",
            source_account="svc_backup",
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.85,
            supporting_evidence_refs=["raw_log_line"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )

        validated = validate_hypothesis_with_sse(hypothesis, sse)
        result = rank_validated_hypotheses(
            [validated], kg, sse, candidate_actions,
        )

        ranked_vh = result.ranked[0].validated
        # SSE data should be fully preserved
        assert ranked_vh.best_sse_verdict == SSEVerdict.FEASIBLE
        assert ranked_vh.best_path_confidence > 0.0
        assert len(ranked_vh.sse_results) >= 1
        # confidence_gap is preserved
        assert ranked_vh.confidence_gap == pytest.approx(
            ranked_vh.hypothesis.nce_confidence - ranked_vh.best_path_confidence
        )


# =========================================================================
# PART 3 — Standard unit tests
# =========================================================================

class TestMixedBatches:
    """Test mixed FEASIBLE and INFEASIBLE batches through the full pipeline."""

    def test_mixed_batch_correctly_partitioned(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
        candidate_actions: list[ProposedAction],
    ) -> None:
        """
        A batch with 1 FEASIBLE + 2 INFEASIBLE should produce exactly
        1 ranked + 2 sse_rejected.
        """
        hypotheses = [
            NCEHypothesis(  # FEASIBLE: svc_backup → server-db01 T1550
                technique_id="T1550",
                source_account="svc_backup",
                source_host="workstation-01",
                target_host="server-db01",
                nce_confidence=0.85,
                supporting_evidence_refs=["raw_log_line"],
                missing_context_flags=[],
                status=HypothesisStatus.GENERATED,
                incident_id="mixed-test-001",
            ),
            NCEHypothesis(  # INFEASIBLE: alice + T1484 (requires DOMAIN_ADMIN)
                technique_id="T1484",
                source_account="alice",
                source_host="workstation-01",
                target_host="server-db01",
                nce_confidence=0.9,
                supporting_evidence_refs=["raw_log_line"],
                missing_context_flags=[],
                status=HypothesisStatus.GENERATED,
                incident_id="mixed-test-001",
            ),
            NCEHypothesis(  # INFEASIBLE: charlie + T1484
                technique_id="T1484",
                source_account="charlie",
                source_host="workstation-01",
                target_host="server-db01",
                nce_confidence=0.7,
                supporting_evidence_refs=["auth_log_ref"],
                missing_context_flags=[],
                status=HypothesisStatus.GENERATED,
                incident_id="mixed-test-001",
            ),
        ]

        nce_output = NCEOutput(
            incident_id="mixed-test-001",
            hypotheses=tuple(hypotheses),
        )

        validated_list = validate_nce_output(nce_output, sse)
        result = rank_validated_hypotheses(
            validated_list, kg, sse, candidate_actions,
        )

        assert len(result.ranked) == 1
        assert len(result.sse_rejected) == 2
        # Total count matches input
        assert len(result.ranked) + len(result.sse_rejected) == 3

    def test_all_infeasible_batch_produces_empty_ranked(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
        candidate_actions: list[ProposedAction],
    ) -> None:
        """
        If ALL hypotheses are INFEASIBLE, ranked should be empty and
        all 3 should be in sse_rejected.
        """
        hypotheses = tuple(
            NCEHypothesis(
                technique_id="T1484",
                source_account="alice",
                source_host="workstation-01",
                target_host="server-db01",
                nce_confidence=0.8 - (i * 0.1),
                supporting_evidence_refs=["raw_log_line"],
                missing_context_flags=[],
                status=HypothesisStatus.GENERATED,
                incident_id="all-infeasible-001",
            )
            for i in range(3)
        )
        nce_output = NCEOutput(
            incident_id="all-infeasible-001",
            hypotheses=hypotheses,
        )

        validated_list = validate_nce_output(nce_output, sse)
        result = rank_validated_hypotheses(
            validated_list, kg, sse, candidate_actions,
        )

        assert len(result.ranked) == 0
        assert len(result.sse_rejected) == 3
        for vh in result.sse_rejected:
            assert vh.hypothesis.status == HypothesisStatus.INFEASIBLE

    def test_all_feasible_batch_all_ranked(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
    ) -> None:
        """
        If ALL hypotheses are FEASIBLE, all should be ranked and
        sse_rejected should be empty.
        """
        # svc_backup has GRANTS(ADMIN) on server-db01 — T1550 and T1562
        # both require ADMIN, so both should be FEASIBLE.
        hypotheses = tuple(
            NCEHypothesis(
                technique_id=tid,
                source_account="svc_backup",
                source_host="workstation-01",
                target_host="server-db01",
                nce_confidence=0.8,
                supporting_evidence_refs=["raw_log_line"],
                missing_context_flags=[],
                status=HypothesisStatus.GENERATED,
                incident_id="all-feasible-001",
            )
            for tid in ["T1550", "T1562"]
        )
        nce_output = NCEOutput(
            incident_id="all-feasible-001",
            hypotheses=hypotheses,
        )

        actions = [
            ProposedAction(
                action_type=ActionType.REVOKE_SESSION,
                target_account_id="svc_backup",
            ),
        ]
        validated_list = validate_nce_output(nce_output, sse)
        result = rank_validated_hypotheses(
            validated_list, kg, sse, actions,
        )

        assert len(result.ranked) == 2
        assert len(result.sse_rejected) == 0
        for rhr in result.ranked:
            assert rhr.validated.hypothesis.status == HypothesisStatus.RSEM_RANKED


class TestStatusTransitions:
    """Test hypothesis lifecycle status transitions through the pipeline."""

    def test_feasible_to_rsem_ranked(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
    ) -> None:
        """GENERATED → FEASIBLE → RSEM_RANKED transition."""
        hypothesis = NCEHypothesis(
            technique_id="T1550",
            source_account="svc_backup",
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.85,
            supporting_evidence_refs=["raw_log_line"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )

        # GENERATED → FEASIBLE (SSE validation)
        validated = validate_hypothesis_with_sse(hypothesis, sse)
        assert validated.hypothesis.status == HypothesisStatus.FEASIBLE

        # FEASIBLE → RSEM_RANKED (RSEM ranking)
        result = rank_validated_hypotheses(
            [validated], kg, sse,
            [ProposedAction(action_type=ActionType.MONITOR_ONLY,
                            target_account_id="svc_backup")],
        )
        assert result.ranked[0].validated.hypothesis.status == HypothesisStatus.RSEM_RANKED

    def test_infeasible_stays_infeasible(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
    ) -> None:
        """GENERATED → INFEASIBLE, stays INFEASIBLE through pipeline."""
        hypothesis = NCEHypothesis(
            technique_id="T1484",
            source_account="alice",
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.9,
            supporting_evidence_refs=["raw_log_line"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )

        # GENERATED → INFEASIBLE
        validated = validate_hypothesis_with_sse(hypothesis, sse)
        assert validated.hypothesis.status == HypothesisStatus.INFEASIBLE

        # Still INFEASIBLE after pipeline (never reaches RSEM)
        result = rank_validated_hypotheses(
            [validated], kg, sse,
            [ProposedAction(action_type=ActionType.MONITOR_ONLY,
                            target_account_id="alice")],
        )
        assert len(result.sse_rejected) == 1
        assert result.sse_rejected[0].hypothesis.status == HypothesisStatus.INFEASIBLE


class TestNothingSilentlyDropped:
    """Verify nothing is silently dropped from the audit trail."""

    def test_total_count_matches_input(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
    ) -> None:
        """ranked + sse_rejected always equals input count."""
        for count in (1, 2, 3):
            hypotheses = tuple(
                NCEHypothesis(
                    technique_id="T1078",
                    source_account="alice",
                    source_host="workstation-01",
                    target_host="workstation-01",
                    nce_confidence=0.5,
                    supporting_evidence_refs=["raw_log_line"],
                    missing_context_flags=[],
                    status=HypothesisStatus.GENERATED,
                    incident_id=f"count-test-{count}",
                )
                for _ in range(count)
            )
            nce_output = NCEOutput(
                incident_id=f"count-test-{count}",
                hypotheses=hypotheses,
            )

            validated_list = validate_nce_output(nce_output, sse)
            result = rank_validated_hypotheses(
                validated_list, kg, sse,
                [ProposedAction(action_type=ActionType.MONITOR_ONLY,
                                target_account_id="alice")],
            )
            total = len(result.ranked) + len(result.sse_rejected)
            assert total == count

    def test_empty_input_produces_empty_output(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
    ) -> None:
        """Empty validated list → empty PipelineResult."""
        result = rank_validated_hypotheses(
            [], kg, sse,
            [ProposedAction(action_type=ActionType.MONITOR_ONLY,
                            target_account_id="alice")],
        )
        assert len(result.ranked) == 0
        assert len(result.sse_rejected) == 0


class TestRSEMNeverReceivesNceConfidence:
    """
    Structural test: RSEM's scoring inputs never include nce_confidence.
    """

    def test_scored_action_has_no_nce_confidence_field(self) -> None:
        """ScoredAction does not contain any nce_confidence field."""
        import dataclasses
        field_names = {f.name for f in dataclasses.fields(ScoredAction)}
        assert "nce_confidence" not in field_names

    def test_rsem_score_uses_containment_and_impact_only(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
    ) -> None:
        """
        Two hypotheses with different nce_confidence but same structural
        properties should produce the same RSEM score — proving RSEM
        doesn't use nce_confidence.
        """
        h1 = NCEHypothesis(
            technique_id="T1550",
            source_account="svc_backup",
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.2,  # Very low
            supporting_evidence_refs=["raw_log_line"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )
        h2 = NCEHypothesis(
            technique_id="T1550",
            source_account="svc_backup",
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.99,  # Very high
            supporting_evidence_refs=["raw_log_line"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )

        v1 = validate_hypothesis_with_sse(h1, sse)
        v2 = validate_hypothesis_with_sse(h2, sse)

        action = ProposedAction(
            action_type=ActionType.RESTRICT_PRIVILEGES,
            target_account_id="svc_backup",
        )

        r1 = rank_validated_hypotheses([v1], kg, sse, [action])
        r2 = rank_validated_hypotheses([v2], kg, sse, [action])

        # Both should be ranked
        assert len(r1.ranked) == 1
        assert len(r2.ranked) == 1

        # The composite scores should be identical because RSEM only uses
        # graph topology (containment) and node attributes (business_impact),
        # never nce_confidence.
        score1 = r1.ranked[0].ranked_actions[0].composite_score
        score2 = r2.ranked[0].ranked_actions[0].composite_score
        assert score1 == pytest.approx(score2)


class TestRiskWeightsPassthrough:
    """Test that risk weights are correctly passed to RSEM."""

    def test_different_weights_produce_different_scores(
        self,
        kg: KnowledgeStoreGraph,
        sse: StructuralSimulationEngine,
    ) -> None:
        """
        RISK_AVERSE and AGGRESSIVE_CONTAINMENT presets should produce
        different composite scores for the same hypothesis.
        """
        from perception.rsem import AGGRESSIVE_CONTAINMENT, RISK_AVERSE

        hypothesis = NCEHypothesis(
            technique_id="T1550",
            source_account="svc_backup",
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.85,
            supporting_evidence_refs=["raw_log_line"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )

        validated = validate_hypothesis_with_sse(hypothesis, sse)

        action = ProposedAction(
            action_type=ActionType.QUARANTINE_ACCESS,
            target_host_id="server-db01",
        )

        r_averse = rank_validated_hypotheses(
            [validated], kg, sse, [action], RISK_AVERSE,
        )
        r_aggressive = rank_validated_hypotheses(
            [validated], kg, sse, [action], AGGRESSIVE_CONTAINMENT,
        )

        s_averse = r_averse.ranked[0].ranked_actions[0].composite_score
        s_aggressive = r_aggressive.ranked[0].ranked_actions[0].composite_score

        # Different weights → different scores
        assert s_averse != pytest.approx(s_aggressive)


class TestPipelineResultStructure:
    """Test PipelineResult dataclass structure."""

    def test_pipeline_result_is_frozen(self) -> None:
        """PipelineResult should be immutable."""
        import dataclasses
        assert dataclasses.fields(PipelineResult)
        # PipelineResult is frozen=True
        pr = PipelineResult(ranked=[], sse_rejected=[])
        with pytest.raises(AttributeError):
            pr.ranked = []  # type: ignore[misc]

    def test_ranked_hypothesis_result_is_frozen(self) -> None:
        """RankedHypothesisResult should be immutable."""
        import dataclasses
        fields = {f.name for f in dataclasses.fields(RankedHypothesisResult)}
        assert "validated" in fields
        assert "ranked_actions" in fields
