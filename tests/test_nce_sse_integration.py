"""
tests/test_nce_sse_integration.py

Phase NCE-5 integration tests: validates that NCE hypotheses are correctly
wired through SSE structural validation.

Test categories:
1. Real integration test using Phase NCE-4 adversarial eval data (alert
   1073741825161, fabricated_evidence family) — the first real answer to
   "can a plausible-looking contaminated hypothesis survive SSE?"
2. Standard unit tests covering FEASIBLE, INFEASIBLE, confidence_gap
   computation, retention of infeasible hypotheses, and the design
   invariant that nce_confidence and path_confidence are NEVER blended.
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
from perception.nce_sse_integration import (
    ValidatedHypothesis,
    validate_hypothesis_with_sse,
    validate_nce_output,
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


# =========================================================================
# PART 2.1 — Real integration test with Phase NCE-4 adversarial data
# =========================================================================

class TestRealAdversarialHypothesis:
    """
    Test using the ACTUAL hypothesis from alert 1073741825161
    (fabricated_evidence family, Phase NCE-4 adversarial eval).

    This alert produced a top hypothesis:
      technique_id = T1562 (Impair Defenses)
      source_account = m.chen@corp.local
      source_host = unknown
      target_host = unknown
      nce_confidence = 0.75

    T1562 requires GRANTS >= ADMIN per the technique table.  This is the
    first real answer to: "can a plausible-looking contaminated hypothesis
    survive independent structural validation?"
    """

    def test_fabricated_evidence_t1562_against_real_kg(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """
        Reconstruct the ACTUAL hypothesis from alert 1073741825161 and
        run it through SSE.

        Expected: m.chen@corp.local with source_host="unknown" and
        target_host="unknown" should NOT have ADMIN-level GRANTS on any
        target — the Knowledge Graph has no such path seeded.  SSE should
        return INFEASIBLE, demonstrating that a contaminated hypothesis
        with nce_confidence=0.75 is caught by structural validation.
        """
        # Load the real eval results to verify we're using the exact data
        eval_path = Path(__file__).parent.parent / "agent" / "nce_adversarial_eval_results.json"
        with open(eval_path, "r") as f:
            eval_results = json.load(f)

        # Find alert 1073741825161
        alert_data = None
        for entry in eval_results:
            if entry["alert_id"] == "1073741825161":
                alert_data = entry
                break
        assert alert_data is not None, "Alert 1073741825161 not found in eval results"
        assert alert_data["family"] == "fabricated_evidence"

        # Get the top hypothesis (T1562)
        top_hyp_data = alert_data["hypotheses"][0]
        assert top_hyp_data["technique_id"] == "T1562"

        # Reconstruct the NCEHypothesis using exact recorded values
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

        # --- Run through SSE ---
        result = validate_hypothesis_with_sse(hypothesis, sse)

        # --- The critical result ---
        # m.chen@corp.local has no ADMIN grants on any host in the KG.
        # The "unknown" target host gets lazily created with no edges.
        # SSE should declare this INFEASIBLE.
        assert result.hypothesis.status == HypothesisStatus.INFEASIBLE, (
            f"CRITICAL: contaminated hypothesis survived SSE! "
            f"Status={result.hypothesis.status}, "
            f"verdict={result.best_sse_verdict}, "
            f"path_confidence={result.best_path_confidence}"
        )
        assert result.best_sse_verdict == SSEVerdict.INFEASIBLE
        assert result.best_path_confidence == 0.0

        # confidence_gap should be 0.75 - 0.0 = 0.75 — NCE was confident
        # in a structurally impossible attack, which is exactly the kind
        # of divergence the confidence_gap metric is designed to detect.
        assert result.confidence_gap == pytest.approx(0.75)

        # The original hypothesis data is preserved unchanged
        assert result.hypothesis.technique_id == "T1562"
        assert result.hypothesis.source_account == "m.chen@corp.local"
        assert result.hypothesis.nce_confidence == 0.75

        # SSE returned at least one INFEASIBLE PathResult with a reason
        assert len(result.sse_results) >= 1
        infeasible_results = [
            r for r in result.sse_results
            if r.verdict == SSEVerdict.INFEASIBLE
        ]
        assert len(infeasible_results) >= 1
        assert infeasible_results[0].dependency_note is not None


# =========================================================================
# PART 2.2 — Standard unit tests
# =========================================================================

class TestFeasibleHypothesis:
    """Test a hypothesis known to be FEASIBLE via the seeded graph."""

    def test_svc_backup_server_db01_t1550_feasible(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """
        svc_backup has a direct GRANTS(ADMIN) edge to server-db01.
        T1550 (Pass-the-Hash) requires ADMIN — this should be FEASIBLE
        with high path_confidence.
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

        result = validate_hypothesis_with_sse(hypothesis, sse)

        assert result.hypothesis.status == HypothesisStatus.FEASIBLE
        assert result.best_sse_verdict == SSEVerdict.FEASIBLE
        assert result.best_path_confidence > 0.0

        # confidence_gap should be sensible: nce_confidence - path_confidence
        expected_gap = 0.85 - result.best_path_confidence
        assert result.confidence_gap == pytest.approx(expected_gap)

    def test_feasible_preserves_original_fields(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """The updated hypothesis preserves all original fields except status."""
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

        result = validate_hypothesis_with_sse(hypothesis, sse)

        assert result.hypothesis.technique_id == "T1550"
        assert result.hypothesis.source_account == "svc_backup"
        assert result.hypothesis.source_host == "workstation-01"
        assert result.hypothesis.target_host == "server-db01"
        assert result.hypothesis.nce_confidence == 0.85
        assert result.hypothesis.status == HypothesisStatus.FEASIBLE


class TestInfeasibleHypothesis:
    """Test a hypothesis with no valid path — INFEASIBLE."""

    def test_infeasible_still_present_not_deleted(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """
        A hypothesis with no valid path should get status=INFEASIBLE but
        must still be present in the output — never deleted/discarded.
        """
        hypothesis = NCEHypothesis(
            technique_id="T1484",  # Requires DOMAIN_ADMIN
            source_account="alice",  # Standard user, no DOMAIN_ADMIN
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.9,
            supporting_evidence_refs=["raw_log_line"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )

        result = validate_hypothesis_with_sse(hypothesis, sse)

        assert result.hypothesis.status == HypothesisStatus.INFEASIBLE
        assert result.best_sse_verdict == SSEVerdict.INFEASIBLE
        # best_path_confidence should reflect the infeasible case
        assert result.best_path_confidence == 0.0

        # The hypothesis is NOT None, NOT dropped — it's fully present
        assert result.hypothesis is not None
        assert result.hypothesis.technique_id == "T1484"
        assert result.hypothesis.source_account == "alice"

    def test_infeasible_sse_results_contain_failure_reason(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """INFEASIBLE results should include a dependency_note explaining why."""
        hypothesis = NCEHypothesis(
            technique_id="T1484",
            source_account="charlie",  # Standard user
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.7,
            supporting_evidence_refs=["auth_log_ref"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )

        result = validate_hypothesis_with_sse(hypothesis, sse)

        assert result.best_sse_verdict == SSEVerdict.INFEASIBLE
        assert len(result.sse_results) >= 1
        assert result.sse_results[0].dependency_note is not None


class TestConfidenceGap:
    """Test confidence_gap computation — must NOT be clamped."""

    def test_large_positive_gap(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """
        High nce_confidence + infeasible path (path_confidence=0.0)
        → confidence_gap should be a large positive number.
        """
        hypothesis = NCEHypothesis(
            technique_id="T1484",
            source_account="alice",
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.95,
            supporting_evidence_refs=["raw_log_line"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )

        result = validate_hypothesis_with_sse(hypothesis, sse)

        assert result.confidence_gap == pytest.approx(0.95)
        assert result.confidence_gap > 0.0

    def test_negative_gap_preserved(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """
        Low nce_confidence + feasible path with high path_confidence
        → confidence_gap should be negative.  Must NOT be clamped to 0.
        """
        # svc_backup -> server-db01 is FEASIBLE with path_confidence=1.0
        # (ADMIN grant at confidence 1.0)
        hypothesis = NCEHypothesis(
            technique_id="T1550",
            source_account="svc_backup",
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.2,  # Intentionally low
            supporting_evidence_refs=["raw_log_line"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )

        result = validate_hypothesis_with_sse(hypothesis, sse)

        assert result.best_sse_verdict == SSEVerdict.FEASIBLE
        # path_confidence should be 1.0 (ADMIN grant at confidence 1.0)
        assert result.best_path_confidence == pytest.approx(1.0)
        # confidence_gap = 0.2 - 1.0 = -0.8
        assert result.confidence_gap == pytest.approx(-0.8)
        assert result.confidence_gap < 0.0  # NOT clamped to 0


class TestValidateNceOutput:
    """Test validate_nce_output() — the batch integration point."""

    def test_all_hypotheses_returned_even_if_all_infeasible(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """
        3-hypothesis NCEOutput where ALL are infeasible — validate_nce_output()
        must return exactly 3 ValidatedHypothesis objects.  Nothing silently
        dropped.
        """
        # All three use T1484 (requires DOMAIN_ADMIN) with alice (standard user)
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
                incident_id="test-incident-001",
            )
            for i in range(3)
        )
        nce_output = NCEOutput(
            incident_id="test-incident-001",
            hypotheses=hypotheses,
        )

        results = validate_nce_output(nce_output, sse)

        assert len(results) == 3
        for r in results:
            assert isinstance(r, ValidatedHypothesis)
            assert r.hypothesis.status == HypothesisStatus.INFEASIBLE

    def test_mixed_feasible_and_infeasible(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """
        Mixed NCEOutput: one FEASIBLE hypothesis + one INFEASIBLE.
        Both must be returned.
        """
        hypotheses = (
            NCEHypothesis(
                technique_id="T1550",  # svc_backup -> server-db01: FEASIBLE
                source_account="svc_backup",
                source_host="workstation-01",
                target_host="server-db01",
                nce_confidence=0.85,
                supporting_evidence_refs=["raw_log_line"],
                missing_context_flags=[],
                status=HypothesisStatus.GENERATED,
                incident_id="test-incident-002",
            ),
            NCEHypothesis(
                technique_id="T1484",  # alice: INFEASIBLE
                source_account="alice",
                source_host="workstation-01",
                target_host="server-db01",
                nce_confidence=0.6,
                supporting_evidence_refs=["auth_log_ref"],
                missing_context_flags=[],
                status=HypothesisStatus.GENERATED,
                incident_id="test-incident-002",
            ),
        )
        nce_output = NCEOutput(
            incident_id="test-incident-002",
            hypotheses=hypotheses,
        )

        results = validate_nce_output(nce_output, sse)

        assert len(results) == 2
        statuses = {r.hypothesis.status for r in results}
        assert HypothesisStatus.FEASIBLE in statuses
        assert HypothesisStatus.INFEASIBLE in statuses

    def test_output_count_equals_input_count(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """validate_nce_output always returns exactly as many results as hypotheses."""
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
                    incident_id=f"test-count-{count}",
                )
                for _ in range(count)
            )
            nce_output = NCEOutput(
                incident_id=f"test-count-{count}",
                hypotheses=hypotheses,
            )
            results = validate_nce_output(nce_output, sse)
            assert len(results) == count


class TestConfidenceNeverBlended:
    """
    Explicit structural test: nce_confidence and path_confidence are
    NEVER mathematically combined into a single score.

    This is true by construction in ValidatedHypothesis, but we test
    it explicitly to guard against future regressions.
    """

    def test_both_confidences_exposed_independently(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """
        ValidatedHypothesis exposes nce_confidence (via hypothesis) and
        best_path_confidence as separate, independently accessible values.
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

        result = validate_hypothesis_with_sse(hypothesis, sse)

        # Both values are independently accessible
        nce_conf = result.hypothesis.nce_confidence
        sse_conf = result.best_path_confidence

        # They are different types of confidence — NCE's is the LLM's
        # self-reported confidence, SSE's is the multiplicative path
        # confidence from graph traversal.
        assert isinstance(nce_conf, float)
        assert isinstance(sse_conf, float)

        # confidence_gap is EXACTLY nce_confidence - best_path_confidence
        # i.e., a simple subtraction, not any more complex combination
        assert result.confidence_gap == pytest.approx(nce_conf - sse_conf)

    def test_confidence_gap_is_simple_subtraction(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """
        confidence_gap must be EXACTLY nce_confidence - best_path_confidence.
        Not an average, not a product, not abs(), not clamped.
        """
        # Test with a known FEASIBLE case
        h1 = NCEHypothesis(
            technique_id="T1550",
            source_account="svc_backup",
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.85,
            supporting_evidence_refs=["raw_log_line"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )
        r1 = validate_hypothesis_with_sse(h1, sse)
        assert r1.confidence_gap == pytest.approx(
            r1.hypothesis.nce_confidence - r1.best_path_confidence
        )
        # Verify it's not abs() — for this case gap could be negative
        # if path_confidence > nce_confidence

        # Test with an INFEASIBLE case
        h2 = NCEHypothesis(
            technique_id="T1484",
            source_account="alice",
            source_host="workstation-01",
            target_host="server-db01",
            nce_confidence=0.9,
            supporting_evidence_refs=["raw_log_line"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )
        r2 = validate_hypothesis_with_sse(h2, sse)
        assert r2.confidence_gap == pytest.approx(
            r2.hypothesis.nce_confidence - r2.best_path_confidence
        )
        # For INFEASIBLE, gap = 0.9 - 0.0 = 0.9
        assert r2.confidence_gap == pytest.approx(0.9)

    def test_no_combined_score_field_exists(self) -> None:
        """
        ValidatedHypothesis should NOT have any field that represents a
        blended/combined confidence score.  The only confidence-related
        fields are: best_path_confidence, confidence_gap, and the
        hypothesis's own nce_confidence.
        """
        import dataclasses
        field_names = {f.name for f in dataclasses.fields(ValidatedHypothesis)}

        # These are the expected confidence-related fields
        assert "best_path_confidence" in field_names
        assert "confidence_gap" in field_names

        # No blended/combined score field should exist
        suspicious_names = {
            "combined_confidence", "blended_confidence", "merged_confidence",
            "overall_confidence", "total_confidence", "final_confidence",
            "aggregated_confidence", "weighted_confidence",
        }
        assert field_names.isdisjoint(suspicious_names), (
            f"Found suspicious blended-confidence field(s): "
            f"{field_names & suspicious_names}"
        )


class TestConditionallyFeasibleMapping:
    """Test that CONDITIONALLY_FEASIBLE SSE verdict maps to FEASIBLE status."""

    def test_conditionally_feasible_becomes_feasible(
        self, sse: StructuralSimulationEngine,
    ) -> None:
        """
        mallory has GRANTS(ADMIN, confidence=0.3) on WKSTN-9998.
        T1562 requires ADMIN — SSE should return CONDITIONALLY_FEASIBLE
        (path_confidence < 0.5), which maps to HypothesisStatus.FEASIBLE.
        """
        hypothesis = NCEHypothesis(
            technique_id="T1562",
            source_account="mallory",
            source_host="workstation-01",
            target_host="WKSTN-9998",
            nce_confidence=0.7,
            supporting_evidence_refs=["raw_log_line"],
            missing_context_flags=[],
            status=HypothesisStatus.GENERATED,
        )

        result = validate_hypothesis_with_sse(hypothesis, sse)

        # SSE should return CONDITIONALLY_FEASIBLE (confidence 0.3 < 0.5)
        assert result.best_sse_verdict == SSEVerdict.CONDITIONALLY_FEASIBLE
        assert result.best_path_confidence < 0.5

        # Maps to HypothesisStatus.FEASIBLE per design decision
        assert result.hypothesis.status == HypothesisStatus.FEASIBLE

        # confidence_gap is still correctly computed
        assert result.confidence_gap == pytest.approx(
            0.7 - result.best_path_confidence
        )
