"""
tests/test_nce_contract.py

Tests for the NCE data contract (perception/nce_contract.py).

Covers:
  1. NCEHypothesis rejects unknown technique_id
  2. NCEHypothesis rejects nce_confidence outside [0,1]
  3. generate_mock_hypotheses returns valid objects
  4. NCE → SSE → RSEM end-to-end integration (MOST IMPORTANT TEST)
"""

from __future__ import annotations

import pytest

from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import NCEHypothesis, generate_mock_hypotheses
from perception.rsem import (
    ActionType,
    ProposedAction,
    compute_containment,
)
from perception.sse import StructuralSimulationEngine, TECHNIQUE_TABLE


# ---------------------------------------------------------------------------
# Test 1: NCEHypothesis rejects unknown technique_id
# ---------------------------------------------------------------------------

class TestNCEHypothesisValidation:
    """NCEHypothesis rejects invalid inputs."""

    def test_rejects_unknown_technique_id(self):
        with pytest.raises(ValueError, match="TECHNIQUE_TABLE"):
            NCEHypothesis(
                technique_id="T9999",
                source_account="alice",
                source_host="workstation-01",
                target_host="server-dc01",
                nce_confidence=0.8,
                supporting_evidence_refs=["raw_log_line"],
            )


# ---------------------------------------------------------------------------
# Test 2: NCEHypothesis rejects nce_confidence outside [0,1]
# ---------------------------------------------------------------------------

    def test_rejects_confidence_above_1(self):
        with pytest.raises(ValueError, match="nce_confidence"):
            NCEHypothesis(
                technique_id="T1078",
                source_account="alice",
                source_host="workstation-01",
                target_host="server-dc01",
                nce_confidence=1.5,
                supporting_evidence_refs=["raw_log_line"],
            )

    def test_rejects_confidence_below_0(self):
        with pytest.raises(ValueError, match="nce_confidence"):
            NCEHypothesis(
                technique_id="T1078",
                source_account="alice",
                source_host="workstation-01",
                target_host="server-dc01",
                nce_confidence=-0.1,
                supporting_evidence_refs=["raw_log_line"],
            )


# ---------------------------------------------------------------------------
# Test 3: generate_mock_hypotheses returns valid objects
# ---------------------------------------------------------------------------

class TestMockHypotheses:
    """generate_mock_hypotheses returns valid, usable NCEHypothesis objects."""

    def test_returns_valid_hypotheses(self):
        hypotheses = generate_mock_hypotheses(
            "alice", "workstation-01", "server-dc01"
        )
        assert len(hypotheses) > 0
        for h in hypotheses:
            assert isinstance(h, NCEHypothesis)
            assert h.technique_id in TECHNIQUE_TABLE
            assert 0.0 <= h.nce_confidence <= 1.0

    def test_custom_technique_ids(self):
        hypotheses = generate_mock_hypotheses(
            "alice", "workstation-01", "server-dc01",
            technique_ids=["T1078", "T1550"],
        )
        assert len(hypotheses) == 2
        assert {h.technique_id for h in hypotheses} == {"T1078", "T1550"}


# ---------------------------------------------------------------------------
# Test 4: NCE → SSE → RSEM end-to-end integration
# ---------------------------------------------------------------------------

class TestNCESSERSEMIntegration:
    """
    THE MOST IMPORTANT TEST IN THIS SESSION.

    Proves the NCE → SSE → RSEM contract chain works end-to-end:
    generate_mock_hypotheses output feeds directly into
    compute_containment without error.
    """

    @pytest.fixture
    def graph_store(self):
        return KnowledgeStoreGraph()

    @pytest.fixture
    def sse(self, graph_store):
        return StructuralSimulationEngine(graph_store)

    def test_nce_to_sse_to_rsem_end_to_end(self, graph_store, sse):
        """Mock NCE hypotheses feed through SSE into RSEM's
        compute_containment without any errors — proving the
        three-module contract chain is type-compatible and functional."""
        # NCE generates hypotheses
        hypotheses = generate_mock_hypotheses(
            account_id="svc_backup",
            source_host="workstation-01",
            target_host="server-db01",
            technique_ids=["T1078", "T1550"],
        )

        # RSEM consumes them via SSE
        action = ProposedAction(
            action_type=ActionType.REVOKE_SESSION,
            target_account_id="svc_backup",
        )

        containment, paths_cut, paths_total = compute_containment(
            graph_store, sse, action, hypotheses
        )

        # Structural assertions — not just "didn't crash"
        assert isinstance(containment, float)
        assert 0.0 <= containment <= 1.0
        assert isinstance(paths_cut, int)
        assert isinstance(paths_total, int)
        assert paths_total >= 0
        assert paths_cut >= 0
        assert paths_cut <= paths_total
        # This action should actually cut paths (svc_backup has
        # real GRANTS+HAS_PRIOR_ACCESS to server-db01)
        assert containment > 0.0, (
            "REVOKE_SESSION on svc_backup should cut at least one "
            "feasible path to server-db01"
        )
        assert paths_cut > 0
