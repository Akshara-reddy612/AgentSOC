"""
tests/test_rsem.py

Tests for the Risk Scoring and Evaluation Module (perception/rsem.py).

Covers all 10 required test cases from the spec.
"""

from __future__ import annotations

import pytest

from perception.knowledge_graph import KnowledgeStoreGraph, host_node_id
from perception.nce_contract import generate_mock_hypotheses
from perception.rsem import (
    AGGRESSIVE_CONTAINMENT,
    ActionType,
    ProposedAction,
    RISK_AVERSE,
    RiskWeights,
    ScoredAction,
    compute_business_impact,
    compute_containment,
    rank_actions,
    score_action,
)
from perception.sse import StructuralSimulationEngine


# ---------------------------------------------------------------------------
# Test 1: RiskWeights rejects alpha<=0 or beta<=0
# ---------------------------------------------------------------------------

class TestRiskWeightsValidation:

    def test_rejects_alpha_zero(self):
        with pytest.raises(ValueError, match="alpha"):
            RiskWeights(alpha=0, beta=1.0)

    def test_rejects_alpha_negative(self):
        with pytest.raises(ValueError, match="alpha"):
            RiskWeights(alpha=-0.5, beta=1.0)

    def test_rejects_beta_zero(self):
        with pytest.raises(ValueError, match="beta"):
            RiskWeights(alpha=1.0, beta=0)

    def test_rejects_beta_negative(self):
        with pytest.raises(ValueError, match="beta"):
            RiskWeights(alpha=1.0, beta=-1.0)

    def test_accepts_valid_weights(self):
        w = RiskWeights(alpha=0.5, beta=2.0)
        assert w.alpha == 0.5
        assert w.beta == 2.0


# ---------------------------------------------------------------------------
# Test 2: ProposedAction rejects both targets None
# ---------------------------------------------------------------------------

class TestProposedActionValidation:

    def test_rejects_both_none(self):
        with pytest.raises(ValueError, match="at least one"):
            ProposedAction(action_type=ActionType.REVOKE_SESSION)

    def test_accepts_account_only(self):
        a = ProposedAction(
            action_type=ActionType.REVOKE_SESSION,
            target_account_id="alice",
        )
        assert a.target_account_id == "alice"

    def test_accepts_host_only(self):
        a = ProposedAction(
            action_type=ActionType.QUARANTINE_ACCESS,
            target_host_id="server-dc01",
        )
        assert a.target_host_id == "server-dc01"


# ---------------------------------------------------------------------------
# Test 3: MONITOR_ONLY returns containment ~0.0
# ---------------------------------------------------------------------------

class TestMonitorOnly:

    @pytest.fixture
    def setup(self):
        gs = KnowledgeStoreGraph()
        sse = StructuralSimulationEngine(gs)
        hypotheses = generate_mock_hypotheses(
            "svc_backup", "workstation-01", "server-db01",
            technique_ids=["T1078", "T1550"],
        )
        return gs, sse, hypotheses

    def test_monitor_only_zero_containment(self, setup):
        gs, sse, hypotheses = setup
        action = ProposedAction(
            action_type=ActionType.MONITOR_ONLY,
            target_account_id="svc_backup",
        )
        containment, paths_cut, paths_total = compute_containment(
            gs, sse, action, hypotheses
        )
        assert containment == 0.0
        assert paths_cut == 0


# ---------------------------------------------------------------------------
# Test 4: REVOKE_SESSION on svc_backup yields containment > 0
# ---------------------------------------------------------------------------

class TestRevokeSession:

    @pytest.fixture
    def setup(self):
        gs = KnowledgeStoreGraph()
        sse = StructuralSimulationEngine(gs)
        hypotheses = generate_mock_hypotheses(
            "svc_backup", "workstation-01", "server-db01",
            technique_ids=["T1078", "T1550"],
        )
        return gs, sse, hypotheses

    def test_revoke_session_positive_containment(self, setup):
        gs, sse, hypotheses = setup
        action = ProposedAction(
            action_type=ActionType.REVOKE_SESSION,
            target_account_id="svc_backup",
        )
        containment, paths_cut, paths_total = compute_containment(
            gs, sse, action, hypotheses
        )
        assert containment > 0.0
        assert paths_cut > 0


# ---------------------------------------------------------------------------
# Test 5: compute_containment never mutates the live graph
# ---------------------------------------------------------------------------

class TestGraphImmutability:

    def test_live_graph_unmutated(self):
        gs = KnowledgeStoreGraph()
        sse = StructuralSimulationEngine(gs)
        hypotheses = generate_mock_hypotheses(
            "svc_backup", "workstation-01", "server-db01",
            technique_ids=["T1078", "T1550"],
        )

        edges_before = gs.graph.number_of_edges()
        nodes_before = gs.graph.number_of_nodes()

        action = ProposedAction(
            action_type=ActionType.REVOKE_SESSION,
            target_account_id="svc_backup",
        )
        compute_containment(gs, sse, action, hypotheses)

        edges_after = gs.graph.number_of_edges()
        nodes_after = gs.graph.number_of_nodes()

        assert edges_after == edges_before, (
            f"Live graph edge count changed: {edges_before} -> {edges_after}"
        )
        assert nodes_after == nodes_before, (
            f"Live graph node count changed: {nodes_before} -> {nodes_after}"
        )


# ---------------------------------------------------------------------------
# Test 6: Business impact ordering (high-criticality > low-criticality)
# ---------------------------------------------------------------------------

class TestBusinessImpactOrdering:

    @pytest.fixture
    def graph_store(self):
        return KnowledgeStoreGraph()

    def test_high_criticality_scores_higher(self, graph_store):
        """server-dc01 (tier 3, critical) should score higher than
        workstation-01 (tier 0, low)."""
        high_action = ProposedAction(
            action_type=ActionType.QUARANTINE_ACCESS,
            target_host_id="server-dc01",
        )
        low_action = ProposedAction(
            action_type=ActionType.QUARANTINE_ACCESS,
            target_host_id="workstation-01",
        )

        high_impact = compute_business_impact(graph_store, high_action)
        low_impact = compute_business_impact(graph_store, low_action)

        assert 0.0 <= high_impact <= 1.0
        assert 0.0 <= low_impact <= 1.0
        assert high_impact > low_impact, (
            f"server-dc01 ({high_impact}) should have higher impact "
            f"than workstation-01 ({low_impact})"
        )


# ---------------------------------------------------------------------------
# Test 7: Business impact increases with more service dependents
# ---------------------------------------------------------------------------

class TestBusinessImpactBlastRadius:

    def test_more_dependents_higher_impact(self):
        """A host with 3 service dependents should score strictly higher
        than the same host class with 0 dependents."""
        action = ProposedAction(
            action_type=ActionType.QUARANTINE_ACCESS,
            target_host_id="server-db01",
        )

        # Scenario 1: host with service that has NO DEPENDS_ON edges
        gs_no_deps = KnowledgeStoreGraph()
        gs_no_deps.get_or_create_service_node("svc-no-deps", "server-db01", 2)
        impact_no_deps = compute_business_impact(gs_no_deps, action)

        # Scenario 2: host with service that has 3 dependents
        gs_with_deps = KnowledgeStoreGraph()
        gs_with_deps.get_or_create_service_node(
            "svc-parent", "server-db01", 2
        )
        gs_with_deps.get_or_create_service_node("dep-1", "server-web01", 1)
        gs_with_deps.get_or_create_service_node("dep-2", "server-web01", 1)
        gs_with_deps.get_or_create_service_node("dep-3", "server-web01", 1)
        gs_with_deps.add_dependency("dep-1", "svc-parent")
        gs_with_deps.add_dependency("dep-2", "svc-parent")
        gs_with_deps.add_dependency("dep-3", "svc-parent")

        impact_with_deps = compute_business_impact(gs_with_deps, action)

        assert impact_with_deps > impact_no_deps, (
            f"3 dependents ({impact_with_deps}) should score higher "
            f"than 0 dependents ({impact_no_deps})"
        )


# ---------------------------------------------------------------------------
# Test 8: score_action arithmetic assertion
# ---------------------------------------------------------------------------

class TestScoreActionArithmetic:

    def test_composite_score_formula(self):
        """composite_score must exactly equal
        (alpha * containment) - (beta * business_impact).

        Hand-computed: svc_backup REVOKE_SESSION (account only, no host)
        REVOKE_SESSION removes HAS_PRIOR_ACCESS only — GRANTS edges survive.
        svc_backup has 2 paths to server-db01 for T1078:
          1. HAS_PRIOR_ACCESS (removed by REVOKE)
          2. GRANTS:ADMIN   (survives — standing grant, not a session)
        → containment = 1/2 = 0.5, business_impact = 0.0
        → composite = 1.5 * 0.5 - 0.8 * 0.0 = 0.75
        """
        gs = KnowledgeStoreGraph()
        sse = StructuralSimulationEngine(gs)
        hypotheses = generate_mock_hypotheses(
            "svc_backup", "workstation-01", "server-db01",
            technique_ids=["T1078"],
        )
        action = ProposedAction(
            action_type=ActionType.REVOKE_SESSION,
            target_account_id="svc_backup",
        )
        weights = RiskWeights(alpha=1.5, beta=0.8)

        result = score_action(gs, sse, action, hypotheses, weights)

        # REVOKE removes HAS_PRIOR_ACCESS; GRANTS survives → 1 of 2 cut
        assert result.containment == pytest.approx(0.5), (
            f"Expected 0.5 (1 of 2 paths cut), got {result.containment}"
        )
        assert result.business_impact == pytest.approx(0.0), (
            f"No target host → impact=0, got {result.business_impact}"
        )

        # Verify the formula: composite = alpha*containment - beta*impact
        expected = (weights.alpha * result.containment) - (
            weights.beta * result.business_impact
        )
        assert result.composite_score == pytest.approx(expected)
        assert result.composite_score == pytest.approx(0.75)


# ---------------------------------------------------------------------------
# Test 9: rank_actions sorted descending by composite_score
# ---------------------------------------------------------------------------

class TestRankActions:

    def test_sorted_descending(self):
        """Three clearly-differentiated actions should sort correctly:
        - REVOKE_SESSION svc_backup (account only): high containment, no impact
        - QUARANTINE server-db01 (host only): high containment, high impact
        - MONITOR_ONLY server-db01: zero containment, high impact (worst)
        """
        gs = KnowledgeStoreGraph()
        sse = StructuralSimulationEngine(gs)
        hypotheses = generate_mock_hypotheses(
            "svc_backup", "workstation-01", "server-db01",
            technique_ids=["T1078", "T1550"],
        )

        candidates = [
            # MONITOR_ONLY: containment=0, impact=0.75 → worst score
            ProposedAction(
                action_type=ActionType.MONITOR_ONLY,
                target_host_id="server-db01",
            ),
            # QUARANTINE server-db01: high containment, impact=0.75 → middle
            ProposedAction(
                action_type=ActionType.QUARANTINE_ACCESS,
                target_host_id="server-db01",
            ),
            # REVOKE svc_backup (no host): high containment, impact=0 → best
            ProposedAction(
                action_type=ActionType.REVOKE_SESSION,
                target_account_id="svc_backup",
            ),
        ]

        ranked = rank_actions(gs, sse, candidates, hypotheses)

        assert len(ranked) == 3
        # Must be sorted descending by composite_score
        for i in range(len(ranked) - 1):
            assert ranked[i].composite_score >= ranked[i + 1].composite_score, (
                f"rank_actions not sorted: "
                f"{ranked[i].composite_score} < {ranked[i+1].composite_score}"
            )

        # The three actions should have genuinely different scores
        scores = [r.composite_score for r in ranked]
        assert len(set(scores)) == 3, (
            f"Expected 3 distinct scores, got {scores}"
        )


# ---------------------------------------------------------------------------
# Test 10: RISK_AVERSE vs AGGRESSIVE_CONTAINMENT produce different scores
# ---------------------------------------------------------------------------

class TestWeightPresets:

    def test_presets_produce_different_scores(self):
        """AGGRESSIVE_CONTAINMENT should score a high-containment action
        higher than RISK_AVERSE does, since it weights containment more
        and business disruption less."""
        gs = KnowledgeStoreGraph()
        sse = StructuralSimulationEngine(gs)
        hypotheses = generate_mock_hypotheses(
            "svc_backup", "workstation-01", "server-db01",
            technique_ids=["T1078", "T1550"],
        )

        # Use both account AND host so we get non-zero business impact
        action = ProposedAction(
            action_type=ActionType.REVOKE_SESSION,
            target_account_id="svc_backup",
            target_host_id="server-db01",
        )

        averse = score_action(gs, sse, action, hypotheses, RISK_AVERSE)
        aggressive = score_action(
            gs, sse, action, hypotheses, AGGRESSIVE_CONTAINMENT
        )

        # Scores must be different
        assert averse.composite_score != aggressive.composite_score, (
            "Weight presets should produce different composite scores"
        )

        # AGGRESSIVE_CONTAINMENT (alpha=1.3, beta=0.7) should favor
        # high-containment actions MORE than RISK_AVERSE (alpha=0.7, beta=1.3).
        # For an action with containment > 0 and business_impact > 0:
        # aggressive gives more weight to containment and less penalty
        # for impact → higher composite_score than risk_averse.
        assert aggressive.composite_score > averse.composite_score, (
            f"AGGRESSIVE_CONTAINMENT ({aggressive.composite_score}) should "
            f"score higher than RISK_AVERSE ({averse.composite_score}) "
            f"for a high-containment action"
        )


# ---------------------------------------------------------------------------
# Test 11: Action type differentiation (REVOKE vs RESTRICT vs QUARANTINE)
# ---------------------------------------------------------------------------

class TestActionTypeDifferentiation:
    """Tests proving REVOKE_SESSION, RESTRICT_PRIVILEGES, and
    QUARANTINE_ACCESS produce genuinely different graph mutations,
    not just different enum labels with identical behavior."""

    @pytest.fixture
    def setup(self):
        gs = KnowledgeStoreGraph()
        sse = StructuralSimulationEngine(gs)
        return gs, sse

    def test_revoke_preserves_but_restrict_cuts_group_mediated(self, setup):
        """bob's group-mediated path to server-dc01 (via domain-admins):
        - REVOKE_SESSION does NOT cut it (only removes HAS_PRIOR_ACCESS)
        - RESTRICT_PRIVILEGES DOES cut it (removes MEMBER_OF edges)

        Uses T1484 (Domain Policy Modification) which requires DOMAIN_ADMIN
        and is ONLY reachable via the group-mediated path."""
        gs, sse = setup

        # T1484 requires DOMAIN_ADMIN — bob's only path is group-mediated:
        #   bob → MEMBER_OF → domain-admins → GRANTS:DOMAIN_ADMIN → server-dc01
        hypotheses = generate_mock_hypotheses(
            "bob", "workstation-01", "server-dc01",
            technique_ids=["T1484"],
        )

        # REVOKE_SESSION: removes HAS_PRIOR_ACCESS only
        revoke = ProposedAction(
            action_type=ActionType.REVOKE_SESSION,
            target_account_id="bob",
        )
        revoke_cont, revoke_cut, _ = compute_containment(
            gs, sse, revoke, hypotheses
        )

        # T1484's group-mediated path should be UNAFFECTED by REVOKE
        assert revoke_cont == 0.0, (
            f"REVOKE_SESSION should not cut group-mediated T1484, "
            f"got containment={revoke_cont}"
        )
        assert revoke_cut == 0

        # RESTRICT_PRIVILEGES: removes GRANTS + MEMBER_OF
        restrict = ProposedAction(
            action_type=ActionType.RESTRICT_PRIVILEGES,
            target_account_id="bob",
        )
        restrict_cont, restrict_cut, _ = compute_containment(
            gs, sse, restrict, hypotheses
        )

        # T1484's group-mediated path should be CUT by RESTRICT
        assert restrict_cont > 0.0, (
            f"RESTRICT_PRIVILEGES should cut group-mediated T1484, "
            f"got containment={restrict_cont}"
        )
        assert restrict_cut > 0

    def test_quarantine_at_least_as_aggressive_as_restrict(self, setup):
        """QUARANTINE_ACCESS (host-level isolation) should produce
        containment >= RESTRICT_PRIVILEGES (account-level privilege removal)
        because it is the superset action.

        RESTRICT on bob: removes MEMBER_OF (cuts group path) but
          HAS_PRIOR_ACCESS survives → some paths remain.
        QUARANTINE on server-dc01: removes ALL GRANTS + HAS_PRIOR_ACCESS
          edges to the host → all paths cut."""
        gs, sse = setup

        hypotheses = generate_mock_hypotheses(
            "bob", "workstation-01", "server-dc01",
            technique_ids=["T1078", "T1484"],
        )

        restrict = ProposedAction(
            action_type=ActionType.RESTRICT_PRIVILEGES,
            target_account_id="bob",
        )
        restrict_cont, _, _ = compute_containment(
            gs, sse, restrict, hypotheses
        )

        quarantine = ProposedAction(
            action_type=ActionType.QUARANTINE_ACCESS,
            target_host_id="server-dc01",
        )
        quarantine_cont, _, _ = compute_containment(
            gs, sse, quarantine, hypotheses
        )

        assert quarantine_cont >= restrict_cont, (
            f"QUARANTINE ({quarantine_cont}) should be at least as "
            f"aggressive as RESTRICT ({restrict_cont})"
        )
        # Both should actually cut paths (not both zero)
        assert restrict_cont > 0.0
        assert quarantine_cont > 0.0

    def test_revoke_still_works_for_direct_edge(self, setup):
        """Regression: REVOKE_SESSION still cuts direct HAS_PRIOR_ACCESS
        edges (the svc_backup case) — differentiation didn't break
        the already-correct direct-edge behavior."""
        gs, sse = setup

        hypotheses = generate_mock_hypotheses(
            "svc_backup", "workstation-01", "server-db01",
            technique_ids=["T1078", "T1550"],
        )

        revoke = ProposedAction(
            action_type=ActionType.REVOKE_SESSION,
            target_account_id="svc_backup",
        )
        containment, paths_cut, _ = compute_containment(
            gs, sse, revoke, hypotheses
        )

        # svc_backup has HAS_PRIOR_ACCESS to server-db01 → should be cut
        assert containment > 0.0
        assert paths_cut > 0
