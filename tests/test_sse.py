"""
tests/test_sse.py

Tests for the Structural Simulation Engine (perception/sse.py).

Covers:
  6.  Evidence object rejection (TypeError at security gate)
  7.  svc_backup → server-db01 FEASIBLE via direct GRANTS for T1550
  7b. bob → server-dc01 FEASIBLE via MEMBER_OF-mediated path for T1484
  8.  charlie → server-dc01 INFEASIBLE for T1484 (no matching path)
  9.  compute_path_confidence compounds multiplicatively
  10. Low-confidence structurally valid path → CONDITIONALLY_FEASIBLE
      (Correction 1: full structural match, only confidence < 0.5)
"""

from __future__ import annotations

import pytest

from perception.knowledge_graph import (
    AccessLevel,
    KnowledgeStoreGraph,
    account_node_id,
    host_node_id,
)
from perception.knowledge_store import InMemoryKnowledgeStore, KnowledgeFact
from perception.models import Evidence, TrustedField, TrustLevel
from perception.source_systems import SourceSystem
from perception.sse import (
    PathResult,
    SSEVerdict,
    StructuralSimulationEngine,
    compute_path_confidence,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tf_free(value: str) -> TrustedField:
    """Create a FREE_TEXT TrustedField (for constructing Evidence objects)."""
    return TrustedField(
        value=value,
        trust_level=TrustLevel.FREE_TEXT,
        source_system=SourceSystem.EDR,
    )


# ---------------------------------------------------------------------------
# Test 6: Evidence object rejection
# ---------------------------------------------------------------------------

class TestEvidenceRejection:
    """SSE.check() must raise TypeError when ANY argument is an Evidence
    object — this is the load-bearing security invariant."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.sse = StructuralSimulationEngine(KnowledgeStoreGraph())

    def test_evidence_as_account_id(self):
        ev = Evidence(process_name=_tf_free("notepad.exe"))
        with pytest.raises(TypeError, match="Evidence"):
            self.sse.check(ev, "host1", "host2", "T1078")

    def test_evidence_as_source_host(self):
        ev = Evidence(process_name=_tf_free("notepad.exe"))
        with pytest.raises(TypeError, match="Evidence"):
            self.sse.check("alice", ev, "host2", "T1078")

    def test_evidence_as_target_host(self):
        ev = Evidence(process_name=_tf_free("notepad.exe"))
        with pytest.raises(TypeError, match="Evidence"):
            self.sse.check("alice", "host1", ev, "T1078")

    def test_evidence_as_technique_id(self):
        ev = Evidence(process_name=_tf_free("notepad.exe"))
        with pytest.raises(TypeError, match="Evidence"):
            self.sse.check("alice", "host1", "host2", ev)


# ---------------------------------------------------------------------------
# Test 7: svc_backup → server-db01 FEASIBLE for T1550 (direct GRANTS)
# ---------------------------------------------------------------------------

class TestDirectAdminPath:
    """svc_backup has a direct GRANTS(ADMIN) edge to server-db01.
    T1550 (Pass-the-Hash) requires GRANTS >= ADMIN.  This must be
    FEASIBLE with confidence 1.0."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.graph_store = KnowledgeStoreGraph()
        self.sse = StructuralSimulationEngine(self.graph_store)

    def test_feasible(self):
        results = self.sse.check(
            "svc_backup", "workstation-01", "server-db01", "T1550"
        )
        feasible = [
            r for r in results if r.verdict == SSEVerdict.FEASIBLE
        ]
        assert len(feasible) >= 1, (
            f"Expected at least one FEASIBLE result, "
            f"got: {[r.verdict.value for r in results]}"
        )

    def test_high_confidence(self):
        results = self.sse.check(
            "svc_backup", "workstation-01", "server-db01", "T1550"
        )
        feasible = [
            r for r in results if r.verdict == SSEVerdict.FEASIBLE
        ]
        # Direct edge with confidence 1.0
        assert feasible[0].path_confidence >= 0.5

    def test_single_edge_path(self):
        results = self.sse.check(
            "svc_backup", "workstation-01", "server-db01", "T1550"
        )
        feasible = [
            r for r in results if r.verdict == SSEVerdict.FEASIBLE
        ]
        # Direct path = 1 edge
        assert len(feasible[0].edge_path) == 1


# ---------------------------------------------------------------------------
# Test 7b: bob → server-dc01 FEASIBLE for T1484 (group-mediated GRANTS)
# ---------------------------------------------------------------------------

class TestGroupMediatedPath:
    """bob is MEMBER_OF domain-admins group, which GRANTS DOMAIN_ADMIN to
    server-dc01.  T1484 requires GRANTS >= DOMAIN_ADMIN.  This must be
    FEASIBLE via the 2-edge group-mediated path, exercising the multi-hop
    grant resolution (Correction 2)."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.graph_store = KnowledgeStoreGraph()
        self.sse = StructuralSimulationEngine(self.graph_store)

    def test_feasible(self):
        results = self.sse.check(
            "bob", "workstation-01", "server-dc01", "T1484"
        )
        feasible = [
            r for r in results if r.verdict == SSEVerdict.FEASIBLE
        ]
        assert len(feasible) >= 1, (
            f"Expected FEASIBLE via group-mediated path, "
            f"got: {[r.verdict.value for r in results]}"
        )

    def test_two_edge_path(self):
        """The group-mediated path has exactly 2 edges:
        bob -> domain-admins (MEMBER_OF) -> server-dc01 (GRANTS)."""
        results = self.sse.check(
            "bob", "workstation-01", "server-dc01", "T1484"
        )
        feasible = [
            r for r in results if r.verdict == SSEVerdict.FEASIBLE
        ]
        group_paths = [
            r for r in feasible if len(r.edge_path) == 2
        ]
        assert len(group_paths) >= 1, (
            "Expected at least one 2-edge group-mediated path"
        )

    def test_bob_has_no_direct_domain_admin_grant(self):
        """Confirm bob reaches T1484 only through the group — there's no
        direct GRANTS(DOMAIN_ADMIN) edge from bob to server-dc01."""
        bob = account_node_id("bob")
        dc = host_node_id("server-dc01")
        g = self.graph_store.graph
        if g.has_edge(bob, dc):
            edges = g[bob][dc]
            direct_da_grants = [
                d for d in edges.values()
                if d.get("edge_type") == "GRANTS"
                and isinstance(d.get("access_level"), KnowledgeFact)
                and d["access_level"].value >= AccessLevel.DOMAIN_ADMIN
            ]
            assert len(direct_da_grants) == 0, (
                "bob should NOT have a direct GRANTS(DOMAIN_ADMIN) edge "
                "to server-dc01 — the path must go through domain-admins group"
            )


# ---------------------------------------------------------------------------
# Test 8: charlie → server-dc01 INFEASIBLE for T1484
# ---------------------------------------------------------------------------

class TestInfeasiblePath:
    """charlie has no GRANTS or MEMBER_OF edges that could satisfy T1484's
    requirement of DOMAIN_ADMIN access to server-dc01."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.sse = StructuralSimulationEngine(KnowledgeStoreGraph())

    def test_infeasible(self):
        results = self.sse.check(
            "charlie", "workstation-01", "server-dc01", "T1484"
        )
        assert len(results) == 1
        assert results[0].verdict == SSEVerdict.INFEASIBLE

    def test_has_failure_reason(self):
        results = self.sse.check(
            "charlie", "workstation-01", "server-dc01", "T1484"
        )
        assert results[0].dependency_note is not None
        assert len(results[0].dependency_note) > 0

    def test_empty_edge_path(self):
        results = self.sse.check(
            "charlie", "workstation-01", "server-dc01", "T1484"
        )
        assert results[0].edge_path == []

    def test_zero_confidence(self):
        results = self.sse.check(
            "charlie", "workstation-01", "server-dc01", "T1484"
        )
        assert results[0].path_confidence == 0.0


# ---------------------------------------------------------------------------
# Test 9: compute_path_confidence compounds multiplicatively
# ---------------------------------------------------------------------------

class TestPathConfidence:
    """compute_path_confidence multiplies — not averages, not maxes."""

    def test_two_values(self):
        assert compute_path_confidence([0.9, 0.6]) == pytest.approx(0.54)

    def test_single_value(self):
        assert compute_path_confidence([0.5]) == pytest.approx(0.5)

    def test_all_ones(self):
        assert compute_path_confidence([1.0, 1.0, 1.0]) == pytest.approx(1.0)

    def test_empty_list(self):
        """No edges = no uncertainty → 1.0"""
        assert compute_path_confidence([]) == 1.0

    def test_three_values(self):
        assert compute_path_confidence([0.9, 0.8, 0.7]) == pytest.approx(0.504)

    def test_low_confidence_chain(self):
        """Long chain of low confidence compounds severely."""
        assert compute_path_confidence([0.3, 0.3]) == pytest.approx(0.09)


# ---------------------------------------------------------------------------
# Test 10: CONDITIONALLY_FEASIBLE — structurally valid, low confidence
# ---------------------------------------------------------------------------

class TestConditionallyFeasible:
    """
    A structurally complete, valid path that matches the technique's
    required_edge_sequence but has low compounded confidence (< 0.5)
    must be classified CONDITIONALLY_FEASIBLE — NOT INFEASIBLE and
    NOT FEASIBLE.

    Setup:
        mallory → WKSTN-9998 via GRANTS(ADMIN, confidence=0.3)
        Technique T1550 requires GRANTS >= ADMIN

    The path is a COMPLETE match:
        - Edge type: GRANTS (matches)
        - Access level: ADMIN >= ADMIN (matches)
        - All required hops present: 1 edge, 1 hop (matches)
    Only the edge confidence (0.3) is low, giving path_confidence=0.3 < 0.5.

    This test demonstrates Correction 1: structural validity and confidence
    classification are SEPARATE, INDEPENDENT checks.  A structurally valid
    path with low confidence is CONDITIONALLY_FEASIBLE.  An invalid path
    (wrong edge types, missing hops) is INFEASIBLE regardless of confidence.
    """

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.graph_store = KnowledgeStoreGraph()
        self.sse = StructuralSimulationEngine(self.graph_store)

    def test_verdict_is_conditionally_feasible(self):
        results = self.sse.check(
            "mallory", "workstation-01", "WKSTN-9998", "T1550"
        )

        assert len(results) >= 1, "Must find at least one result"

        cond = [
            r for r in results
            if r.verdict == SSEVerdict.CONDITIONALLY_FEASIBLE
        ]
        assert len(cond) >= 1, (
            f"Expected CONDITIONALLY_FEASIBLE, "
            f"got: {[r.verdict.value for r in results]}"
        )

    def test_structural_validity_checked_before_confidence(self):
        """
        The path's edge_path is non-empty, confirming it passed FULL
        structural validation (correct edge types, correct order, all
        required hops present) BEFORE confidence classification was
        applied.

        Structural validation and confidence classification are separate:
            Step 1: Does the path match the required_edge_sequence?  → YES
            Step 2: Is path_confidence >= 0.5?                       → NO
            Result: CONDITIONALLY_FEASIBLE (not INFEASIBLE)
        """
        results = self.sse.check(
            "mallory", "workstation-01", "WKSTN-9998", "T1550"
        )

        cond = [
            r for r in results
            if r.verdict == SSEVerdict.CONDITIONALLY_FEASIBLE
        ]
        result = cond[0]

        # Non-empty edge_path = structural validation passed
        assert len(result.edge_path) > 0, (
            "Path should have been found — structural validation must pass "
            "before confidence classification is applied"
        )

        # This result is NOT INFEASIBLE despite low confidence.
        # A structurally valid path must never be classified INFEASIBLE —
        # low confidence alone does not invalidate structural feasibility.
        assert result.verdict != SSEVerdict.INFEASIBLE, (
            "A structurally valid path must never be INFEASIBLE — "
            "low confidence alone does not invalidate structural feasibility"
        )

    def test_confidence_below_threshold(self):
        results = self.sse.check(
            "mallory", "workstation-01", "WKSTN-9998", "T1550"
        )
        cond = [
            r for r in results
            if r.verdict == SSEVerdict.CONDITIONALLY_FEASIBLE
        ]
        assert cond[0].path_confidence < 0.5

    def test_dependency_note_non_empty(self):
        """CONDITIONALLY_FEASIBLE must name the weak link."""
        results = self.sse.check(
            "mallory", "workstation-01", "WKSTN-9998", "T1550"
        )
        cond = [
            r for r in results
            if r.verdict == SSEVerdict.CONDITIONALLY_FEASIBLE
        ]
        assert cond[0].dependency_note is not None
        assert len(cond[0].dependency_note) > 0

    def test_not_feasible(self):
        """Must NOT be classified FEASIBLE (confidence < 0.5)."""
        results = self.sse.check(
            "mallory", "workstation-01", "WKSTN-9998", "T1550"
        )
        feasible = [
            r for r in results
            if r.verdict == SSEVerdict.FEASIBLE
        ]
        assert len(feasible) == 0, (
            "Path with confidence 0.3 must NOT be FEASIBLE"
        )


# ---------------------------------------------------------------------------
# Additional SSE tests — technique coverage
# ---------------------------------------------------------------------------

class TestT1078ValidAccounts:
    """T1078 uses HAS_PRIOR_ACCESS or GRANTS >= READ."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.sse = StructuralSimulationEngine(KnowledgeStoreGraph())

    def test_alice_has_prior_access_to_workstation_01(self):
        """alice has HAS_PRIOR_ACCESS to workstation-01 from baseline."""
        results = self.sse.check(
            "alice", "workstation-01", "workstation-01", "T1078"
        )
        feasible = [r for r in results if r.verdict == SSEVerdict.FEASIBLE]
        assert len(feasible) >= 1


class TestT1071C2:
    """T1071 checks outbound EGRESS on port 443/80 from source zone."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.sse = StructuralSimulationEngine(KnowledgeStoreGraph())

    def test_workstation_has_external_egress(self):
        """Workstation zone has EGRESS to EXTERNAL on port 443."""
        results = self.sse.check(
            "alice", "workstation-01", "some-external-c2", "T1071"
        )
        feasible = [
            r for r in results
            if r.verdict in (SSEVerdict.FEASIBLE, SSEVerdict.CONDITIONALLY_FEASIBLE)
        ]
        assert len(feasible) >= 1, (
            f"Expected at least one feasible C2 path, "
            f"got: {[r.verdict.value for r in results]}"
        )


class TestUnknownTechnique:
    """Unknown technique IDs return INFEASIBLE."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.sse = StructuralSimulationEngine(KnowledgeStoreGraph())

    def test_unknown_technique_infeasible(self):
        results = self.sse.check("alice", "host1", "host2", "T9999")
        assert len(results) == 1
        assert results[0].verdict == SSEVerdict.INFEASIBLE
        assert "Unknown technique" in results[0].dependency_note
