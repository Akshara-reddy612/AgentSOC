"""
tests/test_nce_contract.py

Tests for the NCE data contract (perception/nce_contract.py).

Covers:
  1. NCEHypothesis rejects unknown technique_id
  2. NCEHypothesis rejects nce_confidence outside [0,1]
  3. generate_mock_hypotheses returns valid objects
  4. NCE → SSE → RSEM end-to-end integration (MOST IMPORTANT TEST)
  5. MissingContextFlag enum validation
  6. HypothesisStatus lifecycle
  7. NCEInput evidence-only enforcement
  8. NCEOutput batch validation
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import (
    FORBIDDEN_FIELD_NAMES,
    HypothesisStatus,
    MissingContextFlag,
    NCEHypothesis,
    NCEInput,
    NCEOutput,
    generate_mock_hypotheses,
    generate_mock_nce_output,
)
from perception.rsem import (
    ActionType,
    ProposedAction,
    compute_containment,
)
from perception.sse import StructuralSimulationEngine, TECHNIQUE_TABLE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_hypothesis(
    technique_id: str = "T1078",
    nce_confidence: float = 0.8,
    missing_context_flags: list | None = None,
    status: HypothesisStatus = HypothesisStatus.GENERATED,
    incident_id: str | None = None,
) -> NCEHypothesis:
    """Convenience factory for tests that need a valid hypothesis."""
    return NCEHypothesis(
        technique_id=technique_id,
        source_account="alice",
        source_host="workstation-01",
        target_host="server-dc01",
        nce_confidence=nce_confidence,
        supporting_evidence_refs=["raw_log_line"],
        missing_context_flags=missing_context_flags or [],
        status=status,
        incident_id=incident_id,
    )


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


# ===========================================================================
# NEW TESTS — Phase NCE-1 contract extensions
# ===========================================================================


# ---------------------------------------------------------------------------
# Test 5: MissingContextFlag enum validation
# ---------------------------------------------------------------------------

class TestMissingContextFlag:
    """MissingContextFlag enum rejects invalid values and accepts valid ones."""

    def test_rejects_raw_string_flag(self):
        """A raw string that matches a flag's value must still be rejected —
        only MissingContextFlag enum members are valid."""
        with pytest.raises(ValueError, match="MissingContextFlag"):
            _make_hypothesis(
                missing_context_flags=["target_privilege_level"],  # type: ignore[list-item]
            )

    def test_rejects_unknown_string_flag(self):
        """A string not matching any flag value is also rejected."""
        with pytest.raises(ValueError, match="MissingContextFlag"):
            _make_hypothesis(
                missing_context_flags=["totally_made_up_flag"],  # type: ignore[list-item]
            )

    def test_accepts_all_five_flags_individually(self):
        """Each of the 5 valid MissingContextFlag values is accepted alone."""
        for flag in MissingContextFlag:
            h = _make_hypothesis(missing_context_flags=[flag])
            assert h.missing_context_flags == [flag]

    def test_accepts_all_five_flags_combined(self):
        """All 5 valid flags can be used together."""
        all_flags = list(MissingContextFlag)
        h = _make_hypothesis(missing_context_flags=all_flags)
        assert h.missing_context_flags == all_flags
        assert len(h.missing_context_flags) == 5

    def test_exactly_five_flags_defined(self):
        """The enum has exactly 5 members — no more, no fewer."""
        assert len(MissingContextFlag) == 5
        expected = {
            "TARGET_PRIVILEGE_LEVEL",
            "PRIOR_ACCESS",
            "NETWORK_REACHABILITY",
            "TARGET_CRITICALITY",
            "TARGET_HOST_CLASS",
        }
        assert {f.name for f in MissingContextFlag} == expected


# ---------------------------------------------------------------------------
# Test 6: HypothesisStatus defaults and transitions
# ---------------------------------------------------------------------------

class TestHypothesisStatus:
    """HypothesisStatus defaults to GENERATED and transitions correctly."""

    def test_defaults_to_generated(self):
        """A newly constructed hypothesis has status GENERATED."""
        h = _make_hypothesis()
        assert h.status == HypothesisStatus.GENERATED

    def test_with_status_produces_updated_copy(self):
        """with_status() returns a new hypothesis with updated status."""
        original = _make_hypothesis()
        validated = original.with_status(HypothesisStatus.SSE_VALIDATED)

        # New instance has the updated status
        assert validated.status == HypothesisStatus.SSE_VALIDATED
        # All other fields are preserved
        assert validated.technique_id == original.technique_id
        assert validated.source_account == original.source_account
        assert validated.nce_confidence == original.nce_confidence

    def test_with_status_does_not_mutate_original(self):
        """The original hypothesis is unchanged after with_status()."""
        original = _make_hypothesis()
        _ = original.with_status(HypothesisStatus.FEASIBLE)

        # Original must still be GENERATED
        assert original.status == HypothesisStatus.GENERATED

    def test_frozen_prevents_direct_mutation(self):
        """Direct attribute assignment raises FrozenInstanceError."""
        h = _make_hypothesis()
        with pytest.raises(AttributeError):
            h.status = HypothesisStatus.INFEASIBLE  # type: ignore[misc]

    def test_full_lifecycle_chain(self):
        """A hypothesis can traverse the full GENERATED → SELECTED chain."""
        h = _make_hypothesis()
        h = h.with_status(HypothesisStatus.SSE_VALIDATED)
        h = h.with_status(HypothesisStatus.FEASIBLE)
        h = h.with_status(HypothesisStatus.RSEM_RANKED)
        h = h.with_status(HypothesisStatus.SELECTED)
        assert h.status == HypothesisStatus.SELECTED

    def test_infeasible_retained_not_deleted(self):
        """An INFEASIBLE hypothesis is retained as a valid object."""
        h = _make_hypothesis()
        h = h.with_status(HypothesisStatus.INFEASIBLE)
        assert h.status == HypothesisStatus.INFEASIBLE
        # Still a fully valid NCEHypothesis — not deleted/None
        assert isinstance(h, NCEHypothesis)
        assert h.technique_id in TECHNIQUE_TABLE


# ---------------------------------------------------------------------------
# Test 7: NCEInput evidence-only enforcement
# ---------------------------------------------------------------------------

class TestNCEInput:
    """NCEInput rejects forbidden trusted-context keys and accepts valid ones."""

    def test_rejects_forbidden_key_user_role(self):
        """evidence_fields containing 'user_role' (an ImmutableContext field)
        must be rejected."""
        with pytest.raises(ValueError, match="forbidden trusted-context"):
            NCEInput(
                incident_id="INC-001",
                evidence_fields={
                    "raw_log_line": "some log data",
                    "user_role": "admin",  # FORBIDDEN
                },
                timestamp=datetime.now(tz=timezone.utc),
            )

    def test_rejects_forbidden_key_asset_criticality(self):
        """evidence_fields containing 'asset_criticality' must be rejected."""
        with pytest.raises(ValueError, match="forbidden trusted-context"):
            NCEInput(
                incident_id="INC-001",
                evidence_fields={"asset_criticality": "high"},
                timestamp=datetime.now(tz=timezone.utc),
            )

    def test_rejects_forbidden_key_network_zone(self):
        """evidence_fields containing 'network_zone' must be rejected."""
        with pytest.raises(ValueError, match="forbidden trusted-context"):
            NCEInput(
                incident_id="INC-001",
                evidence_fields={"network_zone": "dmz"},
                timestamp=datetime.now(tz=timezone.utc),
            )

    def test_rejects_forbidden_key_historical_access(self):
        """evidence_fields containing 'historical_access' must be rejected."""
        with pytest.raises(ValueError, match="forbidden trusted-context"):
            NCEInput(
                incident_id="INC-001",
                evidence_fields={"historical_access": "true"},
                timestamp=datetime.now(tz=timezone.utc),
            )

    def test_rejects_derived_context_key(self):
        """DerivedContext field names are also forbidden."""
        for key in ("no_prior_access", "cross_zone_access",
                     "high_criticality_target", "privilege_escalation_risk"):
            with pytest.raises(ValueError, match="forbidden trusted-context"):
                NCEInput(
                    incident_id="INC-001",
                    evidence_fields={key: "some_value"},
                    timestamp=datetime.now(tz=timezone.utc),
                )

    def test_accepts_valid_evidence_keys(self):
        """Normal raw-evidence keys are accepted."""
        nce_input = NCEInput(
            incident_id="INC-001",
            evidence_fields={
                "raw_log_line": "2026-09-01 SECURITY[4624] Logon",
                "command_line": "powershell.exe -enc AAAA",
                "registry_key": r"HKLM\Software\Microsoft\...",
                "process_name": "svchost.exe",
                "source_ip": "10.0.0.42",
            },
            timestamp=datetime.now(tz=timezone.utc),
        )
        assert nce_input.incident_id == "INC-001"
        assert len(nce_input.evidence_fields) == 5

    def test_rejects_empty_evidence_fields(self):
        """An empty evidence_fields dict is rejected — NCE cannot generate
        hypotheses without any evidence to reason about."""
        with pytest.raises(ValueError, match="must not be empty"):
            NCEInput(
                incident_id="INC-002",
                evidence_fields={},
                timestamp=datetime.now(tz=timezone.utc),
            )

    def test_forbidden_field_names_complete(self):
        """FORBIDDEN_FIELD_NAMES contains all ImmutableContext and
        DerivedContext field names."""
        expected = {
            "user_role", "asset_criticality", "network_zone",
            "historical_access",
            "no_prior_access", "cross_zone_access",
            "high_criticality_target", "privilege_escalation_risk",
        }
        assert FORBIDDEN_FIELD_NAMES == expected


# ---------------------------------------------------------------------------
# Test 8: NCEOutput batch validation
# ---------------------------------------------------------------------------

class TestNCEOutput:
    """NCEOutput validates hypothesis count and incident_id consistency."""

    def test_rejects_zero_hypotheses(self):
        """An empty hypothesis tuple is invalid."""
        with pytest.raises(ValueError, match="at least 1"):
            NCEOutput(incident_id="INC-001", hypotheses=())

    def test_rejects_more_than_three_hypotheses(self):
        """More than 3 hypotheses exceeds the locked design cap."""
        hyps = tuple(
            _make_hypothesis(
                technique_id=tid, incident_id="INC-001"
            )
            for tid in ["T1078", "T1550", "T1562", "T1484"]
        )
        with pytest.raises(ValueError, match="at most 3"):
            NCEOutput(incident_id="INC-001", hypotheses=hyps)

    def test_rejects_mismatched_incident_id(self):
        """A hypothesis with a different incident_id is rejected."""
        h = _make_hypothesis(incident_id="INC-WRONG")
        with pytest.raises(ValueError, match="does not match"):
            NCEOutput(incident_id="INC-001", hypotheses=(h,))

    def test_accepts_valid_single_hypothesis(self):
        """A single valid hypothesis is accepted."""
        h = _make_hypothesis(incident_id="INC-001")
        output = NCEOutput(incident_id="INC-001", hypotheses=(h,))
        assert len(output.hypotheses) == 1
        assert output.incident_id == "INC-001"

    def test_accepts_valid_three_hypothesis_batch(self):
        """A batch of 3 valid hypotheses is accepted."""
        hyps = tuple(
            _make_hypothesis(
                technique_id=tid, incident_id="INC-001"
            )
            for tid in ["T1078", "T1550", "T1562"]
        )
        output = NCEOutput(incident_id="INC-001", hypotheses=hyps)
        assert len(output.hypotheses) == 3

    def test_rejects_hypothesis_with_none_incident_id(self):
        """A hypothesis with incident_id=None is rejected by NCEOutput —
        once you're assembling a batch, every hypothesis must be fully
        stamped.  NCEHypothesis allows None for standalone SSE/RSEM use,
        but NCEOutput does not."""
        h = _make_hypothesis(incident_id=None)
        with pytest.raises(ValueError, match="does not match"):
            NCEOutput(incident_id="INC-001", hypotheses=(h,))

    def test_generate_mock_nce_output(self):
        """generate_mock_nce_output() returns a valid NCEOutput."""
        output = generate_mock_nce_output(
            incident_id="INC-MOCK",
            account_id="svc_backup",
            source_host="workstation-01",
            target_host="server-db01",
        )
        assert isinstance(output, NCEOutput)
        assert output.incident_id == "INC-MOCK"
        assert 1 <= len(output.hypotheses) <= 3
        for h in output.hypotheses:
            assert h.incident_id == "INC-MOCK"


# ---------------------------------------------------------------------------
# Test 9: Existing NCE → SSE → RSEM integration still works
# ---------------------------------------------------------------------------

class TestExistingIntegrationUnchanged:
    """Confirm that the existing test_rsem.py integration test scenario
    still works after the contract extensions — generate_mock_hypotheses()
    returns list[NCEHypothesis] with the same shape it always did."""

    def test_mock_hypotheses_compatible_with_rsem(self):
        """Reproduces the exact scenario from test_rsem.py's
        TestRevokeSession to confirm nothing regressed."""
        gs = KnowledgeStoreGraph()
        sse = StructuralSimulationEngine(gs)
        hypotheses = generate_mock_hypotheses(
            "svc_backup", "workstation-01", "server-db01",
            technique_ids=["T1078", "T1550"],
        )

        # Type check: still returns list[NCEHypothesis]
        assert isinstance(hypotheses, list)
        for h in hypotheses:
            assert isinstance(h, NCEHypothesis)
            # Default status should be GENERATED
            assert h.status == HypothesisStatus.GENERATED
            # missing_context_flags should be empty list (not strings)
            assert h.missing_context_flags == []

        # Still feeds into compute_containment
        action = ProposedAction(
            action_type=ActionType.REVOKE_SESSION,
            target_account_id="svc_backup",
        )
        containment, paths_cut, paths_total = compute_containment(
            gs, sse, action, hypotheses
        )
        assert containment > 0.0
        assert paths_cut > 0
