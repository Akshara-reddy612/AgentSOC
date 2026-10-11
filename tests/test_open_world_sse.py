"""
Decision (a), DEDALE Phase 3 (2026-10-11): open-world SSE for hosts the store
has no telemetry from.  A missing access path to a host outside the profile's
observed_hosts is "not known" (CONDITIONALLY_FEASIBLE -> review), not
"impossible".  Closed-world profiles (observed_hosts None) are unchanged.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from dedale.environment import DEDALE_PROFILE, seed_store
from perception.environment import DEFAULT_PROFILE, EnvironmentProfile
from perception.host_detection import DETECTORS, learn_key
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.sse import SSEVerdict, StructuralSimulationEngine

T0 = datetime(2024, 12, 23, tzinfo=timezone.utc)


@pytest.fixture()
def db(tmp_path):
    with KnowledgeDB(tmp_path / "ks.sqlite", DEDALE_PROFILE, created_at=T0) as store:
        seed_store(store, T0)
        yield store


def _verdict(graph_store, target, technique="T1039", account="breach\\client1", source="CLIENT1"):
    return StructuralSimulationEngine(graph_store).check(account, source, target, technique)[0].verdict


def test_profile_observes_hosts():
    assert DEFAULT_PROFILE.observes_host("CLIENT1") is None                 # closed world: not modelled
    assert DEDALE_PROFILE.observes_host("client7") is True
    assert DEDALE_PROFILE.observes_host("CLIENT7.breach.local") is True
    assert DEDALE_PROFILE.observes_host("internalserver") is False
    assert DEDALE_PROFILE.observes_host("") is False


def test_profile_round_trip_and_default_dict_unchanged():
    assert "observed_hosts" not in DEFAULT_PROFILE.to_dict()                # existing stores stay readable
    again = EnvironmentProfile.from_dict(DEDALE_PROFILE.to_dict())
    assert again.to_dict() == DEDALE_PROFILE.to_dict() and again.observes_host("CLIENT30") is True


def test_unobserved_target_is_not_known_rather_than_impossible(db):
    for target in ("172.16.0.2", "internalserver", "172.19.0.2", "Z:", "unknown"):
        assert _verdict(db.graph, target) == SSEVerdict.CONDITIONALLY_FEASIBLE, target
    note = StructuralSimulationEngine(db.graph).check("root", "CLIENT1", "172.16.0.2", "T1021.004")[0]
    assert "no telemetry" in note.dependency_note


def test_observed_target_without_access_stays_infeasible(db):
    assert _verdict(db.graph, "CLIENT2", technique="T1078") == SSEVerdict.INFEASIBLE
    assert _verdict(db.graph, "172.16.1.3", technique="T1078") == SSEVerdict.INFEASIBLE   # CLIENT2's address


def test_learned_access_is_still_feasible(db):
    learn_key(db, "logon", DETECTORS["logon"].key({"ch": "security", "code": 4624, "host": "CLIENT2",
                                                   "user": "BREACH\\client1", "logon_type": "3", "ip": "-"}),
              provenance="training", at=T0, writer="test")
    assert _verdict(db.graph, "CLIENT2", technique="T1078") == SSEVerdict.FEASIBLE


def test_closed_world_profile_unchanged():
    assert _verdict(KnowledgeStoreGraph(), "SRV-UNKNOWN-99", technique="T1078", account="nobody",
                    source="WKSTN-00001") == SSEVerdict.INFEASIBLE
