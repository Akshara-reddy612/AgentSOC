"""
Design step S2 (2026-10-11): persistent Knowledge Store (perception/knowledge_db.py).
A graph written to the store and read back is identical, the pipeline gives the
same results on it, every write is in an append-only audit log that can rebuild
the graph, and failed writes leave neither the file nor the projection changed.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from perception.defended_pipeline import run_downstream
from perception.enterprise_model import INVENTORY
from perception.environment import DEFAULT_PROFILE, EnvironmentProfile
from perception.knowledge_db import KnowledgeDB, decode_value, encode_value, graph_signature
from perception.knowledge_graph import AccessLevel, AccountType, HostClass, KnowledgeStoreGraph, destination_node_id
from perception.knowledge_store import KnowledgeFact
from perception.nce_contract import NCEHypothesis
from perception.network_model import SYNTHETIC_DESTINATIONS
from perception.source_systems import SourceSystem

T0 = datetime(2024, 12, 23, tzinfo=timezone.utc)
U = next(a for a in INVENTORY.by_role("standard_user") if not a.local_admin)
KNOWN_BAD = next(d["address"] for d in SYNTHETIC_DESTINATIONS if d["reputation"] == "known_bad" and d["kind"] == "domain")


@pytest.fixture()
def stored(tmp_path):
    """The synthetic enterprise graph written to a store file, plus that file's path."""
    kg = KnowledgeStoreGraph()
    path = tmp_path / "ks.sqlite"
    with KnowledgeDB(path, kg.profile, created_at=T0) as db:
        db.import_graph(kg, writer="test", at=T0)
    return kg, path


def test_round_trip_is_exact(stored):
    kg, path = stored
    with KnowledgeDB(path) as db:
        assert graph_signature(db.graph.graph) == graph_signature(kg.graph)
        assert db.profile.to_dict() == kg.profile.to_dict()
        assert db.graph.profile.to_dict() == DEFAULT_PROFILE.to_dict()
        assert list(db.graph.graph.nodes) == list(kg.graph.nodes)          # node order kept
        assert db.learned_from("zone:WORKSTATION") == "config"


def test_pipeline_results_identical_on_the_stored_graph(stored):
    kg, path = stored
    own = NCEHypothesis(technique_id="T1078", source_account=U.account_id, source_host=U.home_host,
                        target_host=U.home_host, nce_confidence=0.6, supporting_evidence_refs=["raw_log_line"])
    base = {"source_user": U.account_id, "source_host": U.home_host, "target_host": U.home_host}
    cases = [([own], base),                                                   # expected activity
             ([], {**base, "destination_domain": "cdn321.example"}),          # telemetry C2, unknown
             ([own], {**base, "destination_domain": KNOWN_BAD})]              # known-bad escalation
    with KnowledgeDB(path) as db:
        for hyps, alert in cases:
            assert run_downstream(hyps, alert, db.graph) == run_downstream(hyps, alert, kg)
        assert db.projection_matches_store()          # the pipeline did not change the graph


def test_audit_log_is_append_only(stored):
    _, path = stored
    with KnowledgeDB(path) as db:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            db._con.execute("UPDATE ks_log SET writer = 'x' WHERE seq = 1")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            db._con.execute("DELETE FROM ks_log")
        first = next(db.audit_log())
        assert first["op"] == "set_profile" and first["payload"] == DEFAULT_PROFILE.to_dict()


def test_fact_versions_history_and_log_replay(stored):
    _, path = stored
    node = destination_node_id("cdn321.example")
    with KnowledgeDB(path) as db:
        db.add_node(node, {"node_type": "ExternalDestination", "address": "cdn321.example", "kind": "domain"},
                    writer="test", at=T0, learned_from="telemetry")
        db.set_fact(node, "reputation", "unknown", confidence=1.0, source=SourceSystem.KNOWLEDGE_STORE,
                    writer="test", at=T0 + timedelta(days=1))
        before_confirm = db.last_seq()
        f = db.set_fact(node, "reputation", "known_bad", confidence=0.9, source=SourceSystem.KNOWLEDGE_STORE,
                        writer="analyst:test", at=T0 + timedelta(days=2))
        assert f.version == 2 and [h.value for h in f.audit_history] == ["unknown"]
        assert db.graph.get_destination_reputation("cdn321.example")[0] == "known_bad"
        assert graph_signature(db.replay_log()) == graph_signature(db.graph.graph)
        assert db.replay_log(before_confirm).nodes[node]["reputation"].value == "unknown"
    with KnowledgeDB(path) as db:                                               # persisted
        assert db.graph.graph.nodes[node]["reputation"] == f
        assert db.learned_from(node) == "telemetry"


def test_failed_batch_leaves_store_and_projection_unchanged(stored):
    _, path = stored
    with KnowledgeDB(path) as db:
        seq, sig = db.last_seq(), graph_signature(db.graph.graph)
        with pytest.raises(KeyError):
            with db.batch():
                db.add_node("host:NEW-1", {"node_type": "HostNode", "host_id": "NEW-1"},
                            writer="test", at=T0, learned_from="telemetry")
                db.add_edge("host:NEW-1", "host:MISSING", "HOSTED_IN", {"edge_type": "HOSTED_IN"},
                            writer="test", at=T0, learned_from="telemetry")
        assert db.last_seq() == seq and graph_signature(db.graph.graph) == sig
        assert "host:NEW-1" not in db.graph.graph and db.projection_matches_store()


@pytest.mark.parametrize("kwargs, error", [
    ({"writer": ""}, ValueError),
    ({"at": datetime(2025, 1, 1)}, ValueError),                     # naive time
    ({"learned_from": "guess"}, ValueError),
])
def test_writes_need_writer_time_and_provenance(stored, kwargs, error):
    _, path = stored
    args = {"writer": "test", "at": T0, "learned_from": "telemetry", **kwargs}
    with KnowledgeDB(path) as db, pytest.raises(error):
        db.add_node("host:NEW-2", {"node_type": "HostNode"}, **args)


def test_projection_cannot_be_changed_through_caller_objects(stored):
    _, path = stored
    services = ["ssh"]
    with KnowledgeDB(path) as db:
        db.add_node("host:NEW-3", {"node_type": "HostNode", "services": services},
                    writer="test", at=T0, learned_from="telemetry")
        services.append("rdp")
        assert db.graph.graph.nodes["host:NEW-3"]["services"] == ["ssh"]
        db.graph.graph.add_node("host:SNEAKY", node_type="HostNode")        # bypasses the store
        assert not db.projection_matches_store()


def test_store_keeps_its_own_profile(stored):
    _, path = stored
    lab = EnvironmentProfile(name="lab", internal_networks=("172.16.0.0/16",))
    with pytest.raises(ValueError, match="different environment profile"):
        KnowledgeDB(path, lab)
    with pytest.raises(ValueError, match="needs an environment profile"):
        KnowledgeDB(path.with_name("new.sqlite"))


def test_typed_json_round_trip():
    old = KnowledgeFact(value=AccessLevel.ADMIN, version=1, confidence=0.8, source=SourceSystem.EDR, timestamp=T0)
    fact = KnowledgeFact(value=HostClass.WORKSTATION, version=2, confidence=0.5, source=SourceSystem.SIEM,
                         timestamp=T0 + timedelta(microseconds=7), audit_history=[old])
    value = {"f": fact, "t": (1, "a", AccountType.SERVICE_ACCOUNT), "d": T0, "l": [None, True, 1.5]}
    assert decode_value(encode_value(value)) == value
    with pytest.raises(TypeError):
        encode_value({"__fact__": 1})                    # would be ambiguous on reading
    with pytest.raises(TypeError):
        encode_value({1, 2})                             # unsupported type
