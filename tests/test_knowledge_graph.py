"""
tests/test_knowledge_graph.py

Tests for the graph-backed Knowledge Store (perception/knowledge_graph.py).

Covers:
  1. classify_host() correctness for all known patterns + UNKNOWN fallback
  2. Lossless migration from InMemoryKnowledgeStore (every toy dict entry
     has a corresponding graph node/edge)
  3. get_or_create_host_node idempotency
  4. Unseen "WKSTN-9999"-style hostname → WORKSTATION, confidence 0.8
  5. Garbage hostname → UNKNOWN, confidence 0.0, no crash
"""

from __future__ import annotations

import pytest

from perception.knowledge_graph import (
    AccessLevel,
    AccountType,
    HostClass,
    KnowledgeStoreGraph,
    account_node_id,
    classify_host,
    group_node_id,
    host_node_id,
    zone_node_id,
)
from perception.knowledge_store import InMemoryKnowledgeStore, KnowledgeFact


# ---------------------------------------------------------------------------
# Test 1: classify_host() correctness
# ---------------------------------------------------------------------------

class TestClassifyHost:
    """classify_host() correctly classifies each known template pattern
    and returns UNKNOWN / 0.0 for unrecognised strings."""

    def test_workstation_pattern(self):
        cls, conf = classify_host("WKSTN-1234")
        assert cls == HostClass.WORKSTATION
        assert conf == 0.8

    def test_workstation_pattern_large_rand(self):
        cls, conf = classify_host("WKSTN-9999")
        assert cls == HostClass.WORKSTATION
        assert conf == 0.8

    def test_file_server_pattern(self):
        cls, conf = classify_host("SRV-FILE4330")
        assert cls == HostClass.FILE_SERVER
        assert conf == 0.8

    def test_laptop_pattern(self):
        cls, conf = classify_host("LT-8430-CORP")
        assert cls == HostClass.LAPTOP_CORP
        assert conf == 0.8

    def test_exact_match_workstation_01(self):
        cls, conf = classify_host("workstation-01")
        assert cls == HostClass.WORKSTATION
        assert conf == 1.0

    def test_exact_match_workstation_02(self):
        cls, conf = classify_host("workstation-02")
        assert cls == HostClass.WORKSTATION
        assert conf == 1.0

    def test_exact_match_domain_controller(self):
        cls, conf = classify_host("server-dc01")
        assert cls == HostClass.DOMAIN_CONTROLLER
        assert conf == 1.0

    def test_exact_match_db_server(self):
        cls, conf = classify_host("server-db01")
        assert cls == HostClass.DB_SERVER
        assert conf == 1.0

    def test_exact_match_web_server(self):
        cls, conf = classify_host("server-web01")
        assert cls == HostClass.FILE_SERVER
        assert conf == 1.0

    def test_unknown_garbage(self):
        cls, conf = classify_host("totally-random-garbage-xyz")
        assert cls == HostClass.UNKNOWN
        assert conf == 0.0

    def test_empty_string(self):
        cls, conf = classify_host("")
        assert cls == HostClass.UNKNOWN
        assert conf == 0.0

    def test_case_insensitive_pattern(self):
        cls, conf = classify_host("wkstn-5555")
        assert cls == HostClass.WORKSTATION
        assert conf == 0.8

    def test_case_insensitive_exact_match(self):
        """Exact match lookup is case-insensitive (lowered)."""
        cls, conf = classify_host("Server-DC01")
        assert cls == HostClass.DOMAIN_CONTROLLER
        assert conf == 1.0


# ---------------------------------------------------------------------------
# Test 2: Lossless migration from InMemoryKnowledgeStore
# ---------------------------------------------------------------------------

class TestLosslessMigration:
    """Every entry in InMemoryKnowledgeStore's existing toy dicts
    (_user_privilege, _asset_info, _topology, _access_baseline) has a
    corresponding node/edge in the graph after construction."""

    @pytest.fixture
    def store(self):
        return InMemoryKnowledgeStore()

    @pytest.fixture
    def graph(self, store):
        return KnowledgeStoreGraph(store)

    def test_all_users_have_account_nodes(self, store, graph):
        for user_id in store._user_privilege:
            node_id = account_node_id(user_id)
            assert node_id in graph.graph, f"Missing AccountNode for {user_id}"
            assert graph.graph.nodes[node_id]["node_type"] == "AccountNode"

    def test_all_hosts_have_host_nodes(self, store, graph):
        for host_id_str in store._asset_info:
            node_id = host_node_id(host_id_str)
            assert node_id in graph.graph, f"Missing HostNode for {host_id_str}"
            assert graph.graph.nodes[node_id]["node_type"] == "HostNode"

    def test_all_hosts_have_hosted_in_edge(self, store, graph):
        for host_id_str, asset_fact in store._asset_info.items():
            h_node = host_node_id(host_id_str)
            zone_str = asset_fact.value.get("zone", "UNKNOWN")
            z_node = zone_node_id(zone_str)
            assert graph.graph.has_edge(h_node, z_node), (
                f"Missing HOSTED_IN from {host_id_str} to {zone_str}"
            )

    def test_all_reachable_topology_has_egress(self, store, graph):
        for (src_zone, dst_zone), topo_fact in store._topology.items():
            if topo_fact.value:  # reachable
                src = zone_node_id(src_zone)
                dst = zone_node_id(dst_zone)
                assert src in graph.graph, f"Missing ZoneNode for {src_zone}"
                assert dst in graph.graph, f"Missing ZoneNode for {dst_zone}"
                assert graph.graph.has_edge(src, dst), (
                    f"Missing edge from {src_zone} to {dst_zone}"
                )
                edges = graph.graph[src][dst]
                egress_found = any(
                    d.get("edge_type") == "EGRESS" for d in edges.values()
                )
                assert egress_found, (
                    f"No EGRESS edge from {src_zone} to {dst_zone}"
                )

    def test_unreachable_topology_has_no_egress(self, store, graph):
        for (src_zone, dst_zone), topo_fact in store._topology.items():
            if not topo_fact.value:  # NOT reachable
                src = zone_node_id(src_zone)
                dst = zone_node_id(dst_zone)
                if not graph.graph.has_edge(src, dst):
                    continue  # No edge at all — correct
                edges = graph.graph[src][dst]
                # There should be no EGRESS edges for this pair from the
                # store migration (additional topology may add some to
                # EXTERNAL, but not between these pairs)
                egress_from_store = [
                    k for k, d in edges.items()
                    if d.get("edge_type") == "EGRESS"
                    and "EXTERNAL" not in str(dst)
                ]
                assert len(egress_from_store) == 0, (
                    f"Unexpected EGRESS from {src_zone} to {dst_zone}"
                )

    def test_all_access_baseline_has_edges(self, store, graph):
        for (user_id, host_id_str) in store._access_baseline:
            acct = account_node_id(user_id)
            host = host_node_id(host_id_str)
            assert graph.graph.has_edge(acct, host), (
                f"Missing edge from {user_id} to {host_id_str}"
            )
            edges = graph.graph[acct][host]
            has_access_edge = any(
                d.get("edge_type") == "HAS_PRIOR_ACCESS"
                for d in edges.values()
            )
            assert has_access_edge, (
                f"Missing HAS_PRIOR_ACCESS from {user_id} to {host_id_str}"
            )

    def test_host_node_attributes_preserve_criticality(self, store, graph):
        """Verify that host node attributes faithfully represent the store data."""
        for host_id_str, asset_fact in store._asset_info.items():
            node_id = host_node_id(host_id_str)
            attrs = graph.graph.nodes[node_id]
            zone_fact = attrs["zone_id"]
            assert isinstance(zone_fact, KnowledgeFact)
            assert zone_fact.value == asset_fact.value["zone"]


# ---------------------------------------------------------------------------
# Test 3: get_or_create_host_node idempotency
# ---------------------------------------------------------------------------

class TestHostNodeIdempotency:
    """get_or_create_host_node called twice for the same hostname returns
    the same node id and doesn't grow the graph."""

    @pytest.fixture
    def graph(self):
        return KnowledgeStoreGraph()

    def test_same_id_returned(self, graph):
        id1 = graph.get_or_create_host_node("WKSTN-5555")
        id2 = graph.get_or_create_host_node("WKSTN-5555")
        assert id1 == id2

    def test_graph_not_grown(self, graph):
        count_before = graph.graph.number_of_nodes()
        graph.get_or_create_host_node("WKSTN-5555")
        count_after_first = graph.graph.number_of_nodes()
        graph.get_or_create_host_node("WKSTN-5555")
        count_after_second = graph.graph.number_of_nodes()
        assert count_after_second == count_after_first


# ---------------------------------------------------------------------------
# Test 4: Unseen WKSTN-9999 → WORKSTATION, confidence 0.8
# ---------------------------------------------------------------------------

class TestUnseenHostCreation:
    """get_or_create_host_node on an unseen "WKSTN-9999"-style hostname
    creates a node with HostClass.WORKSTATION and confidence 0.8."""

    @pytest.fixture
    def graph(self):
        return KnowledgeStoreGraph()

    def test_classified_as_workstation(self, graph):
        node_id = graph.get_or_create_host_node("WKSTN-9999")
        attrs = graph.graph.nodes[node_id]
        host_class_fact = attrs["host_class"]
        assert isinstance(host_class_fact, KnowledgeFact)
        assert host_class_fact.value == HostClass.WORKSTATION

    def test_confidence_is_0_8(self, graph):
        node_id = graph.get_or_create_host_node("WKSTN-9999")
        attrs = graph.graph.nodes[node_id]
        host_class_fact = attrs["host_class"]
        assert host_class_fact.confidence == 0.8

    def test_not_confidence_1_0(self, graph):
        """Inherited confidence is 0.8, NOT 1.0 — it's pattern-matched,
        not authored."""
        node_id = graph.get_or_create_host_node("WKSTN-9999")
        attrs = graph.graph.nodes[node_id]
        assert attrs["host_class"].confidence != 1.0

    def test_hosted_in_edge_created(self, graph):
        node_id = graph.get_or_create_host_node("WKSTN-9999")
        zone = graph.get_host_zone(node_id)
        assert zone is not None
        assert zone == zone_node_id("WORKSTATION")


# ---------------------------------------------------------------------------
# Test 5: Garbage hostname → UNKNOWN, confidence 0.0, no crash
# ---------------------------------------------------------------------------

class TestGarbageHostCreation:
    """get_or_create_host_node on a totally unrecognised hostname creates
    UNKNOWN class at confidence 0.0 and does NOT raise or hard-fail."""

    @pytest.fixture
    def graph(self):
        return KnowledgeStoreGraph()

    def test_classified_as_unknown(self, graph):
        node_id = graph.get_or_create_host_node("xyzzy-garbage-999")
        attrs = graph.graph.nodes[node_id]
        host_class_fact = attrs["host_class"]
        assert isinstance(host_class_fact, KnowledgeFact)
        assert host_class_fact.value == HostClass.UNKNOWN

    def test_confidence_is_0_0(self, graph):
        node_id = graph.get_or_create_host_node("xyzzy-garbage-999")
        attrs = graph.graph.nodes[node_id]
        assert attrs["host_class"].confidence == 0.0

    def test_does_not_raise(self, graph):
        """Must not raise — graceful degradation for unknown hosts."""
        node_id = graph.get_or_create_host_node("xyzzy-garbage-999")
        assert node_id is not None

    def test_hosted_in_unknown_zone(self, graph):
        node_id = graph.get_or_create_host_node("xyzzy-garbage-999")
        zone = graph.get_host_zone(node_id)
        assert zone is not None
        assert zone == zone_node_id("UNKNOWN")


# ---------------------------------------------------------------------------
# Additional graph structure tests
# ---------------------------------------------------------------------------

class TestAdditionalTopology:
    """Verify the additional seeded topology is present."""

    @pytest.fixture
    def graph(self):
        return KnowledgeStoreGraph()

    def test_domain_admins_group_exists(self, graph):
        da = group_node_id("domain-admins")
        assert da in graph.graph
        assert graph.graph.nodes[da]["node_type"] == "GroupNode"

    def test_bob_member_of_domain_admins(self, graph):
        bob = account_node_id("bob")
        da = group_node_id("domain-admins")
        assert graph.graph.has_edge(bob, da)
        edges = graph.graph[bob][da]
        member_of = any(
            d.get("edge_type") == "MEMBER_OF" for d in edges.values()
        )
        assert member_of

    def test_domain_admins_grants_to_dc(self, graph):
        da = group_node_id("domain-admins")
        dc = host_node_id("server-dc01")
        assert graph.graph.has_edge(da, dc)
        edges = graph.graph[da][dc]
        grants = [
            d for d in edges.values()
            if d.get("edge_type") == "GRANTS"
        ]
        assert len(grants) >= 1
        al = grants[0]["access_level"]
        assert isinstance(al, KnowledgeFact)
        assert al.value == AccessLevel.DOMAIN_ADMIN

    def test_svc_backup_grants_admin_to_db(self, graph):
        svc = account_node_id("svc_backup")
        db = host_node_id("server-db01")
        assert graph.graph.has_edge(svc, db)
        edges = graph.graph[svc][db]
        grants = [
            d for d in edges.values()
            if d.get("edge_type") == "GRANTS"
        ]
        assert len(grants) >= 1
        al = grants[0]["access_level"]
        assert isinstance(al, KnowledgeFact)
        assert al.value == AccessLevel.ADMIN

    def test_external_zone_exists(self, graph):
        ext = zone_node_id("EXTERNAL")
        assert ext in graph.graph
