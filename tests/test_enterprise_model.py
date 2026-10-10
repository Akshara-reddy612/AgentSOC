"""
Phase 3 step 3.1 (2026-10-11): synthetic enterprise inventory seeded into the
Knowledge Store graph, so hypotheses naming an alert's real entities can be
structurally checked instead of failing on an empty identity graph.
"""
from __future__ import annotations

import re

from perception.enterprise_model import INVENTORY, _build
from perception.knowledge_graph import KnowledgeStoreGraph, account_node_id, host_node_id
from perception.sse import SSEVerdict, StructuralSimulationEngine

FEAS = {SSEVerdict.FEASIBLE, SSEVerdict.CONDITIONALLY_FEASIBLE}


def _feasible(sse, acct, src, tgt, tech):
    return any(r.verdict in FEAS for r in sse.check(acct, src, tgt, tech))


def test_deterministic_and_unique():
    again = _build()
    assert [a.account_id for a in again.accounts] == [a.account_id for a in INVENTORY.accounts]
    assert [h.host_id for h in again.hosts] == [h.host_id for h in INVENTORY.hosts]
    assert len({a.account_id for a in INVENTORY.accounts}) == len(INVENTORY.accounts)
    assert len({h.host_id.lower() for h in INVENTORY.hosts}) == len(INVENTORY.hosts)


def test_no_collision_with_historical_corpus_names_or_toy_entities():
    for h in INVENTORY.hosts:
        assert not re.fullmatch(r"(WKSTN-|SRV-FILE)\d{4}|LT-\d{4}-CORP", h.host_id)
    toy = {"alice", "bob", "charlie", "mallory", "svc_backup"}
    assert toy.isdisjoint(a.account_id for a in INVENTORY.accounts)


def test_seeded_into_graph():
    kg = KnowledgeStoreGraph()
    for a in INVENTORY.accounts:
        assert account_node_id(a.account_id) in kg.graph
    for h in INVENTORY.hosts:
        assert host_node_id(h.host_id) in kg.graph
    # toy seed data still present
    assert account_node_id("svc_backup") in kg.graph and host_node_id("server-db01") in kg.graph


def test_structural_expectations():
    sse = StructuralSimulationEngine(KnowledgeStoreGraph())
    plain = next(a for a in INVENTORY.by_role("standard_user") if not a.local_admin)
    ladmin = next(a for a in INVENTORY.by_role("standard_user") if a.local_admin)
    hd = INVENTORY.by_role("helpdesk_admin")[0]
    da = INVENTORY.by_role("domain_admin")[0]
    h = plain.home_host
    assert _feasible(sse, plain.account_id, h, h, "T1078")            # valid account on own device
    assert not _feasible(sse, plain.account_id, h, h, "T1562")        # no admin -> cannot impair defenses
    assert _feasible(sse, ladmin.account_id, ladmin.home_host, ladmin.home_host, "T1562")
    assert _feasible(sse, hd.account_id, h, h, "T1550")               # helpdesk admin on every endpoint
    assert _feasible(sse, da.account_id, h, "SRV-DC01", "T1484")
    assert not _feasible(sse, plain.account_id, h, "SRV-DB01", "T1078")
    assert not _feasible(sse, plain.account_id, h, "SRV-DC01", "T1484")
