"""
perception/baseline.py

Expected-activity check (Phase 4 step 4.0, 2026-10-11).

With the corpus's entities in the identity graph, a hypothesis such as
"T1078: user on their own laptop" is structurally FEASIBLE by definition, so
feasibility alone sent ~97% of clean alerts to an analyst.  SSE keeps
reporting the truth (the path exists); this module tells the guardrail when
the ONLY feasible paths are the account's normal access, so the playbook is
logged at low priority instead of acted on.

A validated hypothesis is baseline-only when ALL of these hold:
  - technique is an access-path technique (not T1071, which is judged on
    destination telemetry), and SSE's best verdict is FEASIBLE;
  - entity binding is "bound" (every entity matches the alert's trusted
    fields; None = no alert context -> never baseline);
  - the account is a STANDARD_USER (privileged, admin and service accounts
    are never baseline);
  - the target host is in the inventory with criticality tier <= 1;
  - the account has HAS_PRIOR_ACCESS to the target, and the source host is
    the target or another host it has prior access to;
  - no feasible path goes through a group (MEMBER_OF): group-mediated rights
    are not the account's own history.
Read-only; reads only trusted graph facts.
"""
from __future__ import annotations

from perception.knowledge_graph import AccountType, KnowledgeStoreGraph, account_node_id, host_node_id
from perception.knowledge_store import KnowledgeFact
from perception.sse import SSEVerdict

MAX_BASELINE_TIER = 1


def _fact_value(data: dict, key: str):
    v = data.get(key)
    return v.value if isinstance(v, KnowledgeFact) else v


def _has_prior_access(kg: KnowledgeStoreGraph, acct: str, host: str) -> bool:
    g = kg.graph
    return g.has_edge(acct, host) and any(d.get("edge_type") == "HAS_PRIOR_ACCESS"
                                          for d in g[acct][host].values())


def privileged_context(validated, kg: KnowledgeStoreGraph) -> str | None:
    """
    Review reason when the hypothesis involves a non-standard account (admin,
    helpdesk, service) or a critical host (tier >= 2): acting on those is
    disruptive, so it must never be auto-approved.  None otherwise.
    """
    h = validated.hypothesis
    g = kg.graph
    acct = account_node_id(h.source_account or "")
    if acct in g:
        at = _fact_value(g.nodes[acct], "account_type")
        if at is not None and at != AccountType.STANDARD_USER:
            return f"Hypothesis involves privileged account {h.source_account!r} ({at.value})."
    for host in (h.source_host, h.target_host):
        n = host_node_id(host or "")
        if n in g and (_fact_value(g.nodes[n], "criticality_tier") or 0) > MAX_BASELINE_TIER:
            return f"Hypothesis involves critical host {host!r}."
    return None


def baseline_only(validated, kg: KnowledgeStoreGraph) -> bool:
    h = validated.hypothesis
    if h.technique_id == "T1071" or validated.best_sse_verdict != SSEVerdict.FEASIBLE:
        return False
    if h.entity_binding != "bound":
        return False
    g = kg.graph
    acct = account_node_id(h.source_account or "")
    tgt = host_node_id(h.target_host or "")
    src = host_node_id(h.source_host or h.target_host or "")
    if acct not in g or tgt not in g:
        return False
    if _fact_value(g.nodes[acct], "account_type") != AccountType.STANDARD_USER:
        return False
    if (_fact_value(g.nodes[tgt], "criticality_tier") or 0) > MAX_BASELINE_TIER:
        return False
    if not _has_prior_access(kg, acct, tgt):
        return False
    if src != tgt and not _has_prior_access(kg, acct, src):
        return False
    feasible = [r for r in validated.sse_results if r.verdict != SSEVerdict.INFEASIBLE]
    return bool(feasible) and not any("MEMBER_OF" in step for r in feasible for step in r.edge_path)
