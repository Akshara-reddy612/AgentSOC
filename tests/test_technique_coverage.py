"""
Design decision D6 (2026-10-11): techniques host logs show.  New SSE
constraints, the "no structural precondition -> review" path, and the NCE
vocabulary switch (legacy by default, full table on request).
"""
from __future__ import annotations

from perception.defended_pipeline import run_downstream
from perception.enterprise_model import INVENTORY
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import NCEHypothesis
from perception.sse import LEGACY_TECHNIQUES, TECHNIQUE_TABLE, SSEVerdict, StructuralSimulationEngine

ADMIN = next(a for a in INVENTORY.by_role("standard_user") if a.local_admin)
USER = next(a for a in INVENTORY.by_role("standard_user") if not a.local_admin)


def _check(technique, account, source, target, **kw):
    sse = StructuralSimulationEngine(KnowledgeStoreGraph())
    return sse.check(account, source, target, technique, **kw)


def test_vocabulary_extends_the_legacy_list():
    new = set(TECHNIQUE_TABLE) - set(LEGACY_TECHNIQUES)
    assert {"T1003", "T1005", "T1021.004", "T1039", "T1041", "T1059", "T1105",
            "T1204", "T1210", "T1547", "T1566"} == new
    NCEHypothesis(technique_id="T1566", source_account=USER.account_id, source_host=USER.home_host,
                  target_host=USER.home_host, nce_confidence=0.5, supporting_evidence_refs=["raw_log_line"])


def test_no_structural_precondition_goes_to_review():
    (r,) = _check("T1059", USER.account_id, USER.home_host, USER.home_host)
    assert r.verdict == SSEVerdict.CONDITIONALLY_FEASIBLE and r.path_confidence == 0.0
    assert "no structural precondition" in r.dependency_note
    h = NCEHypothesis(technique_id="T1059", source_account=USER.account_id, source_host=USER.home_host,
                      target_host=USER.home_host, nce_confidence=0.7, supporting_evidence_refs=["command_line"])
    alert = {"source_user": USER.account_id, "source_host": USER.home_host, "target_host": USER.home_host}
    res = run_downstream([h], alert)
    assert res["hypotheses"][0]["sse_verdict"] == "CONDITIONALLY_FEASIBLE" and res["outcome"] == "REVIEW"


def test_credential_dumping_needs_local_admin():
    assert _check("T1003", USER.account_id, USER.home_host, USER.home_host)[0].verdict == SSEVerdict.INFEASIBLE
    assert _check("T1003", ADMIN.account_id, ADMIN.home_host, ADMIN.home_host)[0].verdict != SSEVerdict.INFEASIBLE


def test_remote_service_exploitation_needs_only_a_network_path():
    r = _check("T1210", "", USER.home_host, ADMIN.home_host)[0]       # no account given
    assert r.verdict == SSEVerdict.FEASIBLE and "zone" in " ".join(r.edge_path)


def test_tool_download_uses_the_internet_route():
    r = _check("T1105", "", USER.home_host, "updates.example", trusted_destination=None)[0]
    assert r.verdict == SSEVerdict.FEASIBLE and r.destination_status == "unverified"
