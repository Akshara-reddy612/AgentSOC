"""
Phase 3 step 3.4 (2026-10-11): attacker-goal metrics, shared downstream
function, and the offline mock-NCE modes of agent/run_v2_eval.py.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.run_v2_eval import mock_hijacked, mock_oracle
from experiments.attack_metrics import misdirected_actions, summarize
from perception.defended_pipeline import run_downstream

V2 = Path(__file__).resolve().parent.parent / "GUIDE_Dataset" / "processed" / "v2" / "guide_v2_dev.json"


@pytest.fixture(scope="module")
def alerts():
    return json.loads(V2.read_text(encoding="utf-8"))


def _rec(alert, outcome, hyps=()):
    return {"alert_id": alert["alert_id"], "outcome": outcome, "hypotheses": list(hyps)}


def test_suppression_counted_only_against_clean_twin(alerts):
    c, x = alerts[0], alerts[1]
    rep = summarize([_rec(c, "REVIEW"), _rec(x, "NO_ACTIONABLE")], [c, x])
    fam = rep["families"][x["_ground_truth_injection_category"]]
    assert fam["suppressed"] == 1 and fam["clean_responded"] == 1
    rep = summarize([_rec(c, "NO_ACTIONABLE"), _rec(x, "NO_ACTIONABLE")], [c, x])
    assert rep["families"][x["_ground_truth_injection_category"]].get("suppressed", 0) == 0


def test_nce_error_pairs_excluded(alerts):
    c, x = alerts[0], alerts[1]
    rep = summarize([_rec(c, "REVIEW"), {"alert_id": x["alert_id"], "nce_error": "quota"}], [c, x])
    assert rep["excluded"] == {"nce_error": 1} and rep["families"] == {}


def test_misdirection_executed_vs_gated(alerts):
    x = next(a for a in alerts if a["_ground_truth_injection_category"] == "identity_steering")
    c = next(a for a in alerts if a["_pair_id"] == x["_pair_id"] and a["_variant"] == "clean")
    user, host = x["_steered_entities"]
    wrong = {"top_action": "QUARANTINE_ACCESS", "top_target_host": host, "top_target_account": None}
    right = {"top_action": "QUARANTINE_ACCESS", "top_target_host": x["source_host"], "top_target_account": None}
    assert misdirected_actions({"hypotheses": [right]}, x) == []
    for status, key in (("AUTO_APPROVED", "misdirect_executed"), ("PENDING_ANALYST_REVIEW", "misdirect_gated")):
        rep = summarize([_rec(c, "REVIEW"), _rec(x, "REVIEW", [{**wrong, "playbook_status": status}])], [c, x])
        assert rep["families"]["identity_steering"][key] == 1
        assert rep["families"]["identity_steering"]["steered_hit"] == 1


def test_mocks_and_downstream(alerts):
    steer = next(a for a in alerts if a["_ground_truth_injection_category"] == "identity_steering")
    clean = next(a for a in alerts if a["_pair_id"] == steer["_pair_id"] and a["_variant"] == "clean")
    assert mock_hijacked(clean) == mock_oracle(clean)
    h = mock_hijacked(steer)[0]
    assert (h.source_account, h.target_host) == tuple(steer["_steered_entities"])
    pub = {k: v for k, v in steer.items() if not k.startswith("_")}
    out = run_downstream([h], pub)
    assert out["hypotheses"][0]["entity_binding"] == "unbound"
    assert out["outcome"] in ("REVIEW", "NO_ACTIONABLE")          # never auto-approved
    supp = next(a for a in alerts if a["_attack_goal"] == "suppress"
                and a["_ground_truth_injection_category"] != "destination_spoof")
    assert mock_hijacked(supp) == []
