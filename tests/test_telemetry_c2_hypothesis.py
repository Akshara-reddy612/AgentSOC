"""
Phase 4 step 4.2 (2026-10-11): with trusted destination telemetry and no NCE
T1071 hypothesis, the pipeline adds one itself, so contaminated text cannot
remove the C2 check.
"""
from __future__ import annotations

from perception.defended_pipeline import run_downstream
from perception.enterprise_model import INVENTORY
from perception.entity_binding import TELEMETRY_REF, attach_alert_context
from perception.nce_contract import NCEHypothesis

U = next(a for a in INVENTORY.by_role("standard_user") if not a.local_admin)
ALERT = {"source_user": U.account_id, "source_host": U.home_host, "target_host": U.home_host,
         "destination_domain": "cdn321.example", "destination_ip": "192.0.2.251",
         "raw_log_line": "user=x behavior=network.periodic_outbound_http dst=cdn321.example"}


def _t1078():
    return NCEHypothesis(technique_id="T1078", source_account=U.account_id, source_host=U.home_host,
                         target_host=U.home_host, nce_confidence=0.6, supporting_evidence_refs=["raw_log_line"])


def test_added_when_nce_omits_c2():
    out = attach_alert_context([_t1078()], ALERT)
    tele = [h for h in out if h.technique_id == "T1071"]
    assert len(tele) == 1
    h = tele[0]
    assert h.supporting_evidence_refs == [TELEMETRY_REF] and h.nce_confidence == 0.0
    assert (h.source_account, h.source_host, h.target_host) == (U.account_id, U.home_host, "cdn321.example")
    assert h.trusted_destination == "cdn321.example" and h.entity_binding == "bound"


def test_not_added_without_destination_or_when_nce_has_c2():
    no_dest = {k: v for k, v in ALERT.items() if not k.startswith("destination")}
    assert [h.technique_id for h in attach_alert_context([_t1078()], no_dest)] == ["T1078"]
    nce_c2 = NCEHypothesis(technique_id="T1071", source_account=U.account_id, source_host=U.home_host,
                           target_host="cdn321.example", nce_confidence=0.7, supporting_evidence_refs=["raw_log_line"])
    out = attach_alert_context([nce_c2], ALERT)
    assert len(out) == 1 and out[0].supporting_evidence_refs == ["raw_log_line"]


def test_fully_suppressed_nce_still_gets_response():
    """A payload that talks NCE out of every hypothesis no longer ends the alert silently."""
    res = run_downstream([], ALERT)
    assert res["outcome"] == "AUTO_APPROVED"            # BLOCK_DESTINATION on the unknown destination
    assert res["hypotheses"][0]["top_action"] == "BLOCK_DESTINATION"
