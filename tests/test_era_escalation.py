"""
Step 4.8 (2026-10-11): ERA level MEDIUM/HIGH escalates an alert to REVIEW and
blocks auto-approval; the alert's ERA level is the max of field and incident levels.
"""
from __future__ import annotations

from experiments.era_offline import level_of
from perception.defended_pipeline import run_downstream
from perception.enterprise_model import INVENTORY
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.outcome import AUTO_APPROVED, LOW_PRIORITY, NO_ACTIONABLE, REVIEW, decide

U = next(a for a in INVENTORY.by_role("standard_user") if not a.local_admin)
ALERT = {"source_user": U.account_id, "source_host": U.home_host, "target_host": U.home_host,
         "destination_domain": "cdn654.example", "destination_ip": "192.0.2.249",
         "raw_log_line": "behavior=network.periodic_outbound_http dst=cdn654.example"}


def test_decide_escalates_on_era_medium_or_high():
    kg = KnowledgeStoreGraph()
    no_dest = {k: v for k, v in ALERT.items() if not k.startswith("destination")}
    assert decide(no_dest, [], kg).label == NO_ACTIONABLE
    assert decide(no_dest, [], kg, era_level="MEDIUM").label == REVIEW
    assert decide(no_dest, ["AUTO_APPROVED"], kg, era_level="HIGH").label == REVIEW
    assert decide(no_dest, ["LOGGED_EXPECTED_ACTIVITY"], kg, era_level="HIGH").label == REVIEW
    assert decide(no_dest, ["LOGGED_EXPECTED_ACTIVITY"], kg, era_level="LOW").label == LOW_PRIORITY
    assert "ERA flagged" in decide(no_dest, [], kg, era_level="MEDIUM").reasons[0]


def test_era_blocks_auto_approval_downstream():
    assert run_downstream([], ALERT)["outcome"] == AUTO_APPROVED          # unknown destination -> auto block
    assert run_downstream([], ALERT, era_level="HIGH")["outcome"] == REVIEW


def test_alert_level_is_max_of_field_and_incident():
    assert level_of({"incident_level": "LOW", "max_field_level": "HIGH"}) == "HIGH"
    assert level_of({"incident_level": "MEDIUM", "max_field_level": "LOW"}) == "MEDIUM"
    assert level_of({}) == "LOW"
