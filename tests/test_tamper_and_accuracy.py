"""
Phase 4 steps 4.4-4.5 (2026-10-11): tampering scenarios edit only structured
fields; accuracy table counts responses per IncidentGrade on clean alerts.
"""
from __future__ import annotations

import json
from pathlib import Path

from experiments.accuracy_by_grade import table
from experiments.tamper_structured import SANCTIONED_DOMAIN, tamper

V2 = Path(__file__).resolve().parent.parent / "GUIDE_Dataset" / "processed" / "v2" / "guide_v2_dev.json"


def test_tamper_scenarios_only_touch_structured_fields():
    alerts = json.loads(V2.read_text(encoding="utf-8"))
    steer = next(a for a in alerts if a["_ground_truth_injection_category"] == "identity_steering")
    t = tamper(steer, "steer_identity")
    user, host = steer["_steered_entities"]
    assert (t["source_user"], t["target_host"]) == (user, host)
    assert t["raw_log_line"] == steer["raw_log_line"] and t["command_line"] == steer["command_line"]
    assert not any(k.startswith("_") for k in t)
    net = next(a for a in alerts if a["destination_ip"] and a["_variant"] == "contaminated")
    assert tamper(net, "drop_destination")["destination_ip"] is None
    assert tamper(net, "launder_destination")["destination_domain"] == SANCTIONED_DOMAIN
    no_net = next(a for a in alerts if not a["destination_ip"] and a["_variant"] == "contaminated")
    assert tamper(no_net, "drop_destination") is None
    assert tamper(net, "steer_identity") is None or net["_ground_truth_injection_category"] == "identity_steering"


def test_accuracy_table_counts_clean_only():
    alerts = {"a-clean": {"_source_incident_grade": "TruePositive"},
              "b-clean": {"_source_incident_grade": "FalsePositive"},
              "a-contaminated": {"_source_incident_grade": "TruePositive"}}
    res = [{"alert_id": "a-clean", "variant": "clean", "outcome": "REVIEW"},
           {"alert_id": "b-clean", "variant": "clean", "outcome": "LOW_PRIORITY"},
           {"alert_id": "a-contaminated", "variant": "contaminated", "outcome": "NO_ACTIONABLE"}]
    t = table(res, alerts)
    assert t["recall_tp"] == 1.0 and t["response_rate_non_tp"] == 0.0
