"""
Design step S1 (2026-10-11): environment profile.  Which addresses are internal
and each zone's egress policy come from a profile that travels with the
Knowledge Store graph.  The default profile must reproduce the pre-S1 rules;
a different profile must change every place that decides internal vs external.
"""
from __future__ import annotations

import pytest

from perception.defended_pipeline import run_downstream
from perception.enterprise_model import INVENTORY
from perception.entity_binding import UNBOUND, UNVERIFIABLE, bind_entities
from perception.environment import DEFAULT_PROFILE, EnvironmentProfile
from perception.knowledge_graph import KnowledgeStoreGraph, zone_node_id
from perception.nce_contract import NCEHypothesis
from perception.nce_engine import _is_private_ip, label_t1071_grounding
from perception.network_model import (
    INTERNAL, KNOWN_BAD, SANCTIONED, UNKNOWN, ZONE_EGRESS_POLICY, egress_permits, policy_permits,
)


# --- verbatim copies of the pre-S1 rules (network_model / nce_engine before 2026-10-11) ---

def _pre_s1_is_internal_address(address: str) -> bool:
    a = address.strip().lower()
    if a.endswith((".corp.local", ".internal")):
        return True
    parts = a.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        o = [int(p) for p in parts]
        return (o[0] == 10 or (o[0] == 172 and 16 <= o[1] <= 31)
                or (o[0] == 192 and o[1] == 168) or o[0] == 127
                or (o[0] == 169 and o[1] == 254))
    return False


def _pre_s1_is_private_ip(ip_str: str) -> bool:
    try:
        parts = [int(p) for p in ip_str.split(".")]
    except (ValueError, AttributeError):
        return True
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        return True
    a, b = parts[0], parts[1]
    return (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            or a == 127 or (a == 169 and b == 254))


def _pre_s1_egress_permits(zone_id: str, reputation: str) -> bool:
    policy = ZONE_EGRESS_POLICY.get(zone_id.upper(), {"mode": "none"})
    mode = policy["mode"]
    if mode == "none":
        return False
    if mode == "proxy":
        return reputation not in policy.get("deny", [])
    if mode == "allowlist":
        return reputation in policy.get("allow", [])
    return False


ADDRESSES = [
    "0.0.0.0", "9.255.255.255", "10.0.0.0", "10.255.255.255", "11.0.0.0",
    "126.255.255.255", "127.0.0.1", "127.255.255.255", "128.0.0.0",
    "169.253.255.255", "169.254.0.0", "169.254.255.255", "169.255.0.0",
    "172.15.255.255", "172.16.0.0", "172.19.1.1", "172.31.255.255", "172.32.0.0",
    "192.167.255.255", "192.168.0.0", "192.168.255.255", "192.169.0.0",
    "192.0.2.10", "198.51.100.7", "203.0.113.9", "8.8.8.8", "255.255.255.255",
    "010.1.2.3", "8.008.8.8", " 10.0.0.1 ",
    "server.corp.local", "HOST.INTERNAL", "gate.c2-panel.example", "cdn123.example", "WKSTN-00001", "",
    "not-an-ip", "1.2.3", "1.2.3.4.5", "-1.2.3.4", "999.999.999.999",
]

# Profile of a lab network whose simulated internet uses other private ranges (like DEDALE).
LAB = EnvironmentProfile(name="lab", internal_networks=("172.16.0.0/16", "172.17.0.0/16"))
U = next(a for a in INVENTORY.by_role("standard_user") if not a.local_admin)
FLOW = "flow 172.16.1.3:52885 -> 172.19.1.1:80"


@pytest.mark.parametrize("address", ADDRESSES)
def test_default_profile_reproduces_pre_s1_rules(address):
    assert DEFAULT_PROFILE.is_internal_address(address) == _pre_s1_is_internal_address(address)
    assert _is_private_ip(address) == _pre_s1_is_private_ip(address)


def test_grounding_fail_safe_for_non_strings_unchanged():
    assert _is_private_ip(None) is True and _pre_s1_is_private_ip(None) is True


def test_malformed_dotted_quad_is_not_an_internal_address():
    """The one intended difference: only the leading octets used to be compared."""
    assert _pre_s1_is_internal_address("10.300.1.1") is True
    assert DEFAULT_PROFILE.is_internal_address("10.300.1.1") is False
    assert _is_private_ip("10.300.1.1") is True           # grounding stays fail-safe


@pytest.mark.parametrize("zone", [*ZONE_EGRESS_POLICY, "workstation", "NOT_A_ZONE"])
@pytest.mark.parametrize("rep", [SANCTIONED, KNOWN_BAD, UNKNOWN, INTERNAL])
def test_egress_policy_unchanged_for_default_profile(zone, rep):
    assert egress_permits(zone, rep) == _pre_s1_egress_permits(zone, rep)
    kg = KnowledgeStoreGraph()
    node = zone_node_id(zone)
    if node in kg.graph and "egress_policy" in kg.graph.nodes[node]:
        assert policy_permits(kg.get_zone_egress_policy(node), rep) == _pre_s1_egress_permits(zone, rep)


def test_lab_profile_changes_internal_ranges():
    for a in ("172.16.1.3", "172.17.0.2"):
        assert LAB.is_internal_address(a) and DEFAULT_PROFILE.is_internal_address(a)
    for a in ("172.19.1.1", "172.18.0.1", "10.0.0.1"):
        assert not LAB.is_internal_address(a) and DEFAULT_PROFILE.is_internal_address(a)


def test_reputation_lookup_and_dry_run_copies_use_the_profile():
    assert KnowledgeStoreGraph().get_destination_reputation("172.19.1.1")[0] == INTERNAL
    kg = KnowledgeStoreGraph(profile=LAB)
    assert kg.get_destination_reputation("172.19.1.1")[0] == UNKNOWN
    copy = KnowledgeStoreGraph.from_graph(kg.graph.copy())     # what RSEM / dry runs do
    assert copy.profile is LAB
    assert copy.get_destination_reputation("172.19.1.1")[0] == UNKNOWN


def test_grounding_uses_the_profile():
    h = NCEHypothesis(technique_id="T1071", source_account=U.account_id, source_host=U.home_host,
                      target_host="172.19.1.1", nce_confidence=0.7, supporting_evidence_refs=["raw_log_line"])
    evidence = {"raw_log_line": FLOW}
    assert label_t1071_grounding([h], evidence)[0].evidence_grounding == "ungrounded"
    assert label_t1071_grounding([h], evidence, LAB)[0].evidence_grounding == "grounded"


def test_entity_binding_uses_the_profile():
    h = NCEHypothesis(technique_id="T1071", source_account=U.account_id, source_host=U.home_host,
                      target_host="172.19.1.1", nce_confidence=0.7, supporting_evidence_refs=["raw_log_line"])
    alert = {"source_user": U.account_id, "source_host": U.home_host, "target_host": U.home_host}
    assert bind_entities(h, alert).roles["target_host"] == UNBOUND
    assert bind_entities(h, alert, LAB).roles["target_host"] == UNVERIFIABLE


def test_run_downstream_end_to_end_uses_the_graph_profile():
    """Telemetry C2 to 172.19.1.1: 'internal' under RFC 1918, an external destination in the lab."""
    alert = {"source_user": U.account_id, "source_host": U.home_host, "target_host": U.home_host,
             "destination_ip": "172.19.1.1", "raw_log_line": FLOW}
    default = run_downstream([], alert)
    assert default["hypotheses"][0]["sse_verdict"] == "INFEASIBLE" and default["outcome"] == "NO_ACTIONABLE"
    lab = run_downstream([], alert, KnowledgeStoreGraph(profile=LAB))
    assert lab["hypotheses"][0]["sse_verdict"] == "FEASIBLE"
    assert lab["hypotheses"][0]["top_action"] == "BLOCK_DESTINATION"
    assert lab["outcome"] == "AUTO_APPROVED"


def test_sse_applies_the_zone_policy_stored_in_the_graph():
    """Before S1 SSE re-read the module table, so a different zone policy in the graph was ignored."""
    strict = EnvironmentProfile(
        name="strict", internal_networks=DEFAULT_PROFILE.internal_networks,
        zone_egress_policy={**ZONE_EGRESS_POLICY, "WORKSTATION": {"mode": "allowlist", "allow": [SANCTIONED]}})
    alert = {"source_user": U.account_id, "source_host": U.home_host, "target_host": U.home_host,
             "destination_domain": "cdn321.example"}
    assert run_downstream([], alert)["hypotheses"][0]["sse_verdict"] == "FEASIBLE"     # proxy allows unknown
    res = run_downstream([], alert, KnowledgeStoreGraph(profile=strict))
    assert res["hypotheses"][0]["sse_verdict"] == "INFEASIBLE"                          # allow-list blocks it
