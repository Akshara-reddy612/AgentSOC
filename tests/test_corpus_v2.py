"""
Phase 3 step 3.2 (2026-10-11): corpus v2 invariants — valid twins by
construction, no label leakage through severity or destination reputation,
no injection wrapper, reserved address space only.
"""
from __future__ import annotations

import ipaddress
import random
import re

import pytest

from corpus import build_v2, evidence
from perception.enterprise_model import INVENTORY

RFC5737 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
SITES = {"raw_log_line", "command_line", "registry_key"}


@pytest.fixture(scope="module")
def dev():
    csv, prefix = build_v2.SETS["dev"]
    return build_v2.build_set(csv, prefix, random.Random(build_v2.SEED))


def _pairs(alerts):
    return list(zip(alerts[0::2], alerts[1::2]))


def test_deterministic(dev):
    csv, prefix = build_v2.SETS["dev"]
    assert build_v2.build_set(csv, prefix, random.Random(build_v2.SEED)) == dev


def test_unique_ids_and_pairing(dev):
    ids = [a["alert_id"] for a in dev]
    assert len(ids) == len(set(ids)) == 1000
    for c, x in _pairs(dev):
        assert c["_pair_id"] == x["_pair_id"] and (c["_variant"], x["_variant"]) == ("clean", "contaminated")


def test_twins_differ_only_at_injection_site(dev):
    for c, x in _pairs(dev):
        public = {k for k in c if not k.startswith("_")} - {"alert_id"}
        changed = {k for k in public if c[k] != x[k]}
        assert changed and changed <= SITES, (c["_pair_id"], changed)
        assert set(x["_injection_site"].split("+")) == changed
        assert not c["_ground_truth_is_contaminated"] and x["_ground_truth_is_contaminated"]


def test_no_wrapper_no_routable_addresses(dev):
    for a in dev:
        text = " ".join(str(a[k]) for k in SITES | {"process_name", "file_path"})
        assert "INJECTED_FIELD_VALUE" not in text
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
            assert any(ipaddress.ip_address(ip) in n for n in RFC5737), ip
        if a["destination_ip"]:
            assert any(ipaddress.ip_address(a["destination_ip"]) in n for n in RFC5737)
        if a["destination_domain"]:
            assert a["destination_domain"].endswith(".example")


def test_grade_does_not_influence_any_pipeline_field():
    base = dict(key="v2d-1", category="CommandAndControl", mitre="T1071", entity_type="Ip",
                timestamp="2024-06-01T00:00:00Z", last_verdict="Suspicious")
    a = evidence.synthesize(**base)
    # synthesize() has no grade parameter; severity follows Category only
    assert "grade" not in evidence.synthesize.__code__.co_varnames
    assert a["severity"] == evidence.CATEGORY_TO_SEVERITY["CommandAndControl"]


def test_entities_from_inventory_and_fields_always_present(dev):
    accounts = {a.account_id for a in INVENTORY.accounts}
    hosts = {h.host_id for h in INVENTORY.hosts}
    for a in dev:
        assert a["source_user"] in accounts and a["source_host"] in hosts and a["target_host"] in hosts
        assert a["parent_process"] and a["registry_key"] and "severity" in a


def test_family_specific_invariants(dev):
    for c, x in _pairs(dev):
        fam = x["_ground_truth_injection_category"]
        if fam == "destination_spoof":
            assert c["destination_ip"] is not None
        if fam == "identity_steering":
            user, host = x["_steered_entities"]
            assert user != c["source_user"] and host not in (c["source_host"], c["target_host"])
            assert INVENTORY.account(user) and INVENTORY.host(host)
            assert x["_attack_goal"] == "misdirect"
        else:
            assert x["_attack_goal"] == "suppress"
