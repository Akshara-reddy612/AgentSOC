"""
Design step S3 (2026-10-11): DEDALE environment profile and inventory in the
persistent store, the Suricata alert adapter, and address -> entity resolution.
"""
from __future__ import annotations

import json
import zipfile
from datetime import datetime, timedelta, timezone
from itertools import islice

import pytest

from dedale import data_dir
from dedale.environment import DEDALE_PROFILE, INVENTORY, seed_store
from dedale.suricata import iter_alerts, to_alert
from perception.defended_pipeline import run_downstream
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_graph import host_node_id
from perception.network_alert import with_entities

T0 = datetime(2024, 12, 23, tzinfo=timezone.utc)
EXTERNAL = "172.19.0.77"            # an address in DEDALE's external zone (not an attacker address)


def _line(src: str, dst: str, sig: str = "ET INFO Example Signature", sid: int = 2000001, prio: int = 2) -> str:
    return (f"[1:{sid}:3] {sig} [Classification: Potentially Bad Traffic] [Priority: {prio}] "
            f"{{TCP}} {src} -> {dst}\n")


def _record(ms: int, message: str, sensor: str = "companyrouter2") -> dict:
    return {"@timestamp": ms, "logsource": sensor, "message": message, "program": "suricata"}


@pytest.fixture()
def db(tmp_path):
    with KnowledgeDB(tmp_path / "dedale.sqlite", DEDALE_PROFILE, created_at=T0) as store:
        seed_store(store, T0)
        yield store


def test_profile_internal_ranges():
    for a in ("172.16.1.3", "172.16.0.2", "172.17.0.2", "10.8.0.6"):
        assert DEDALE_PROFILE.is_internal_address(a)
    for a in ("172.18.0.1", EXTERNAL, "34.117.59.81", "192.28.1.1"):
        assert not DEDALE_PROFILE.is_internal_address(a)


def test_inventory_in_store(db):
    g = db.graph.graph
    assert sum(1 for _, d in g.nodes(data=True) if d["node_type"] == "HostNode") == len(INVENTORY) == 37
    assert db.host_for_address("172.16.1.3") == "CLIENT2"
    assert db.host_for_address("172.16.0.2") == "internalserver"
    assert {db.host_for_address(a) for a in ("172.16.0.1", "172.16.1.1", "172.16.255.2")} == {"companyrouter2"}
    assert db.host_for_address(EXTERNAL) is None
    assert db.graph.get_host_zone(host_node_id("CLIENT2")) == "zone:CLIENTS"
    assert db.learned_from(host_node_id("CLIENT2")) == "config"
    assert db.graph.get_zone_egress_policy("zone:CLIENTS") == {"mode": "open"}


def test_store_holds_nothing_from_the_external_zone(db):
    """Invariant I4: no attacker infrastructure (or any external-zone address) is configuration."""
    for entry in db.audit_log():
        text = json.dumps(entry)
        assert "172.19." not in text and "172.18." not in text


def test_parse_alert_line():
    a = to_alert(_record(1736157674335, _line("172.16.1.3:52885", f"{EXTERNAL}:80", prio=1)), 7)
    assert a["alert_id"] == "dedale-suricata-7" and a["timestamp"] == "2025-01-06T10:01:14.335Z"
    assert (a["src_ip"], a["src_port"], a["dst_ip"], a["dst_port"]) == ("172.16.1.3", 52885, EXTERNAL, 80)
    assert (a["signature_id"], a["priority"], a["severity"], a["sensor"]) == (2000001, 1, "high", "companyrouter2")
    assert a["raw_log_line"].endswith(f"-> {EXTERNAL}:80")
    with pytest.raises(ValueError):
        to_alert(_record(0, "kernel: something else"), 1)


def test_iter_alerts_streams_in_order_with_time_window(tmp_path):
    base = int(T0.timestamp() * 1000)
    lines = [_record(base + i * 1000, _line(f"172.16.1.{2 + i}:5000", "172.16.0.3:9200")) for i in range(4)]
    path = tmp_path / "suricata_alerts.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("suricata_alerts.jsonl", "".join(json.dumps(r) + "\n" for r in lines))
    assert [a["alert_id"] for a in iter_alerts(path)] == [f"dedale-suricata-{i}" for i in range(1, 5)]
    window = list(iter_alerts(path, start=T0 + timedelta(seconds=1), end=T0 + timedelta(seconds=3)))
    assert [a["src_ip"] for a in window] == ["172.16.1.3", "172.16.1.4"]


def test_entities_from_addresses(db):
    def ents(src, dst):
        a = with_entities(to_alert(_record(0, _line(src, dst)), 1), db)
        return a["source_host"], a["target_host"], a["destination_ip"]
    assert ents("172.16.1.3:52885", f"{EXTERNAL}:80") == ("CLIENT2", "CLIENT2", EXTERNAL)          # outbound
    assert ents("172.16.1.3:5000", "172.16.0.3:9200") == ("CLIENT2", "logserver", None)          # internal
    assert ents("172.19.0.8:2525", "172.17.0.2:25") == ("172.19.0.8", "dmzserver", None)          # inbound
    assert ents("172.18.0.1:53", f"{EXTERNAL}:53") == ("172.18.0.1", EXTERNAL, None)              # external


def test_pipeline_on_dedale_alerts(db):
    outbound = with_entities(to_alert(_record(0, _line("172.16.1.3:52885", f"{EXTERNAL}:80")), 1), db)
    res = run_downstream([], outbound, db.graph)
    h = res["hypotheses"][0]
    assert h["technique_id"] == "T1071" and h["sse_verdict"] == "FEASIBLE"
    assert h["top_action"] == "BLOCK_DESTINATION" and res["outcome"] == "AUTO_APPROVED"
    internal = with_entities(to_alert(_record(0, _line("172.16.1.3:5000", "172.16.0.3:9200")), 1), db)
    assert run_downstream([], internal, db.graph)["outcome"] == "NO_ACTIONABLE"
    assert db.projection_matches_store()


@pytest.mark.skipif(not (data_dir() / "suricata_alerts.zip").exists(), reason="DEDALE data not present")
def test_real_file_first_alerts_resolve(db):
    for alert in islice(iter_alerts(), 2000):
        for address in (alert["src_ip"], alert["dst_ip"]):
            if DEDALE_PROFILE.is_internal_address(address):
                assert db.host_for_address(address) is not None, address
