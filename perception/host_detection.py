"""
perception/host_detection.py

Host detection from the Knowledge Store (Phase 2, 2026-10-11; see
experiments/PHASE2_HOST_LOGS_DESIGN.md).

For host telemetry the store is the detector's memory.  A detector turns a
host event into a structured key -- which program started which program on
which host, which account logged on to which host how and from where, which
program read LSASS memory.  Keys the store has learned are routine and stay
silent; an event whose key the store does not know becomes a host alert, which
then goes through the same case builder, triage gate, outcome monitor and
gated learning as network alerts.

Keys use structured sensor fields only (paths of executables, account names,
logon types, addresses, host names; invariant I1).  Command lines and script
text are never part of a key and never learned: they are carried in the
alert as free-text evidence for NCE.

Each key is stored as one graph edge (learned with a provenance, like the
network alert patterns), so the projection SSE and the guardrails read holds
it too.  A first logon of an account on a host also becomes HAS_PRIOR_ACCESS,
the edge the expected-activity rule (perception/baseline.py) reads.
"""
from __future__ import annotations

import json
import ntpath
from dataclasses import dataclass
from typing import Callable

from perception.knowledge_db import KnowledgeDB
from perception.knowledge_graph import account_node_id, host_node_id

# Node ids for programs (executables).  Paths are case-insensitive on Windows.
def image_node_id(path: str) -> str:
    return f"image:{path.lower()}"


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    key: str
    edge_type: str
    src_attrs: dict
    dst_attrs: dict


@dataclass(frozen=True)
class HostDetector:
    name: str
    key: Callable[[dict], tuple | None]          # host event -> structured key, or None (not this detector's event)
    edge: Callable[[tuple], Edge]                # key -> the graph edge that records it as learned


def _image(path: str | None) -> dict:
    return {"node_type": "ImageNode", "path": path or ""}


def _lineage_key(e: dict) -> tuple | None:
    if e.get("ch") == "sysmon" and e.get("code") == 1 and e.get("image"):
        return (e["host"], (e.get("parent_image") or "").lower(), e["image"].lower())
    return None


def _lineage_edge(k: tuple) -> Edge:
    host, parent, child = k
    return Edge(image_node_id(parent), image_node_id(child), f"host:{host.lower()}", "SPAWNED",
                _image(parent), _image(child))


def _logon_key(e: dict) -> tuple | None:
    if e.get("ch") == "security" and e.get("code") == 4624 and e.get("user"):
        return (e["host"], e["user"].lower(), str(e.get("logon_type") or ""), str(e.get("ip") or "-"))
    return None


def _logon_edge(k: tuple) -> Edge:
    host, user, logon_type, ip = k
    return Edge(account_node_id(user), host_node_id(host), f"logon:{logon_type}|{ip}", "LOGON",
                {"node_type": "AccountNode", "account_id": user}, {"node_type": "HostNode", "host_id": host})


def _lsass_key(e: dict) -> tuple | None:
    if e.get("ch") == "sysmon" and e.get("code") == 10 and e.get("image"):
        return (e["host"], e["image"].lower())
    return None


def _lsass_edge(k: tuple) -> Edge:
    host, image = k
    return Edge(image_node_id(image), host_node_id(host), "lsass", "READS_LSASS",
                _image(image), {"node_type": "HostNode", "host_id": host})


DETECTORS: dict[str, HostDetector] = {d.name: d for d in (
    HostDetector("lineage", _lineage_key, _lineage_edge),
    HostDetector("logon", _logon_key, _logon_edge),
    HostDetector("lsass_access", _lsass_key, _lsass_edge),
)}


def novel_keys(db: KnowledgeDB, event: dict, detectors: tuple[str, ...]) -> list[tuple[str, tuple]]:
    """(detector, key) for every enabled detector whose key for this event the store has not learned."""
    g = db.graph.graph
    out = []
    for name in detectors:
        d = DETECTORS[name]
        k = d.key(event)
        if k is None:
            continue
        edge = d.edge(k)
        if not g.has_edge(edge.src, edge.dst, edge.key):
            out.append((name, k))
    return out


def host_alert(event: dict, detector: str, key: tuple, db: KnowledgeDB) -> dict:
    """A host alert in the pipeline's alert format: structured entities + free-text evidence for NCE."""
    host = event["host"]
    alert = {
        "alert_id": f"{event['host']}:{event['ch']}:{event['rid']}:{detector}",
        "timestamp": event["t"],
        "kind": "host",
        "event_type": f"host_{detector}",
        "source_system": "EDR",
        "detector": detector,
        "detector_key": list(key),
        "event_ref": [event["host"], event["ch"], event["rid"]],
        "source_host": host,
        "target_host": host,
        "source_user": event.get("user"),
        "destination_ip": None,
        "destination_domain": None,
        # free text (NCE evidence): sensor-recorded but attacker-influenced
        "process_name": ntpath.basename(event.get("image") or "") or None,
        "parent_process": ntpath.basename(event.get("parent_image") or "") or None,
        "command_line": event.get("cmd"),
        "file_path": event.get("image"),
        "raw_log_line": json.dumps(event, separators=(",", ":"), sort_keys=True),
    }
    if detector == "logon":
        source = db.host_for_address(str(event.get("ip") or "")) if event.get("ip") not in (None, "-") else None
        alert["source_host"] = source or event.get("ip") or host        # where the logon came from
    return alert


def learn_key(db: KnowledgeDB, detector: str, key: tuple, *, provenance: str, at, writer: str,
              first_seen=None, last_seen=None, count: int = 1) -> None:
    """Record a key as learned (one edge, created or counted), plus HAS_PRIOR_ACCESS for a first logon."""
    edge = DETECTORS[detector].edge(key)
    g = db.graph.graph
    with db.batch():
        for node, attrs in ((edge.src, edge.src_attrs), (edge.dst, edge.dst_attrs)):
            if node not in g:
                db.add_node(node, attrs, writer=writer, at=at, learned_from="telemetry")
        old = db.edge_attrs(edge.src, edge.dst, edge.key)
        if old is None:
            db.add_edge(edge.src, edge.dst, edge.key, {
                "edge_type": edge.edge_type, "detector": detector, "first_seen": first_seen or at,
                "last_seen": last_seen or at, "count": count, "provenance_counts": {provenance: 1},
            }, writer=writer, at=at, learned_from=provenance)
        else:
            counts = dict(old["provenance_counts"])
            counts[provenance] = counts.get(provenance, 0) + 1
            db.update_edge(edge.src, edge.dst, edge.key, {
                "last_seen": max(old["last_seen"], last_seen or at), "count": old["count"] + count,
                "provenance_counts": counts}, writer=writer, at=at)
        if detector == "logon" and not g.has_edge(edge.src, edge.dst, "HAS_PRIOR_ACCESS"):
            db.add_edge(edge.src, edge.dst, "HAS_PRIOR_ACCESS", {"edge_type": "HAS_PRIOR_ACCESS"},
                        writer=writer, at=at, learned_from=provenance)
