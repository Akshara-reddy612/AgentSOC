"""
perception/knowledge_updater.py

The Knowledge Store's learning writer (design step S5, 2026-10-11; see
experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md): what the store learns from
closed cases, and when it may treat something as normal.

What is learned from a case, from structured fields only (invariant I1: never
NCE output, never the alert's text):
  - an ALERT_PATTERN edge source -> destination, key "sid:<signature id>": this
    detection fires between these endpoints;
  - a COMMUNICATES_WITH edge, key "<protocol>/<destination port>": the
    endpoints talk on this port.
Both carry first/last seen, case and alert counts, and how many times each
provenance contributed.  An endpoint is the inventory host when the store
knows the address, otherwise a node created with provenance "telemetry" (an
external address becomes an ExternalDestination with reputation "unknown").

When (invariant I3, the learning gate):
  - training window: every closed case, provenance "training";
  - afterwards: only cases that ended LOW_PRIORITY or NO_ACTIONABLE, released
    `gate_delay` after they closed, and only if no case involving one of the
    same endpoints was escalated (REVIEW / AUTO_APPROVED) since the case
    opened; provenance "closed_benign".  Escalated cases are never learned
    automatically; an analyst can close one as benign (provenance "analyst");
  - with the gate switched off (ablation C3): every closed case at once,
    provenance "ungated".
Network cases only for now (the case's first alert has src_ip / dst_ip /
signature_id / protocol / dst_port).  Every write goes through KnowledgeDB and
its audit log (invariant I6).
"""
from __future__ import annotations

import heapq
import itertools
from datetime import datetime, timedelta

from perception.case_builder import Case
from perception.environment import parse_ipv4
from perception.host_detection import DETECTORS, learn_key
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_graph import destination_node_id, host_node_id
from perception.knowledge_store import KnowledgeFact
from perception.network_model import UNKNOWN
from perception.source_systems import SourceSystem

BENIGN_OUTCOMES = frozenset({"LOW_PRIORITY", "NO_ACTIONABLE"})
ESCALATED_OUTCOMES = frozenset({"REVIEW", "AUTO_APPROVED"})
GATE_DELAY = timedelta(hours=24)


class KnowledgeUpdater:
    """The only writer of learned knowledge (see module docstring)."""

    def __init__(self, db: KnowledgeDB, *, gate: bool = True, gate_delay: timedelta = GATE_DELAY,
                 writer: str = "updater") -> None:
        self.db = db
        self.gate = gate
        self.gate_delay = gate_delay
        self.writer = writer
        self._pending: list[tuple[datetime, int, Case]] = []     # heap by release time
        self._seq = itertools.count()
        self._last_escalation: dict[str, datetime] = {}          # address -> latest escalation time
        self.dropped = 0                                         # benign cases not learned (escalation nearby)

    # -- inputs from the triage loop ------------------------------------------

    def record_outcome(self, case: Case, outcome: str, at: datetime) -> None:
        """Every triage decision.  An escalated case stops learning about its endpoints for now."""
        if outcome in ESCALATED_OUTCOMES:
            for address in _addresses(case):
                prev = self._last_escalation.get(address)
                self._last_escalation[address] = at if prev is None else max(prev, at)

    def case_closed(self, case: Case, outcome: str, *, training: bool) -> None:
        if training:
            self._learn(case, "training", case.closed)
        elif not self.gate:
            self._learn(case, "ungated", case.closed)
        elif outcome in BENIGN_OUTCOMES:
            heapq.heappush(self._pending, (case.closed + self.gate_delay, next(self._seq), case))

    def advance(self, now: datetime) -> int:
        """
        Release the pending benign cases whose gate delay has passed; returns how
        many were learned.  Call it before the triage step for time `now`, so
        every escalation it sees happened before the releases it decides.
        """
        learned = 0
        while self._pending and self._pending[0][0] <= now:
            release, _, case = heapq.heappop(self._pending)
            if self._escalated_since(case):
                self.dropped += 1
                continue
            self._learn(case, "closed_benign", release)
            learned += 1
        return learned

    def _escalated_since(self, case: Case) -> bool:
        """Was a case involving one of this case's endpoints escalated after it opened?"""
        return any((t := self._last_escalation.get(a)) is not None and t >= case.opened
                   for a in _addresses(case))

    def analyst_closed_benign(self, case: Case, at: datetime, analyst: str) -> None:
        self._learn(case, "analyst", at, writer=f"analyst:{analyst}")

    @property
    def pending(self) -> int:
        return len(self._pending)

    # -- writing ----------------------------------------------------------------

    def _learn(self, case: Case, provenance: str, at: datetime, writer: str | None = None) -> None:
        a = case.first_alert
        writer = writer or self.writer
        if a.get("kind") == "host":                     # host alert: its detector key (Phase 2)
            learn_key(self.db, a["detector"], tuple(a["detector_key"]), provenance=provenance, at=at,
                      writer=writer, first_seen=case.opened, last_seen=case.last_seen, count=case.alert_count)
            return
        sid = int(a["signature_id"])
        with self.db.batch():
            src = self._endpoint(str(a["src_ip"]), at, writer)
            dst = self._endpoint(str(a["dst_ip"]), at, writer)
            self._count_edge(src, dst, f"sid:{sid}", {"edge_type": "ALERT_PATTERN", "signature_id": sid},
                             case, provenance, at, writer)
            proto, port = str(a["protocol"]), int(a["dst_port"])
            self._count_edge(src, dst, f"{proto}/{port}",
                             {"edge_type": "COMMUNICATES_WITH", "protocol": proto, "port": port},
                             case, provenance, at, writer)

    def _endpoint(self, address: str, at: datetime, writer: str) -> str:
        return ensure_endpoint(self.db, address, at, writer)

    def _count_edge(self, src: str, dst: str, key: str, base: dict, case: Case, provenance: str,
                    at: datetime, writer: str) -> None:
        old = self.db.edge_attrs(src, dst, key)
        if old is None:
            self.db.add_edge(src, dst, key, {
                **base, "first_seen": case.opened, "last_seen": case.last_seen,
                "case_count": 1, "alert_count": case.alert_count, "provenance_counts": {provenance: 1},
            }, writer=writer, at=at, learned_from=provenance)
            return
        counts = dict(old["provenance_counts"])
        counts[provenance] = counts.get(provenance, 0) + 1
        self.db.update_edge(src, dst, key, {
            "first_seen": min(old["first_seen"], case.opened), "last_seen": max(old["last_seen"], case.last_seen),
            "case_count": old["case_count"] + 1, "alert_count": old["alert_count"] + case.alert_count,
            "provenance_counts": counts,
        }, writer=writer, at=at)


def pattern_edge(db: KnowledgeDB, alert: dict) -> tuple[str, str, str]:
    """(source node, destination node, edge key) under which an alert's pattern counts as learned."""
    if alert.get("kind") == "host":
        e = DETECTORS[alert["detector"]].edge(tuple(alert["detector_key"]))
        return e.src, e.dst, e.key
    return (endpoint_node_id(db, str(alert["src_ip"])), endpoint_node_id(db, str(alert["dst_ip"])),
            f"sid:{alert['signature_id']}")


def pattern_learned(db: KnowledgeDB, alert: dict) -> bool:
    src, dst, key = pattern_edge(db, alert)
    return db.graph.graph.has_edge(src, dst, key)


def endpoint_node_id(db: KnowledgeDB, address: str) -> str:
    """The node that stands for an address: its inventory host, else an internal address or external destination."""
    host = db.host_for_address(address)
    if host is not None:
        return host_node_id(host)
    return f"addr:{address}" if db.profile.is_internal_address(address) else destination_node_id(address)


def ensure_endpoint(db: KnowledgeDB, address: str, at: datetime, writer: str) -> str:
    """endpoint_node_id, creating the node (provenance "telemetry") if the store has none yet."""
    node = endpoint_node_id(db, address)
    if node in db.graph.graph:
        return node
    if node.startswith("addr:"):
        attrs = {"node_type": "AddressNode", "address": address}
    else:
        attrs = {"node_type": "ExternalDestination", "address": address,
                 "kind": "ip" if parse_ipv4(address) else "domain", "source": "observed",
                 "reputation": KnowledgeFact(value=UNKNOWN, version=1, confidence=1.0,
                                             source=SourceSystem.KNOWLEDGE_STORE, timestamp=at)}
    db.add_node(node, attrs, writer=writer, at=at, learned_from="telemetry")
    return node


def _addresses(case: Case) -> tuple[str, str]:
    """The case's two endpoints as the escalation bookkeeping names them (addresses, or hosts for host alerts)."""
    a = case.first_alert
    if a.get("kind") == "host":
        return str(a.get("source_host")), str(a.get("target_host"))
    return str(a["src_ip"]), str(a["dst_ip"])
