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
    automatically; an analyst can close one as benign (provenance "analyst"),
    which also lifts its hold: an escalation an analyst has closed as benign no
    longer blocks learning about its endpoints (added 2026-10-11; before, every
    escalation blocked them, and on host alerts -- where the endpoint is the
    whole host -- reviews on a host blocked nearly all learning there);
  - with the gate switched off (ablation C3): every closed case at once,
    provenance "ungated".

Corroborated learning (decision P9 B, 2026-11-28; experiments/P9B_CORROBORATED_LEARNING_DESIGN.md; option,
off by default).  An attacker can get its tools' host keys learned by running them harmlessly first and letting
an analyst truthfully close those cases as benign (checklist A8).  With `corroboration` set, a host key learned
after training (verdict, gate release or ungated) is learned only if its pattern -- the key without its host,
`host_detection.edge_pattern` -- is corroborated by other hosts:
  - "fleet" (R1): the pattern was seen in training on another host;
  - "fleet_verdicts" (R1b): R1, or analysts closed the pattern as benign on at least `corroboration_hosts`
    other hosts that were not confirmed compromised at the time (the tally counts verdicts even when nothing is
    learned, so the first hosts are not deadlocked; it is kept in memory: a restarted loop starts it afresh).
An uncorroborated case is not learned: its hold is lifted (as `benign_once`) and its key alerts again.
Network patterns are per endpoint pair already and are not affected.
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
from perception.host_detection import DETECTORS, edge_pattern, key_pattern, learn_key
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_graph import destination_node_id, host_node_id
from perception.knowledge_store import KnowledgeFact
from perception.network_model import UNKNOWN
from perception.source_systems import SourceSystem

BENIGN_OUTCOMES = frozenset({"LOW_PRIORITY", "NO_ACTIONABLE"})
RETRACTABLE = frozenset({"closed_benign", "analyst", "ungated"})   # learned after training (decision B5)
ESCALATED_OUTCOMES = frozenset({"REVIEW", "AUTO_APPROVED"})
GATE_DELAY = timedelta(hours=24)
CORROBORATION = ("none", "fleet", "fleet_verdicts")        # decision P9 B (option; "none" = today's behaviour)


class KnowledgeUpdater:
    """The only writer of learned knowledge (see module docstring)."""

    def __init__(self, db: KnowledgeDB, *, gate: bool = True, gate_delay: timedelta = GATE_DELAY,
                 writer: str = "updater", corroboration: str = "none", corroboration_hosts: int = 2,
                 monitor=None) -> None:
        if corroboration not in CORROBORATION:
            raise ValueError(f"corroboration must be one of {CORROBORATION}")
        self.corroboration = corroboration
        self.corroboration_hosts = corroboration_hosts
        self._monitor = monitor          # OutcomeMonitor: is a host confirmed compromised? (an object, not a
                                         # bound method: the runner's safe checkpoint loader refuses those)
        self._fleet: dict[tuple, set[str]] | None = None         # pattern -> hosts that showed it in training
        self._verdict_hosts: dict[tuple, set[str]] = {}          # pattern -> hosts with a benign verdict on it
        self.uncorroborated = 0                                  # cases not learned for want of corroboration
        self.db = db
        self.gate = gate
        self.gate_delay = gate_delay
        self.writer = writer
        self._pending: list[tuple[datetime, int, Case]] = []     # heap by release time
        self._seq = itertools.count()
        self._escalations: dict[str, dict[str, datetime]] = {}   # address -> {case id: escalation time}
        self.dropped = 0                                         # benign cases not learned (escalation nearby)

    # -- inputs from the triage loop ------------------------------------------

    def record_outcome(self, case: Case, outcome: str, at: datetime) -> None:
        """Every triage decision.  An escalated case stops learning about its endpoints for now."""
        if outcome in ESCALATED_OUTCOMES:
            for address in _addresses(case):
                self._escalations.setdefault(address, {})[case.case_id] = at

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
            learned += self._learn(case, "closed_benign", release)
        return learned

    def _escalated_since(self, case: Case) -> bool:
        """Was a case involving one of this case's endpoints escalated after it opened (and not closed benign)?"""
        return any(t >= case.opened for a in _addresses(case) for t in self._escalations.get(a, {}).values())

    def analyst_closed_benign(self, case: Case, at: datetime, analyst: str) -> bool:
        """
        The analyst closed an escalated case as benign: lift its hold on its endpoints and learn it.  False if
        it was not learned (P9 B: its pattern is not corroborated).
        """
        self.lift_hold(case)
        a = case.first_alert
        if self.corroboration == "fleet_verdicts" and a.get("kind") == "host":
            pattern, host = key_pattern(a["detector"], a["detector_key"])
            host_name = str(a.get("target_host"))              # the monitor's own spelling of the host
            if self._monitor is None or not self._monitor.host_confirmed(host_name, at):
                self._verdict_hosts.setdefault(pattern, set()).add(host)
        return self._learn(case, "analyst", at, writer=f"analyst:{analyst}")

    # -- corroboration (P9 B) -----------------------------------------------------

    def index_training(self) -> None:
        """Record which hosts showed each pattern in training (called when training ends; rebuilt lazily if not)."""
        fleet: dict[tuple, set[str]] = {}
        for src, dst, key, _, _ in self.db.learned_edges({"training"}):
            attrs = self.db.edge_attrs(src, dst, key)
            hp = edge_pattern(attrs.get("edge_type", ""), src, dst, key) if attrs and "detector" in attrs else None
            if hp is not None:
                fleet.setdefault(hp[0], set()).add(hp[1])
        self._fleet = fleet

    def corroborated(self, detector: str, key: tuple) -> bool:
        """Is this host key's pattern corroborated by other hosts (see module docstring)?"""
        if self.corroboration == "none":
            return True
        if self._fleet is None:
            self.index_training()
        pattern, host = key_pattern(detector, key)
        if self._fleet.get(pattern, set()) - {host}:
            return True
        return (self.corroboration == "fleet_verdicts"
                and len(self._verdict_hosts.get(pattern, set()) - {host}) >= self.corroboration_hosts)

    def lift_hold(self, case: Case) -> None:
        """The analyst resolved this escalated case as not malicious: it stops blocking gated learning."""
        for address in _addresses(case):
            self._escalations.get(address, {}).pop(case.case_id, None)

    def retract_host_learning(self, host: str, since: datetime, at: datetime, writer: str) -> list[dict]:
        """
        Decision B5 (a): the host is confirmed compromised.  Patterns learned on it
        since `since` from closed cases or verdicts (not training, not config) may
        be the attacker's, so they are retracted: they alert again.  Returns the
        retracted edges as {"src", "dst", "key"} (what withdrawing the verdict restores).
        """
        node, lineage_key = host_node_id(host), f"host:{host.lower()}"
        out = []
        for src, dst, key, _, learned_at in self.db.learned_edges(RETRACTABLE):
            if learned_at < since or not (node in (src, dst) or key == lineage_key):
                continue
            if not self.db.graph.graph.has_edge(src, dst, key):
                continue
            self.db.retract_edge(src, dst, key, writer=writer, at=at,
                                 reason=f"host {host} confirmed compromised; learned since {since.isoformat()}")
            out.append({"src": src, "dst": dst, "key": key})
        return out

    def retract_all_learning(self, host: str, since: datetime, at: datetime, writer: str) -> list[dict]:
        """
        Cross-host unlearning (option, 2026-11-23; checklist A8 mitigation, off by default): `host` is confirmed
        compromised, so every pattern learned on any host since `since` from closed cases or verdicts may be the
        attacker's (it may already have moved on). Same retraction and return value as retract_host_learning.
        """
        out = []
        for src, dst, key, _, learned_at in self.db.learned_edges(RETRACTABLE):
            if learned_at < since:
                continue
            if not self.db.graph.graph.has_edge(src, dst, key):
                continue
            self.db.retract_edge(src, dst, key, writer=writer, at=at,
                                 reason=f"host {host} confirmed compromised (cross-host); learned since "
                                        f"{since.isoformat()}")
            out.append({"src": src, "dst": dst, "key": key})
        return out

    def learned_patterns(self, host: str, since: datetime) -> set[tuple]:
        """P9 B patterns of the host keys learned on `host` since `since` that B5 would retract (R6 reads them first)."""
        node, lineage_key, out = host_node_id(host), f"host:{host.lower()}", set()
        for src, dst, key, _, learned_at in self.db.learned_edges(RETRACTABLE):
            if learned_at < since or not (node in (src, dst) or key == lineage_key):
                continue
            attrs = self.db.edge_attrs(src, dst, key)
            hp = edge_pattern(attrs.get("edge_type", ""), src, dst, key) if attrs and "detector" in attrs else None
            if hp is not None:
                out.add(hp[0])
        return out

    def retract_pattern_learning(self, patterns: set[tuple], host: str, since: datetime, at: datetime,
                                 writer: str) -> list[dict]:
        """
        Pattern-following unlearning (P9 B rule R6 / P8 change 7, option, 2026-11-28): `host` is confirmed
        compromised, so the same patterns learned since `since` on other hosts (closed cases or verdicts) are
        retracted too.  Same return value as retract_host_learning.
        """
        out = []
        for src, dst, key, _, learned_at in self.db.learned_edges(RETRACTABLE):
            if learned_at < since or not self.db.graph.graph.has_edge(src, dst, key):
                continue
            attrs = self.db.edge_attrs(src, dst, key)
            hp = edge_pattern(attrs.get("edge_type", ""), src, dst, key) if attrs and "detector" in attrs else None
            if hp is None or hp[0] not in patterns or hp[1] == host.lower():
                continue
            self.db.retract_edge(src, dst, key, writer=writer, at=at,
                                 reason=f"host {host} confirmed compromised; same pattern learned since "
                                        f"{since.isoformat()}")
            out.append({"src": src, "dst": dst, "key": key})
        return out

    @property
    def pending(self) -> int:
        return len(self._pending)

    # -- writing ----------------------------------------------------------------

    def _learn(self, case: Case, provenance: str, at: datetime, writer: str | None = None) -> bool:
        """Learn a case; False if P9 B corroboration refused it (host keys after training only)."""
        a = case.first_alert
        writer = writer or self.writer
        if a.get("kind") == "host":                     # host alert: its detector key (Phase 2)
            if provenance in RETRACTABLE and not self.corroborated(a["detector"], tuple(a["detector_key"])):
                self.uncorroborated += 1
                return False
            learn_key(self.db, a["detector"], tuple(a["detector_key"]), provenance=provenance, at=at,
                      writer=writer, first_seen=case.opened, last_seen=case.last_seen, count=case.alert_count)
            return True
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
        return True

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
