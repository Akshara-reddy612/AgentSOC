"""
perception/outcome_monitor.py

Outcome monitor: the base paper's Real-Time Monitoring (section III-D,
workflow steps 7-8) for an alert stream (design step S7, 2026-10-11; see
experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md).

When a case's decision auto-approves a response, the monitor watches the
response's target for `duration`:
  - every later alert that touches the target is counted (`hits`), and the
    ones the action would have stopped are counted separately
    (`would_block`: outbound contact with a blocked destination, outbound
    traffic from a host whose egress was blocked, anything involving a
    quarantined host).  Actions are dry runs, so this is SIMULATED
    (invariant I5): it says what the response would have prevented, not
    what happened;
  - a newly opened case touching the target gets an escalation reason through
    the triage gate's watch hook (`reasons`): activity on something already
    contained means the containment did not end the problem;
  - the response and, when the watch ends, its observed result are written
    to the target's node in the Knowledge Store as a `response` fact
    (mode "simulated"), so later reasoning sees what was done and what
    followed.  Observed facts (reputation etc.) are never overwritten.
Call `observe` for every alert and `advance` as time moves; register each
decision with `register`.
"""
from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass
from datetime import datetime, timedelta

from perception.environment import parse_ipv4
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_graph import account_node_id, host_node_id
from perception.knowledge_updater import ensure_endpoint, pattern_learned
from perception.outcome import AUTO_APPROVED
from perception.source_systems import SourceSystem
from perception.triage_gate import Decision

WATCH_DURATION = timedelta(days=7)
TARGET_KIND = {
    "BLOCK_DESTINATION": "destination",
    "BLOCK_EGRESS": "host",
    "QUARANTINE_ACCESS": "host",
    "REVOKE_SESSION": "account",
    "RESTRICT_PRIVILEGES": "account",
    "ENABLE_MFA": "account",
}


@dataclass(frozen=True)
class ProposedResponse:
    row: int                         # index of the hypothesis row in the decision
    action: str
    target: str
    target_kind: str                 # "destination" | "host" | "account"
    playbook_status: str             # "AUTO_APPROVED" | "PENDING_ANALYST_REVIEW"


def proposed_responses(decision: Decision) -> list[ProposedResponse]:
    """The containment responses a decision proposes: executable now (AUTO_APPROVED) or after approval."""
    out = []
    for i, row in enumerate(decision.hypotheses):
        action, status = row.get("top_action"), row.get("playbook_status")
        if action not in TARGET_KIND or status not in (AUTO_APPROVED, "PENDING_ANALYST_REVIEW"):
            continue
        kind = TARGET_KIND[action]
        target = row.get("top_target_account") if kind == "account" else row.get("top_target_host")
        if target:
            out.append(ProposedResponse(i, action, str(target), kind, status))
    return out


@dataclass
class Watch:
    watch_id: str
    case_id: str
    action: str
    target: str
    target_kind: str                 # "destination" | "host" | "account"
    since: datetime
    until: datetime
    hits: int = 0
    would_block: int = 0             # simulated: alerts the action would have stopped
    status: str = "active"           # "active" | "ended" | "rolled_back"


class OutcomeMonitor:
    """Watches the targets of auto-approved responses (see module docstring)."""

    def __init__(self, db: KnowledgeDB, *, duration: timedelta = WATCH_DURATION, writer: str = "monitor") -> None:
        self.db = db
        self.duration = duration
        self.writer = writer
        self._by_target: dict[tuple[str, str], list[Watch]] = {}
        self._expiry: list[tuple[datetime, int, Watch]] = []
        self._ids = itertools.count(1)
        self._by_id: dict[str, Watch] = {}
        self.finished: list[Watch] = []

    def register(self, decision: Decision, at: datetime, *, approved_by: str | None = None) -> list[Watch]:
        """
        Start watching the targets of the responses this decision auto-approved,
        or, with `approved_by`, the responses an analyst approved from review.
        """
        if approved_by is None and decision.outcome != AUTO_APPROVED:
            return []
        executed = {AUTO_APPROVED} if approved_by is None else {AUTO_APPROVED, "PENDING_ANALYST_REVIEW"}
        return [self.start(decision.case_id, r.action, r.target, r.target_kind, at)
                for r in proposed_responses(decision) if r.playbook_status in executed]

    def start(self, case_id: str, action: str, target: str, target_kind: str, at: datetime) -> Watch:
        """Start watching one executed response (simulated) on its target."""
        w = Watch(f"watch-{next(self._ids)}", case_id, action, target, target_kind, at, at + self.duration)
        self._by_target.setdefault((target_kind, target), []).append(w)
        self._by_id[w.watch_id] = w
        heapq.heappush(self._expiry, (w.until, next(self._ids), w))
        self._write_back(w, at, "active")
        return w

    def roll_back(self, watch_id: str, at: datetime) -> Watch | None:
        """An analyst rolled back the response: its watch ends now (None if it is not active)."""
        w = self._by_id.get(watch_id)
        if w is None or w.status != "active":
            return None
        self._by_target[(w.target_kind, w.target)].remove(w)
        w.until, w.status = at, "rolled_back"
        self._write_back(w, at, "rolled_back")
        self.finished.append(w)
        return w

    def flag_host(self, host: str, case_id: str, at: datetime) -> Watch:
        """An analyst confirmed malicious activity from this host: watch it (no containment effect)."""
        return self.start(case_id, "ANALYST_CONFIRMED", host, "host", at)

    def end_flags(self, case_id: str, at: datetime) -> list[str]:
        """A confirmation was withdrawn: end that case's ANALYST_CONFIRMED watches; returns their ids."""
        flags = [w for ws in self._by_target.values() for w in ws
                 if w.case_id == case_id and w.action == "ANALYST_CONFIRMED" and w.status == "active"]
        return [w.watch_id for w in flags if self.roll_back(w.watch_id, at) is not None]

    def host_confirmed(self, host: str, at: datetime) -> bool:
        """Is the host under an analyst's confirmed-compromise watch at `at`?"""
        return any(w.action == "ANALYST_CONFIRMED" and w.since <= at <= w.until
                   for w in self._by_target.get(("host", host), ()))

    def observe(self, alert: dict, at: datetime) -> None:
        """Count one alert against every active watch it touches."""
        for w in self._matching(alert, at):
            w.hits += 1
            if self._would_block(w, alert):
                w.would_block += 1

    def reasons(self, alert: dict, at: datetime) -> list[str]:
        """
        Escalation reasons for a newly opened case (the triage gate's watch hook).
        A containment watch escalates any activity on its target (the response
        should have ended it); an analyst's investigation flag on a host escalates
        only activity that is not a learned routine pattern.
        """
        return [f"{w.target_kind.capitalize()} {w.target} is under watch after the {w.action} response "
                f"to {w.case_id} ({w.since:%Y-%m-%d %H:%M}); activity continues "
                f"({w.hits} alerts since, {w.would_block} of them the response would have stopped)."
                for w in self._matching(alert, at)
                if not (w.action == "ANALYST_CONFIRMED" and self._routine(alert))]

    def advance(self, now: datetime) -> list[Watch]:
        """End the watches whose time is over and record their result in the store."""
        ended = []
        while self._expiry and self._expiry[0][0] <= now:
            _, _, w = heapq.heappop(self._expiry)
            if w.status != "active":                 # rolled back earlier
                continue
            self._by_target[(w.target_kind, w.target)].remove(w)
            w.status = "ended"
            self._write_back(w, w.until, "ended")
            self.finished.append(w)
            ended.append(w)
        return ended

    def finish(self, now: datetime) -> list[Watch]:
        """End of the stream: close every watch at `now`."""
        ended = []
        while self._expiry:
            _, _, w = heapq.heappop(self._expiry)
            if w.status != "active":
                continue
            self._by_target[(w.target_kind, w.target)].remove(w)
            w.status = "ended"
            self._write_back(w, min(now, w.until), "ended")
            self.finished.append(w)
            ended.append(w)
        return ended

    # -- internals ------------------------------------------------------------

    def _routine(self, alert: dict) -> bool:
        """Is this alert's pattern (network signature or host detector key) learned as routine?"""
        if "signature_id" not in alert and alert.get("kind") != "host":
            return False
        return pattern_learned(self.db, alert)

    def _matching(self, alert: dict, at: datetime) -> list[Watch]:
        # de-duplicated in a fixed order (a set's order changes with Python's per-process string hashing,
        # which made the order of escalation reasons differ between identical runs; fixed 2026-10-11)
        keys = dict.fromkeys([("destination", str(alert.get("destination_ip") or "")),
                              ("host", str(alert.get("source_host") or "")),
                              ("host", str(alert.get("target_host") or "")),
                              ("account", str(alert.get("source_user") or ""))])
        return [w for k in keys if k[1] for w in self._by_target.get(k, ()) if w.since < at <= w.until]

    @staticmethod
    def _would_block(w: Watch, alert: dict) -> bool:
        if w.action == "BLOCK_DESTINATION":
            return alert.get("destination_ip") == w.target
        if w.action == "BLOCK_EGRESS":
            return alert.get("source_host") == w.target and bool(alert.get("destination_ip"))
        if w.action == "QUARANTINE_ACCESS":
            return w.target in (alert.get("source_host"), alert.get("target_host"))
        return False                     # session / privilege actions: effect on network alerts unknown

    def _write_back(self, w: Watch, at: datetime, status: str) -> None:
        node = self._target_node(w, at)
        if node is None:
            return
        self.db.set_fact(node, "response", {
            "mode": "simulated", "status": status, "action": w.action, "case_id": w.case_id,
            "since": w.since, "until": w.until, "hits": w.hits, "would_block": w.would_block,
        }, confidence=1.0, source=SourceSystem.SYSTEM, writer=self.writer, at=at)

    def _target_node(self, w: Watch, at: datetime) -> str | None:
        g = self.db.graph.graph
        if w.target_kind == "account":
            node = account_node_id(w.target)
            return node if node in g else None
        if w.target_kind == "host" and host_node_id(w.target) in g:
            return host_node_id(w.target)
        if w.target_kind == "destination" or parse_ipv4(w.target):
            return ensure_endpoint(self.db, w.target, at, self.writer)
        return None
