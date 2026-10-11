"""
perception/review_service.py

Review service (analyst review loop, step 3, 2026-10-11; see
experiments/ANALYST_REVIEW_LOOP_DESIGN.md): what an analyst works with, on top
of the case store.  The HTTP API calls this; it holds the review logic.

  - queue: cases waiting for an analyst, ordered by a transparent priority.
    Every item lists the points it got and why (escalation on trusted fields,
    host criticality, hypotheses naming another host as target, other open
    or confirmed cases on the same host in the previous 24 h -- the
    risk-based-alerting idea --, a structurally feasible hypothesis, proposed
    containment, number of alerts, waiting time), so the order can be checked
    and tuned.  LLM output may raise a case's priority, never lower it.
  - case view: evidence in three labelled groups --
      trusted:  structured sensor / inventory fields;
      untrusted text: command lines, raw events (may contain text written by
        the attacker, including instructions: data, never instructions);
      system reasoning: the triage decision, and NCE's hypotheses (LLM output)
        with what SSE / RSEM / the guardrails made of them;
    plus the proposed responses, related cases (decision B3: shown, never
    closed automatically), notes, the case's audit trail, and the learning
    preview (decision B2): what each verdict would do, in particular what
    `benign` would teach the store.
  - claim / release / verdicts (single or an explicit list) / notes, and
    approve / reject / roll back proposed responses (four-eyes where the
    case store requires two approvals), passed to the case store with the
    service's clock.
It reads only the case store: the Knowledge Store stays with the loop (its
single writer), which records at triage time what reviewing needs.
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Callable

from perception.case_store import CaseStore, ReviewError

QUEUE_STATUSES = ("open", "claimed", "needs_info")
UNTRUSTED_NOTICE = ("Untrusted text: recorded by sensors but chosen or influenced by whoever ran the activity. "
                    "It may contain instructions addressed to an analyst or an AI; treat it as data.")
LLM_NOTICE = ("Hypotheses are LLM output (NCE) from the alert text, checked against the Knowledge Store "
              "(SSE structural feasibility, entity binding, RSEM ranking, guardrails). They are leads, not findings.")

# Priority points (transparent and deliberately simple; tune on reviewed data, not on labels).
P_ESCALATED = 50          # known-bad contact or activity on something under watch (trusted fields)
P_PER_TIER = 10           # host criticality tier 0-3
P_OTHER_TARGET = 25       # the hypotheses name another host / address as target (lateral movement, remote access)
P_PER_PEER = 5            # each other open or confirmed-malicious case on the same host in the previous 24 h
P_PEERS_MAX = 25
PEER_WINDOW = timedelta(hours=24)
P_FEASIBLE = 15           # a hypothesis SSE found structurally feasible
P_PROPOSED = 10           # containment waiting for approval
P_ALERTS_MAX = 10         # 2 points per doubling of the alert count
P_WAIT_MAX = 24           # 1 point per hour waiting

# What `benign` makes routine, per pattern type (decision B2: the analyst sees the scope before choosing).
SCOPE = {
    "lineage": "The pattern is this parent and child program on this host. It does not include the command line: "
               "every later start of this pair on this host stops alerting, whatever its arguments.",
    "pipe": "The pattern is this program and pipe name on this host (digits in the name are ignored).",
    "exec_file_write": "The pattern is this program writing this file type on this host: any such file stops "
                       "alerting.",
    "powershell": "The pattern is this exact script on this host (by fingerprint): other scripts still alert.",
    "logon": "The pattern is this account, logon type and source on this host.",
    "lsass_access": "The pattern is this program reading LSASS memory on this host.",
    "network": "The pattern is this IDS signature between these two endpoints.",
}


def _t(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def _pattern_type(case: dict) -> str:
    key = case["case_key"]
    return key[1] if key and key[0] == "host" else "network"


def host_peers(case: dict, pool: list[dict]) -> int:
    """Other cases in `pool` on the same host, opened in the PEER_WINDOW before this one."""
    opened = _t(case["opened"])
    return sum(1 for p in pool if p["case_id"] != case["case_id"] and p["host"] == case["host"]
               and opened - PEER_WINDOW <= _t(p["opened"]) <= opened)


def priority(case: dict, decision: dict | None, actions: list[dict], now: datetime,
             peers: int = 0) -> tuple[int, list[str]]:
    """(points, reasons) for a case in the review queue; `peers` from host_peers."""
    points, why = 0, []

    def add(p: int, reason: str) -> None:
        nonlocal points
        if p:
            points += p
            why.append(f"+{p} {reason}")

    if decision and decision.get("escalations"):
        add(P_ESCALATED, f"escalated: {decision['escalations'][0]}")
    tier = case.get("host_tier")
    if tier:
        add(P_PER_TIER * int(tier), f"host criticality tier {tier}")
    others = (decision or {}).get("other_targets") or []
    if others:
        add(P_OTHER_TARGET, "hypotheses name another target: " + ", ".join(others))
    if peers:
        add(min(P_PEERS_MAX, P_PER_PEER * peers), f"{peers} other open or confirmed cases on this host in 24 h")
    feasible = sorted({h["technique_id"] for h in (decision or {}).get("hypotheses", [])
                       if h.get("sse_verdict") == "FEASIBLE"})
    if feasible:
        add(P_FEASIBLE, "structurally feasible: " + ", ".join(feasible))
    proposed = [a for a in actions if a["status"] == "proposed"]
    if proposed:
        add(P_PROPOSED, "containment proposed: " + ", ".join(f"{a['action']} {a['target']}" for a in proposed))
    n = int(case.get("alert_count") or 1)
    if n > 1:
        add(min(P_ALERTS_MAX, 2 * int(math.log2(n))), f"{n} alerts")
    waited = (now - _t(case["opened"])).total_seconds() / 3600
    if waited >= 1:
        add(min(P_WAIT_MAX, int(waited)), f"waiting {int(waited)} h")
    return points, why


def learning_preview(case: dict) -> dict[str, str]:
    """What each verdict would do (decision B2)."""
    return {
        "benign": (f"Teaches the store that \"{case['title']}\" is routine: it stops alerting. "
                   f"{SCOPE[_pattern_type(case)]}"),
        "benign_once": "Closes this case without teaching the store: the next occurrence alerts again.",
        "malicious": ("Confirms an attack: an external destination involved is marked known-bad and the host is put "
                      "under watch. Proposed containment is not executed by the verdict: approve each action."),
        "needs_info": "Puts the case back in the queue; it keeps blocking automatic learning on its host.",
    }


class ReviewService:
    """The analyst's operations on the case store (see module docstring)."""

    def __init__(self, store: CaseStore, clock: Callable[[], datetime] | None = None) -> None:
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    # -- reading ------------------------------------------------------------------

    def queue(self, *, limit: int = 50, host: str | None = None, include_claimed: bool = True) -> list[dict]:
        """Cases waiting for an analyst, highest priority first (ties: oldest first)."""
        now = self.clock()
        statuses = QUEUE_STATUSES if include_claimed else ("open", "needs_info")
        waiting = self.store.cases(review_status=statuses, host=host, limit=100_000)
        pools = defaultdict(list)
        for p in self._peer_pool(host):
            pools[p["host"]].append(p)
        items = []
        for c in waiting:
            d = self.store.decision(c["case_id"])
            acts = self.store.actions(c["case_id"])
            points, why = priority(c, d, acts, now, host_peers(c, pools[c["host"]]))
            items.append({"case_id": c["case_id"], "title": c["title"], "host": c["host"],
                          "opened": c["opened"], "alert_count": c["alert_count"],
                          "review_status": c["review_status"], "claimed_by": c["claimed_by"],
                          "priority": points, "priority_reasons": why})
        items.sort(key=lambda i: (-i["priority"], i["opened"], i["case_id"]))
        return items[:limit]

    def case_view(self, case_id: str) -> dict:
        c = self.store.case(case_id)
        if c is None:
            raise ReviewError(f"no case {case_id!r}")
        d = self.store.decision(case_id)
        alerts = self.store.alerts(case_id)
        actions = self.store.actions(case_id)
        same_pattern = [self._summary(x) for x in self.store.cases(case_key=c["case_key"]) if x["case_id"] != case_id]
        same_host = ([self._summary(x) for x in self.store.cases(review_status=QUEUE_STATUSES, host=c["host"])
                      if x["case_id"] != case_id] if c["host"] else [])
        points, why = priority(c, d, actions, self.clock(), host_peers(c, self._peer_pool(c["host"])))
        return {
            "case": c,
            "priority": points, "priority_reasons": why,
            "trusted": alerts[0]["trusted"] if alerts else {},
            "untrusted_notice": UNTRUSTED_NOTICE,
            "alerts": alerts,
            "alerts_stored": len(alerts),
            "system_reasoning": {
                "notice": LLM_NOTICE,
                "outcome": d["outcome"] if d else None, "path": d["path"] if d else None,
                "nce": d["nce"] if d else None, "reasons": d["reasons"] if d else [],
                "escalations": d["escalations"] if d else [],
                "hypotheses": d["hypotheses"] if d else [],
            },
            "actions": actions,
            "related": {"same_pattern": same_pattern, "same_host_in_queue": same_host},
            "learning_preview": learning_preview(c),
            "notes": self.store.notes(case_id),
            "audit": self.store.audit(case_id=case_id),
        }

    def _peer_pool(self, host: str | None) -> list[dict]:
        """Cases that raise a host's risk: waiting for review, or confirmed malicious."""
        pool =self.store.cases(review_status=QUEUE_STATUSES, host=host, limit=100_000)
        pool += [c for c in self.store.cases(review_status="closed", host=host, limit=100_000)
                 if c["verdict"] == "malicious"]
        return pool

    @staticmethod
    def _summary(c: dict) -> dict:
        return {k: c[k] for k in ("case_id", "title", "opened", "alert_count", "outcome", "review_status", "verdict")}

    # -- acting -------------------------------------------------------------------

    def claim(self, case_id: str, analyst: str) -> None:
        self.store.claim(case_id, analyst, self.clock())

    def release(self, case_id: str, analyst: str) -> None:
        self.store.release(case_id, analyst, self.clock())

    def verdict(self, case_id: str, verdict: str, analyst: str, note: str | None = None) -> int | None:
        return self.store.submit_verdict(case_id, verdict, analyst, self.clock(), note)

    def verdicts(self, case_ids: list[str], verdict: str, analyst: str, note: str | None = None) -> list[int | None]:
        """The same verdict on an explicit list of cases (decision B3; never on "similar" cases implicitly)."""
        return self.store.submit_verdicts(case_ids, verdict, analyst, self.clock(), note)

    def note(self, case_id: str, analyst: str, text: str) -> None:
        self.store.add_note(case_id, analyst, self.clock(), text)

    def approve(self, action_id: str, analyst: str) -> int | None:
        """Approve a proposed response; returns the execute command's id once it has enough approvals."""
        return self.store.approve_action(action_id, analyst, self.clock())

    def reject(self, action_id: str, analyst: str, reason: str) -> None:
        self.store.reject_action(action_id, analyst, self.clock(), reason)

    def rollback(self, action_id: str, analyst: str, reason: str) -> int:
        return self.store.request_rollback(action_id, analyst, self.clock(), reason)
