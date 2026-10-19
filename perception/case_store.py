"""
perception/case_store.py

Case store (analyst review loop, step 1, 2026-10-11; see
experiments/ANALYST_REVIEW_LOOP_DESIGN.md): the persistent record of what the
SOC loop raised and what analysts did about it, and the loop's inbox.

  - What it holds: every case the loop triaged (test window) with its alerts
    (all counted; the first 50 of a review case and a sample of 5 of any other
    case stored in full -- raw telemetry stays in the SIEM / data store),
    the triage decision (hypotheses, SSE / RSEM / guardrail results, reasons),
    the containment responses the decision proposed, analyst claims, verdicts
    and notes, and an append-only audit trail of every state change.
  - Separate from the Knowledge Store on purpose.  The Knowledge Store holds
    only trusted, structured knowledge (invariant I1); the case store holds
    what analysts need to see, including attacker-influenced text (command
    lines, raw events) and LLM output, and nothing here is ever read as
    knowledge.  Each alert is split into `trusted` (structured sensor and
    inventory fields, TRUSTED_FIELDS) and `untrusted` (everything else,
    including any field not on the list).
  - The loop's inbox (single writer, invariant I6).  Analysts never write the
    Knowledge Store: a final verdict becomes a command here, and the loop
    applies commands in order once its clock reaches their time, then marks
    each one applied with what it did.
  - Review status of a case: none (not for review) / open -> claimed ->
    closed; needs_info puts it back in the queue (it keeps its learning hold).
  - Proposed responses (step 4): proposed -> approved (enough approvals:
    one, or two different analysts under the four-eyes rule, decision B4)
    -> executed by the loop (simulated, invariant I5: watched by the outcome
    monitor) -> rollback_requested -> rolled_back; or proposed -> rejected.
    A verdict never executes containment by itself: each action is approved
    on its own.  Responses the policy auto-approved arrive as executed.
  - Times are event times (replay-safe), stored as ISO 8601 UTC.
All strings are data: a client must escape them when it displays them.
"""
from __future__ import annotations

import json
import ntpath
import re
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from perception.action_playbook import HARD_FLOOR_ACTIONS
from perception.case_builder import Case
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_graph import host_node_id
from perception.knowledge_store import KnowledgeFact
from perception.outcome import AUTO_APPROVED, REVIEW
from perception.outcome_monitor import TARGET_KIND, ProposedResponse, proposed_responses
from perception.triage_gate import Decision

SCHEMA_VERSION = 1
VERDICTS = ("malicious", "benign", "benign_once", "needs_info")
FINAL_VERDICTS = frozenset({"malicious", "benign", "benign_once"})
MAX_ALERTS_PER_CASE = 50          # stored in full per review case; the rest are counted (alert_count)
MAX_ALERTS_NOT_FOR_REVIEW = 5     # cases nobody reviews (LOW_PRIORITY, NO_ACTIONABLE, AUTO_APPROVED): a sample
_ANALYST_ID = re.compile(r"[A-Za-z0-9_.@-]{1,64}")

# Structured fields from sensors and the inventory.  Everything else in an alert
# (command lines, process and file names as free text, raw log lines, any field
# not listed here) is stored as untrusted text.  IDS rule text (signature,
# classification) comes from the rule set, not from the traffic.
TRUSTED_FIELDS = frozenset({
    "alert_id", "timestamp", "kind", "event_type", "source_system", "sensor",
    "detector", "detector_key", "event_ref",
    "source_host", "target_host", "source_user", "destination_ip", "destination_domain",
    "generator_id", "signature_id", "signature_rev", "signature", "classification", "priority", "severity",
    "protocol", "src_ip", "src_port", "dst_ip", "dst_port",
})

# Decision B4: hard-floor actions that cut off a host need a second analyst on critical hosts.
FOUR_EYES_ACTIONS = frozenset(a.value for a in HARD_FLOOR_ACTIONS if TARGET_KIND.get(a.value) == "host")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
    seq     INTEGER PRIMARY KEY AUTOINCREMENT,
    at      TEXT NOT NULL,
    actor   TEXT NOT NULL,
    op      TEXT NOT NULL,
    case_id TEXT,
    payload TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
    BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
    BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TABLE IF NOT EXISTS cases (
    case_id       TEXT PRIMARY KEY,
    case_key      TEXT NOT NULL,
    kind          TEXT NOT NULL,
    title         TEXT NOT NULL,
    host          TEXT,
    host_tier     INTEGER,
    opened        TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    closed        TEXT,
    close_reason  TEXT,
    alert_count   INTEGER NOT NULL,
    outcome       TEXT NOT NULL,
    review_status TEXT NOT NULL,
    claimed_by    TEXT,
    verdict       TEXT
);
CREATE INDEX IF NOT EXISTS cases_review ON cases (review_status, opened);
CREATE INDEX IF NOT EXISTS cases_host ON cases (host, opened);
CREATE INDEX IF NOT EXISTS cases_key ON cases (case_key);
CREATE TABLE IF NOT EXISTS alerts (
    case_id   TEXT NOT NULL,
    n         INTEGER NOT NULL,
    alert_id  TEXT NOT NULL,
    at        TEXT NOT NULL,
    trusted   TEXT NOT NULL,
    untrusted TEXT NOT NULL,
    PRIMARY KEY (case_id, n)
);
CREATE TRIGGER IF NOT EXISTS alerts_no_update BEFORE UPDATE ON alerts
    BEGIN SELECT RAISE(ABORT, 'alerts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS alerts_no_delete BEFORE DELETE ON alerts
    BEGIN SELECT RAISE(ABORT, 'alerts are append-only'); END;
CREATE TABLE IF NOT EXISTS decisions (
    case_id          TEXT PRIMARY KEY,
    at               TEXT NOT NULL,
    path             TEXT NOT NULL,
    outcome          TEXT NOT NULL,
    pipeline_outcome TEXT,
    nce              TEXT NOT NULL,
    reasons          TEXT NOT NULL,
    hypotheses       TEXT NOT NULL,
    store_seq        INTEGER NOT NULL,
    escalations      TEXT NOT NULL,
    other_targets    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
    action_id        TEXT PRIMARY KEY,
    case_id          TEXT NOT NULL,
    row              INTEGER NOT NULL,
    action           TEXT NOT NULL,
    target           TEXT NOT NULL,
    target_kind      TEXT NOT NULL,
    status           TEXT NOT NULL,
    approvals_needed INTEGER NOT NULL,
    approvals        TEXT NOT NULL,
    watch_id         TEXT
);
CREATE INDEX IF NOT EXISTS actions_case ON actions (case_id);
CREATE TABLE IF NOT EXISTS notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    at      TEXT NOT NULL,
    analyst TEXT NOT NULL,
    text    TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS notes_no_update BEFORE UPDATE ON notes
    BEGIN SELECT RAISE(ABORT, 'notes are append-only'); END;
CREATE TRIGGER IF NOT EXISTS notes_no_delete BEFORE DELETE ON notes
    BEGIN SELECT RAISE(ABORT, 'notes are append-only'); END;
CREATE TABLE IF NOT EXISTS commands (
    cmd_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    case_id    TEXT NOT NULL,
    action_id  TEXT,
    verdict    TEXT,
    actor      TEXT NOT NULL,
    at         TEXT NOT NULL,
    applied_at TEXT,
    result     TEXT
);
CREATE INDEX IF NOT EXISTS commands_pending ON commands (applied_at, at);
CREATE TRIGGER IF NOT EXISTS commands_no_delete BEFORE DELETE ON commands
    BEGIN SELECT RAISE(ABORT, 'commands are never deleted'); END;
CREATE TRIGGER IF NOT EXISTS commands_apply_once BEFORE UPDATE ON commands
    WHEN OLD.applied_at IS NOT NULL OR NEW.kind IS NOT OLD.kind OR NEW.case_id IS NOT OLD.case_id
      OR NEW.action_id IS NOT OLD.action_id OR NEW.verdict IS NOT OLD.verdict
      OR NEW.actor IS NOT OLD.actor OR NEW.at IS NOT OLD.at
    BEGIN SELECT RAISE(ABORT, 'a command is applied once and never changed'); END;
"""


class ReviewError(ValueError):
    """An analyst action that is not allowed in the case's current state."""


class NotFoundError(ReviewError):
    """No case or action with that id."""


class ConflictError(ReviewError):
    """The case is claimed by another analyst."""


@dataclass(frozen=True)
class Command:
    cmd_id: int
    kind: str                   # "verdict" | "execute" | "rollback" | "withdraw"
    case_id: str
    action_id: str | None
    verdict: str | None
    actor: str                  # "analyst:<id>"
    at: datetime


def _iso(t: datetime | None) -> str | None:
    if t is None:
        return None
    if t.tzinfo is None:
        raise ValueError("times must be timezone-aware (UTC)")
    # fixed width (always microseconds), so text order is time order in SQL comparisons
    return t.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _t(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def _json_default(v: Any) -> Any:
    if isinstance(v, datetime):
        return _iso(v)
    if isinstance(v, (set, frozenset)):
        return sorted(v, key=str)
    raise TypeError(f"cannot store a value of type {type(v).__name__}")


def _dumps(v: Any) -> str:
    return json.dumps(v, default=_json_default, sort_keys=True, separators=(",", ":"))


def split_alert(alert: dict) -> tuple[dict, dict]:
    """(trusted structured fields, untrusted text fields) of an alert."""
    trusted = {k: v for k, v in alert.items() if k in TRUSTED_FIELDS}
    untrusted = {k: v for k, v in alert.items() if k not in TRUSTED_FIELDS}
    return trusted, untrusted


def _base(path: str) -> str:
    return ntpath.basename(path or "") or "(none)"


def describe_pattern(alert: dict) -> str:
    """
    The alert's pattern in words, from structured fields only: what the store
    learns as routine if the case is closed `benign` (the learning preview of
    decision B2).
    """
    if alert.get("kind") == "host":
        d, k = alert["detector"], [str(x) for x in alert["detector_key"]]
        host = k[0]
        if d == "lineage":
            return f"{_base(k[1])} starting {_base(k[2])} on {host}"
        if d == "pipe":
            return f"{_base(k[1])} using pipe {k[2] or '(unnamed)'} on {host}"
        if d == "exec_file_write":
            return f"{_base(k[1])} writing .{k[2]} files on {host}"
        if d == "powershell":
            return f"PowerShell script {k[1][:12]} (fingerprint) on {host}"
        if d == "logon":
            return f"{k[1]} logging on to {host} (logon type {k[2]}, from {k[3]})"
        if d == "lsass_access":
            return f"{_base(k[1])} reading LSASS memory on {host}"
        return f"{d} {k}"
    return (f"{alert.get('signature')} [sid {alert.get('signature_id')}] "
            f"{alert.get('src_ip')} -> {alert.get('dst_ip')}:{alert.get('dst_port')}")


def host_tier(db: KnowledgeDB, host: str) -> int | None:
    """Criticality tier of an inventory host (by name or address), None if the store does not know it."""
    node = host_node_id(db.host_for_address(host) or host)
    g = db.graph.graph
    if node not in g:
        return None
    tier = g.nodes[node].get("criticality_tier")
    if isinstance(tier, KnowledgeFact):
        tier = tier.value
    return int(tier) if isinstance(tier, (int, float)) else None


def _host_key(db: KnowledgeDB, name: str) -> str:
    """A host name or address as one comparable key: inventory host for an address, lower case, no domain suffix."""
    n = (db.host_for_address(name.strip()) or name).strip().lower()
    for suffix in db.profile.internal_domain_suffixes:
        if n.endswith(suffix):
            return n[:-len(suffix)]
    return n


ENDPOINT_FIELDS = ("source_host", "target_host", "src_ip", "dst_ip", "destination_ip", "destination_domain")


def other_targets(db: KnowledgeDB, decision: Decision, alert: dict) -> list[str]:
    """
    Targets the hypotheses name that the alert itself does not (its own endpoints
    excluded; addresses resolved to inventory hosts).  LLM output, so the review
    queue uses it only to raise attention, never to lower it.  Endpoints other
    than the host were added 2026-10-19: a network alert's own destination (a
    STUN server) counted as "another target" and put benign cases on top.
    """
    if not alert.get("target_host"):
        return []
    own = {_host_key(db, str(alert[k])) for k in ENDPOINT_FIELDS if alert.get(k)}
    out = []
    for h in decision.hypotheses:
        t = str(h.get("target_host") or "").strip()
        if t and _host_key(db, t) not in own and t not in out:
            out.append(t)
    return out


def approvals_needed(db: KnowledgeDB, response: ProposedResponse) -> int:
    """Decision B4: two different analysts for host cut-offs on hosts at or above the profile's tier."""
    min_tier = db.profile.four_eyes_min_tier
    if min_tier is None or response.action not in FOUR_EYES_ACTIONS:
        return 1
    tier = host_tier(db, response.target)
    return 2 if tier is not None and tier >= min_tier else 1


def is_valid_analyst_id(analyst: object) -> bool:
    return isinstance(analyst, str) and bool(_ANALYST_ID.fullmatch(analyst))


def _check_analyst(analyst: str) -> str:
    if not isinstance(analyst, str) or not _ANALYST_ID.fullmatch(analyst):
        raise ReviewError("analyst ids are 1-64 characters: letters, digits, _ . @ -")
    return analyst


class CaseStore:
    """SQLite-backed case store and inbox (see module docstring).  Safe to share between threads."""

    def __init__(self, path: str | Path, *, created_at: datetime | None = None) -> None:
        self.path = str(path)
        self._con = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        if self.path != ":memory:":
            self._con.execute("PRAGMA journal_mode=WAL")
            self._con.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.RLock()
        self._depth = 0
        self._alert_cap: dict[str, int] = {}          # open cases recorded by this process -> alerts to store
        self._con.executescript(_SCHEMA)
        row = self._con.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        if row is None:
            with self.batch():
                self._con.execute("INSERT INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
                self._audit(created_at or datetime.now(timezone.utc), "system", "created", None, {})
        elif row[0] != str(SCHEMA_VERSION):
            raise ValueError(f"case store schema {row[0]!r}, code expects {SCHEMA_VERSION}")

    def close(self) -> None:
        self._con.close()

    def backup_to(self, path: str | Path) -> None:
        """A consistent copy of the store (SQLite backup API), taken under the store's lock."""
        with self._lock:
            if self._depth:
                raise RuntimeError("backup inside a batch")
            dst = sqlite3.connect(str(path))
            try:
                self._con.backup(dst)
            finally:
                dst.close()

    def __enter__(self) -> "CaseStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @contextmanager
    def batch(self) -> Iterator[None]:
        """Group writes into one transaction (all or nothing); also serialises access between threads."""
        with self._lock:
            if self._depth:
                self._depth += 1
                try:
                    yield
                finally:
                    self._depth -= 1
                return
            self._con.execute("BEGIN IMMEDIATE")
            self._depth = 1
            try:
                yield
            except BaseException:
                self._con.execute("ROLLBACK")
                raise
            else:
                self._con.execute("COMMIT")
            finally:
                self._depth = 0

    def _audit(self, at: datetime, actor: str, op: str, case_id: str | None, payload: dict) -> int:
        cur = self._con.execute("INSERT INTO audit (at, actor, op, case_id, payload) VALUES (?, ?, ?, ?, ?)",
                                (_iso(at), actor, op, case_id, _dumps(payload)))
        return cur.lastrowid

    # -- written by the loop (actor "loop") -------------------------------------

    def case_opened(self, case: Case, alert: dict, at: datetime, decision: Decision,
                    approvals: Callable[[ProposedResponse], int] = lambda r: 1,
                    host_tier: int | None = None, watch_ids: dict[int, str] | None = None,
                    other_targets: list[str] | None = None) -> None:
        """
        A newly opened, triaged case: its row, first alert, decision and proposed
        responses.  What the review side needs from the Knowledge Store (the host's
        criticality tier, the approvals each response needs) is recorded here, so
        reviewing never reads the Knowledge Store.
        """
        review = "open" if decision.outcome == REVIEW else "none"
        self._alert_cap[case.case_id] = MAX_ALERTS_PER_CASE if review == "open" else MAX_ALERTS_NOT_FOR_REVIEW
        with self.batch():
            self._con.execute(
                "INSERT INTO cases (case_id, case_key, kind, title, host, host_tier, opened, last_seen, alert_count,"
                " outcome, review_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (case.case_id, _dumps(list(case.key)), alert.get("kind") or "network", describe_pattern(alert),
                 alert.get("target_host"), host_tier, _iso(case.opened), _iso(case.last_seen), case.alert_count,
                 decision.outcome, review))
            self._insert_alert(case.case_id, 0, alert, at)
            self._con.execute(
                "INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (case.case_id, _iso(decision.at), decision.path, decision.outcome, decision.pipeline_outcome,
                 decision.nce, _dumps(decision.reasons), _dumps(decision.hypotheses), decision.store_seq,
                 _dumps(decision.escalations), _dumps(other_targets or [])))
            self._audit(at, "loop", "case_opened", case.case_id,
                        {"outcome": decision.outcome, "path": decision.path, "review_status": review})
            for r in proposed_responses(decision):
                executed = decision.outcome == AUTO_APPROVED and r.playbook_status == AUTO_APPROVED
                status, needed = ("executed", 1) if executed else ("proposed", approvals(r))
                action_id = f"{case.case_id}:a{r.row}"
                self._con.execute("INSERT INTO actions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                  (action_id, case.case_id, r.row, r.action, r.target, r.target_kind, status,
                                   needed, _dumps(["auto"] if executed else []),
                                   (watch_ids or {}).get(r.row) if executed else None))
                self._audit(at, "loop", "action_executed" if executed else "action_proposed", case.case_id,
                            {"action_id": action_id, "action": r.action, "target": r.target,
                             "approvals_needed": needed})

    def alert_attached(self, case: Case, alert: dict, at: datetime) -> None:
        """A later alert of a recorded case (the first 50 of a review case, 5 otherwise, are stored in full)."""
        with self.batch():
            cur = self._con.execute("UPDATE cases SET last_seen = ?, alert_count = ? WHERE case_id = ?",
                                    (_iso(case.last_seen), case.alert_count, case.case_id))
            if cur.rowcount and case.alert_count <= self._alert_cap.get(case.case_id, MAX_ALERTS_PER_CASE):
                self._insert_alert(case.case_id, case.alert_count - 1, alert, at)

    def case_closed(self, case: Case) -> None:
        self._alert_cap.pop(case.case_id, None)
        with self.batch():
            cur = self._con.execute(
                "UPDATE cases SET closed = ?, close_reason = ?, last_seen = ?, alert_count = ? WHERE case_id = ?",
                (_iso(case.closed), case.close_reason, _iso(case.last_seen), case.alert_count, case.case_id))
            if cur.rowcount:
                self._audit(case.closed, "loop", "case_closed", case.case_id, {"reason": case.close_reason})

    def _insert_alert(self, case_id: str, n: int, alert: dict, at: datetime) -> None:
        trusted, untrusted = split_alert(alert)
        self._con.execute("INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?)",
                          (case_id, n, str(alert.get("alert_id")), _iso(at), _dumps(trusted), _dumps(untrusted)))

    # -- analyst actions ------------------------------------------------------------

    def _review_row(self, case_id: str) -> tuple[str, str | None]:
        row = self._con.execute("SELECT review_status, claimed_by FROM cases WHERE case_id = ?",
                                (case_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"no case {case_id!r}")
        return row

    def claim(self, case_id: str, analyst: str, at: datetime) -> None:
        """Take a case from the queue (an analyst works it; others see who)."""
        _check_analyst(analyst)
        with self.batch():
            status, owner = self._review_row(case_id)
            if status == "claimed" and owner == analyst:
                return
            if status == "claimed":
                raise ConflictError(f"{case_id} is claimed by {owner}")
            if status not in ("open", "needs_info"):
                raise ReviewError(f"{case_id} is not in the review queue (status {status})")
            self._con.execute("UPDATE cases SET review_status = 'claimed', claimed_by = ? WHERE case_id = ?",
                              (analyst, case_id))
            self._audit(at, f"analyst:{analyst}", "claim", case_id, {"from": status})

    def release(self, case_id: str, analyst: str, at: datetime) -> None:
        """Put a claimed case back in the queue."""
        _check_analyst(analyst)
        with self.batch():
            status, owner = self._review_row(case_id)
            if status != "claimed" or owner != analyst:
                raise ConflictError(f"{case_id} is not claimed by {analyst}")
            self._con.execute("UPDATE cases SET review_status = 'open', claimed_by = NULL WHERE case_id = ?",
                              (case_id,))
            self._audit(at, f"analyst:{analyst}", "release", case_id, {})

    def submit_verdict(self, case_id: str, verdict: str, analyst: str, at: datetime,
                       note: str | None = None) -> int | None:
        """
        An analyst's verdict.  A final verdict (malicious / benign / benign_once)
        closes the case and queues a command for the loop (returned: its id);
        needs_info puts the case back in the queue without a command.
        """
        _check_analyst(analyst)
        if verdict not in VERDICTS:
            raise ReviewError(f"verdict must be one of {VERDICTS}")
        with self.batch():
            status, owner = self._review_row(case_id)
            if status not in ("open", "claimed", "needs_info"):
                raise ReviewError(f"{case_id} is not under review (status {status})")
            if status == "claimed" and owner != analyst:
                raise ConflictError(f"{case_id} is claimed by {owner}")
            actor = f"analyst:{analyst}"
            if note:
                self._add_note(case_id, analyst, at, note)
            if verdict == "needs_info":
                self._con.execute("UPDATE cases SET review_status = 'needs_info', claimed_by = NULL"
                                  " WHERE case_id = ?", (case_id,))
                self._audit(at, actor, "verdict", case_id, {"verdict": verdict})
                return None
            self._con.execute("UPDATE cases SET review_status = 'closed', claimed_by = ?, verdict = ?"
                              " WHERE case_id = ?", (analyst, verdict, case_id))
            cur = self._con.execute("INSERT INTO commands (kind, case_id, verdict, actor, at) VALUES (?, ?, ?, ?, ?)",
                                    ("verdict", case_id, verdict, actor, _iso(at)))
            self._audit(at, actor, "verdict", case_id, {"verdict": verdict, "cmd_id": cur.lastrowid})
            return cur.lastrowid

    def withdraw_verdict(self, case_id: str, analyst: str, at: datetime, reason: str) -> int:
        """
        Withdraw a 'malicious' verdict found wrong: the case returns to the queue and the loop
        undoes the verdict's effects (command "withdraw").  Returns the command id.
        """
        _check_analyst(analyst)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
            raise ReviewError("withdrawing a verdict needs a reason (1-1000 characters)")
        with self.batch():
            row = self._con.execute("SELECT review_status, verdict FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"no case {case_id!r}")
            if row != ("closed", "malicious"):
                raise ReviewError(f"{case_id} has no 'malicious' verdict to withdraw")
            self._con.execute("UPDATE cases SET review_status = 'open', verdict = NULL, claimed_by = NULL"
                              " WHERE case_id = ?", (case_id,))
            actor = f"analyst:{analyst}"
            cmd = self._con.execute("INSERT INTO commands (kind, case_id, actor, at) VALUES (?, ?, ?, ?)",
                                    ("withdraw", case_id, actor, _iso(at))).lastrowid
            self._audit(at, actor, "verdict_withdrawn", case_id, {"reason": reason, "cmd_id": cmd})
            return cmd

    def submit_verdicts(self, case_ids: list[str], verdict: str, analyst: str, at: datetime,
                        note: str | None = None) -> list[int | None]:
        """The same verdict on an explicit list of cases (decision B3): all or nothing, each audited."""
        if not case_ids or len(set(case_ids)) != len(case_ids):
            raise ReviewError("give a non-empty list of distinct case ids")
        with self.batch():
            return [self.submit_verdict(c, verdict, analyst, at, note) for c in case_ids]

    def _action_row(self, action_id: str) -> dict:
        cur = self._con.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,))
        row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"no action {action_id!r}")
        a = dict(zip([d[0] for d in cur.description], row))
        a["approvals"] = json.loads(a["approvals"])
        return a

    def approve_action(self, action_id: str, analyst: str, at: datetime) -> int | None:
        """
        One analyst's approval of a proposed response.  With enough approvals
        (two different analysts under the four-eyes rule) the action is
        approved and queued for the loop to execute; returns that command's id.
        """
        _check_analyst(analyst)
        with self.batch():
            a = self._action_row(action_id)
            if a["status"] != "proposed":
                raise ReviewError(f"{action_id} is {a['status']}, not proposed")
            if analyst in a["approvals"]:
                raise ReviewError(f"{analyst} already approved {action_id}; a different analyst must approve it")
            approvals = [*a["approvals"], analyst]
            done = len(approvals) >= a["approvals_needed"]
            self._con.execute("UPDATE actions SET approvals = ?, status = ? WHERE action_id = ?",
                              (_dumps(approvals), "approved" if done else "proposed", action_id))
            actor = f"analyst:{analyst}"
            cmd_id = None
            if done:
                cmd_id = self._con.execute(
                    "INSERT INTO commands (kind, case_id, action_id, actor, at) VALUES (?, ?, ?, ?, ?)",
                    ("execute", a["case_id"], action_id, actor, _iso(at))).lastrowid
            self._audit(at, actor, "action_approval", a["case_id"],
                        {"action_id": action_id, "approvals": f"{len(approvals)}/{a['approvals_needed']}",
                         "cmd_id": cmd_id})
            return cmd_id

    def reject_action(self, action_id: str, analyst: str, at: datetime, reason: str) -> None:
        _check_analyst(analyst)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
            raise ReviewError("a rejection needs a reason (1-1000 characters)")
        with self.batch():
            a = self._action_row(action_id)
            if a["status"] != "proposed":
                raise ReviewError(f"{action_id} is {a['status']}, not proposed")
            self._con.execute("UPDATE actions SET status = 'rejected' WHERE action_id = ?", (action_id,))
            self._audit(at, f"analyst:{analyst}", "action_rejected", a["case_id"],
                        {"action_id": action_id, "reason": reason})

    def request_rollback(self, action_id: str, analyst: str, at: datetime, reason: str) -> int:
        """Undo an executed response (any analyst, decision B4); the loop ends it.  Returns the command id."""
        _check_analyst(analyst)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
            raise ReviewError("a rollback needs a reason (1-1000 characters)")
        with self.batch():
            a = self._action_row(action_id)
            if a["status"] != "executed":
                raise ReviewError(f"{action_id} is {a['status']}; only an executed action can be rolled back")
            self._con.execute("UPDATE actions SET status = 'rollback_requested' WHERE action_id = ?", (action_id,))
            actor = f"analyst:{analyst}"
            cmd_id = self._con.execute(
                "INSERT INTO commands (kind, case_id, action_id, actor, at) VALUES (?, ?, ?, ?, ?)",
                ("rollback", a["case_id"], action_id, actor, _iso(at))).lastrowid
            self._audit(at, actor, "rollback_requested", a["case_id"],
                        {"action_id": action_id, "reason": reason, "cmd_id": cmd_id})
            return cmd_id

    def add_note(self, case_id: str, analyst: str, at: datetime, text: str) -> None:
        """Free-text note (stays in the case store; never read as knowledge)."""
        _check_analyst(analyst)
        with self.batch():
            self._review_row(case_id)
            self._add_note(case_id, analyst, at, text)

    def _add_note(self, case_id: str, analyst: str, at: datetime, text: str) -> None:
        if not isinstance(text, str) or not text.strip() or len(text) > 10_000:
            raise ReviewError("a note is 1-10000 characters of text")
        cur = self._con.execute("INSERT INTO notes (case_id, at, analyst, text) VALUES (?, ?, ?, ?)",
                                (case_id, _iso(at), analyst, text))
        self._audit(at, f"analyst:{analyst}", "note", case_id, {"note_id": cur.lastrowid})

    # -- the loop's inbox -------------------------------------------------------------

    def pending_commands(self, upto: datetime) -> list[Command]:
        """Commands not yet applied whose time is at or before `upto`, in order."""
        with self._lock:
            rows = self._con.execute(
                "SELECT cmd_id, kind, case_id, action_id, verdict, actor, at FROM commands"
                " WHERE applied_at IS NULL AND at <= ? ORDER BY at, cmd_id", (_iso(upto),)).fetchall()
        return [Command(i, k, c, a, v, actor, _t(t)) for i, k, c, a, v, actor, t in rows]

    def mark_applied(self, cmd_id: int, at: datetime, result: dict) -> None:
        with self.batch():
            cur = self._con.execute("UPDATE commands SET applied_at = ?, result = ? WHERE cmd_id = ?"
                                    " AND applied_at IS NULL", (_iso(at), _dumps(result), cmd_id))
            if not cur.rowcount:
                raise ReviewError(f"command {cmd_id} does not exist or was already applied")
            case_id, kind, action_id = self._con.execute(
                "SELECT case_id, kind, action_id FROM commands WHERE cmd_id = ?", (cmd_id,)).fetchone()
            ok = bool(result.get("applied"))
            if kind == "execute":
                self._con.execute("UPDATE actions SET status = ?, watch_id = ? WHERE action_id = ?",
                                  ("executed" if ok else "approved", result.get("watch_id"), action_id))
            elif kind == "rollback":
                self._con.execute("UPDATE actions SET status = ? WHERE action_id = ?",
                                  ("rolled_back" if ok else "executed", action_id))
            self._audit(at, "loop", "command_applied", case_id, {"cmd_id": cmd_id, "kind": kind, **result})

    # -- reading ------------------------------------------------------------------------

    def _rows(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._lock:
            cur = self._con.execute(sql, args)
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r)) for r in cur.fetchall()]

    def case(self, case_id: str) -> dict | None:
        rows = self._rows("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        if not rows:
            return None
        c = rows[0]
        c["case_key"] = json.loads(c["case_key"])
        return c

    def alert_total(self) -> int:
        """Alerts of all recorded cases (the loop records cases after its training window only)."""
        return self._con.execute("SELECT COALESCE(SUM(alert_count), 0) FROM cases").fetchone()[0]

    def cases(self, *, review_status: str | tuple[str, ...] | None = None, host: str | None = None,
              case_key: list | None = None, limit: int = 1000) -> list[dict]:
        where, args = [], []
        if review_status is not None:
            statuses = (review_status,) if isinstance(review_status, str) else tuple(review_status)
            where.append(f"review_status IN ({','.join('?' * len(statuses))})")
            args += statuses
        if host is not None:
            where.append("host = ?")
            args.append(host)
        if case_key is not None:
            where.append("case_key = ?")
            args.append(_dumps(list(case_key)))
        sql = "SELECT * FROM cases" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY opened LIMIT ?"
        out = self._rows(sql, (*args, limit))
        for c in out:
            c["case_key"] = json.loads(c["case_key"])
        return out

    def alerts(self, case_id: str) -> list[dict]:
        out = self._rows("SELECT n, alert_id, at, trusted, untrusted FROM alerts WHERE case_id = ? ORDER BY n",
                         (case_id,))
        for a in out:
            a["trusted"], a["untrusted"] = json.loads(a["trusted"]), json.loads(a["untrusted"])
        return out

    def decision(self, case_id: str) -> dict | None:
        rows = self._rows("SELECT * FROM decisions WHERE case_id = ?", (case_id,))
        if not rows:
            return None
        d = rows[0]
        for k in ("reasons", "hypotheses", "escalations", "other_targets"):
            d[k] = json.loads(d[k])
        return d

    def action(self, action_id: str) -> dict | None:
        with self._lock:
            try:
                return self._action_row(action_id)
            except ReviewError:
                return None

    def actions(self, case_id: str) -> list[dict]:
        out = self._rows("SELECT * FROM actions WHERE case_id = ? ORDER BY row", (case_id,))
        for a in out:
            a["approvals"] = json.loads(a["approvals"])
        return out

    def notes(self, case_id: str) -> list[dict]:
        return self._rows("SELECT note_id, at, analyst, text FROM notes WHERE case_id = ? ORDER BY note_id",
                          (case_id,))

    def commands(self, case_id: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM commands", ()
        if case_id is not None:
            sql, args = sql + " WHERE case_id = ?", (case_id,)
        out = self._rows(sql + " ORDER BY cmd_id", args)
        for c in out:
            c["result"] = json.loads(c["result"]) if c["result"] else None
        return out

    def audit(self, since_seq: int = 0, case_id: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM audit WHERE seq > ?", (since_seq,)
        if case_id is not None:
            sql, args = sql + " AND case_id = ?", (since_seq, case_id)
        out = self._rows(sql + " ORDER BY seq", args)
        for e in out:
            e["payload"] = json.loads(e["payload"])
        return out
