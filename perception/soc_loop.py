"""
perception/soc_loop.py

The Sense-Reason-Act loop over a time-ordered alert stream (design step S8,
2026-10-11; see experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md): the base
paper's workflow steps wired together for network alerts.

  per alert:   time moves on (gated learning released, watches ended)
               -> entity fields from the store (perception/network_alert)
               -> the outcome monitor counts it
               -> the case builder joins it to an open case or opens one
               -> a newly opened case is triaged (perception/triage_gate);
                  the decision goes to the outcome monitor and the updater
  per closed case: the updater may learn from it, behind the gate

Learning modes (the design's ablation):
  static  (C0) - nothing is learned;
  frozen  (C1) - learning during the training window only;
  gated   (C2) - learning continues behind the gate;
  ungated (C3) - learning continues without the gate.
During the training window the loop runs in shadow mode: cases are built and
learned from but not triaged or acted on (DEDALE's authors recommend the
benign weeks for training and calibration).  At the end of the window every
open case is closed, so the test window starts with fresh cases.

Analyst verdicts (open decision D1; review loop 2026-10-11).  `apply_verdict`
is the only path by which a verdict changes the Knowledge Store:
  - "benign" -> the updater learns the case (provenance "analyst"; not in
    frozen or static mode) and lifts its hold on gated learning;
  - "benign_once" -> the hold is lifted, nothing is learned;
  - "malicious" -> the proposed containment is approved (watched by the
    outcome monitor), an external destination is marked known-bad in the
    store, and the host is put under watch.
Verdicts arrive in two ways:
  - with a case store (perception/case_store.py), as commands in its inbox:
    analysts submit them there, never to the Knowledge Store, and the loop
    applies them in order once its clock reaches their time (single writer,
    invariant I6);
  - from the simulated analyst of the experiments, `analyst(case, decision,
    at)`, `analyst_delay` after each REVIEW case.  With a case store it
    submits through the inbox, as a person would.  In the DEDALE experiments
    it is an oracle that reads ground truth: a separate condition, never part
    of the system itself.
"""
from __future__ import annotations

import heapq
import itertools
from collections import Counter
from datetime import datetime, timedelta
from typing import Callable

from perception.case_builder import Case, CaseBuilder, alert_case_key
from perception.case_store import CaseStore, approvals_needed, host_tier
from perception.host_detection import DETECTORS, host_alert, learn_key, novel_keys
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_updater import GATE_DELAY, KnowledgeUpdater, ensure_endpoint
from perception.network_alert import with_entities
from perception.network_model import KNOWN_BAD
from perception.outcome import REVIEW
from perception.outcome_monitor import OutcomeMonitor
from perception.source_systems import SourceSystem
from perception.triage_gate import Decision, TriageGate

LEARNING_MODES = ("static", "frozen", "gated", "ungated")
ANALYST_DELAY = timedelta(hours=4)
SIMULATED_ANALYST = "oracle"
Analyst = Callable[[Case, Decision, datetime], "str | None"]


class SocLoop:
    """Runs one alert stream through the store-backed pipeline (see module docstring)."""

    def __init__(self, db: KnowledgeDB, *, mode: str, training_end: datetime,
                 cases: CaseBuilder | None = None, gate_delay: timedelta = GATE_DELAY,
                 on_case: Callable[[Case, Decision | None, bool], None] | None = None,
                 gate_options: dict | None = None, analyst: Analyst | None = None,
                 analyst_delay: timedelta = ANALYST_DELAY,
                 detectors: tuple[str, ...] = tuple(DETECTORS),
                 on_alert: Callable[[Case, dict], None] | None = None,
                 case_store: CaseStore | None = None) -> None:
        if mode not in LEARNING_MODES:
            raise ValueError(f"mode must be one of {LEARNING_MODES}")
        self.analyst = analyst
        self.analyst_delay = analyst_delay
        self.case_store = case_store                # test-window cases, decisions, alerts (review loop)
        self._awaiting: dict[str, tuple[Case, Decision]] = {}             # REVIEW cases without a verdict yet
        self._reviews: list[tuple[datetime, int, Case, Decision]] = []    # heap by verdict time
        self._review_seq = itertools.count()
        self.verdicts: list[tuple[str, datetime, str]] = []                # (case_id, time, verdict)
        self.db = db
        self.mode = mode
        self.training_end = training_end
        self.cases = cases or CaseBuilder(key=alert_case_key)
        self.detectors = detectors
        self.on_alert = on_alert
        self.monitor = OutcomeMonitor(db)
        self.gate = TriageGate(db, watch=self.monitor.reasons, **(gate_options or {}))
        self.updater = (None if mode == "static"
                        else KnowledgeUpdater(db, gate=mode != "ungated", gate_delay=gate_delay))
        self.on_case = on_case
        self.counts: Counter[str] = Counter()
        self._decisions: dict[str, Decision] = {}
        self._in_training = True

    def process(self, alert: dict, at: datetime) -> None:
        """One network alert (src_ip / dst_ip): entity fields from the store, then the shared alert path."""
        self._advance(at)
        a = with_entities(alert, self.db)
        self.monitor.observe(a, at)
        self._handle_alert(a, at)

    def process_host_event(self, event: dict, at: datetime) -> None:
        """
        One host event (Phase 2).  Training window: every key the detectors see is
        learned (shadow mode).  Afterwards: a key the store has not learned becomes a
        host alert on the shared alert path (perception/host_detection.py).
        """
        self._advance(at)
        if self._in_training:
            self.counts["events_training"] += 1
            if self.updater is not None:
                for name, key in novel_keys(self.db, event, self.detectors):
                    learn_key(self.db, name, key, provenance="training", at=at, writer=self.updater.writer)
            return
        self.counts["events_test"] += 1
        self.monitor.observe({"source_host": event["host"], "target_host": event["host"],
                              "source_user": event.get("user")}, at)
        for name, key in novel_keys(self.db, event, self.detectors):
            self._handle_alert(host_alert(event, name, key, self.db), at)

    def _advance(self, at: datetime) -> None:
        if self._in_training and at >= self.training_end:
            self._end_training()
        if self.updater is not None:
            self.updater.advance(at)
        self.monitor.advance(at)
        self._analyst_due(at)
        self._apply_commands(at)

    def _handle_alert(self, a: dict, at: datetime) -> None:
        closed, event, case = self.cases.add(a, at)
        for c in closed:
            self._closed(c)
        self.counts["alerts"] += 1
        if self.on_alert is not None:
            self.on_alert(case, a)
        if event == "opened":
            self.counts["cases_training" if self._in_training else "cases_test"] += 1
            if not self._in_training:
                d = self.gate.triage(case, a, at)
                self._decisions[case.case_id] = d
                if self.updater is not None:
                    self.updater.record_outcome(case, d.outcome, at)
                self.monitor.register(d, at)
                if d.outcome == REVIEW and (self.analyst is not None or self.case_store is not None):
                    self._awaiting[case.case_id] = (case, d)
                if self.analyst is not None and d.outcome == REVIEW:
                    heapq.heappush(self._reviews, (at + self.analyst_delay, next(self._review_seq), case, d))
                if self.case_store is not None:
                    self.case_store.case_opened(case, a, at, d, approvals=lambda r: approvals_needed(self.db, r),
                                                host_tier=host_tier(self.db, str(a.get("target_host") or "")))
        elif not self._in_training and self.case_store is not None:
            self.case_store.alert_attached(case, a, at)

    def finish(self, at: datetime) -> None:
        """End of the stream: close the open cases and end the watches."""
        if self._in_training:
            self._end_training()
        for c in self.cases.close_all(at):
            self._closed(c)
        self.monitor.finish(at)

    def apply_verdict(self, case_id: str, verdict: str, analyst: str, at: datetime) -> dict:
        """
        Apply an analyst's final verdict at time `at` (see module docstring);
        returns what was done.  A case that is not awaiting a verdict in this
        loop is left alone.
        """
        if verdict not in ("benign", "benign_once", "malicious"):
            raise ValueError(f"not a final verdict: {verdict!r}")
        entry = self._awaiting.pop(case_id, None)
        if entry is None:
            return {"applied": False, "reason": "case is not awaiting a verdict in this loop"}
        case, d = entry
        done: dict = {"applied": True, "verdict": verdict}
        if verdict == "benign":
            done["learned"] = self.updater is not None and self.mode != "frozen"
            if done["learned"]:
                self.updater.analyst_closed_benign(case, at, analyst)
        elif verdict == "benign_once":
            done["learned"] = False
            if self.updater is not None:
                self.updater.lift_hold(case)
        else:
            done.update(self._confirmed_malicious(case, d, at, f"analyst:{analyst}"))
        return done

    def _analyst_due(self, now: datetime) -> None:
        """The simulated analyst (experiments): a verdict `analyst_delay` after each REVIEW case."""
        while self._reviews and self._reviews[0][0] <= now:
            due, _, case, d = heapq.heappop(self._reviews)
            verdict = self.analyst(case, d, due)
            self.verdicts.append((case.case_id, due, verdict or "none"))
            if verdict not in ("benign", "malicious"):
                continue
            if self.case_store is not None:        # the path a person's verdict takes
                self.case_store.submit_verdict(case.case_id, verdict, SIMULATED_ANALYST, due)
                self._apply_commands(due, now)
            else:
                self.apply_verdict(case.case_id, verdict, SIMULATED_ANALYST, due)

    def _apply_commands(self, upto: datetime, now: datetime | None = None) -> None:
        """Apply the case store's commands whose time is at or before `upto`, in order."""
        if self.case_store is None:
            return
        for cmd in self.case_store.pending_commands(upto):
            if cmd.kind == "verdict":
                result = self.apply_verdict(cmd.case_id, cmd.verdict, cmd.actor.removeprefix("analyst:"), cmd.at)
            else:
                result = {"applied": False, "reason": f"unknown command kind {cmd.kind!r}"}
            self.case_store.mark_applied(cmd.cmd_id, now or upto, result)

    def _confirmed_malicious(self, case: Case, d: Decision, at: datetime, writer: str) -> dict:
        a = case.first_alert
        done: dict = {"known_bad": None, "flagged_host": None}
        if a.get("destination_ip"):
            node = ensure_endpoint(self.db, str(a["destination_ip"]), at, writer)
            self.db.set_fact(node, "reputation", KNOWN_BAD, confidence=1.0, source=SourceSystem.SYSTEM,
                             writer=writer, at=at)
            done["known_bad"] = str(a["destination_ip"])
        done["watches"] = [w.watch_id for w in self.monitor.register(d, at, approved_by=writer)]
        if a.get("kind") == "host":                 # the host where the confirmed activity happened
            done["flagged_host"] = str(a["target_host"])
        elif a.get("source_host") and self.db.profile.is_internal_address(str(a["src_ip"])):
            done["flagged_host"] = str(a["source_host"])
        if done["flagged_host"]:
            self.monitor.flag_host(done["flagged_host"], case.case_id, at)
        return done

    def _end_training(self) -> None:
        for c in self.cases.close_all(self.training_end, reason="end_of_training"):
            self._closed(c)
        self._in_training = False

    def _closed(self, case: Case) -> None:
        training = case.opened < self.training_end
        decision = self._decisions.pop(case.case_id, None)
        if self.updater is not None and (training or self.mode != "frozen"):
            self.updater.case_closed(case, decision.outcome if decision else "", training=training)
        if self.case_store is not None and not training:
            self.case_store.case_closed(case)
        if self.on_case is not None:
            self.on_case(case, decision, training)
