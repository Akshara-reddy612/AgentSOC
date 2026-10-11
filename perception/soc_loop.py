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

Analyst feedback (optional, open decision D1): `analyst(case, decision, at)`
gives a verdict on each REVIEW case `analyst_delay` after it was raised.
"benign" -> the updater learns the case (provenance "analyst"; not in frozen
or static mode).  "malicious" -> the analyst approves the proposed
containment (watched by the outcome monitor), marks an external destination
known-bad in the store, and puts the source host under watch.  None -> no
verdict.  In the DEDALE experiments the analyst is an oracle that reads ground
truth; it is a separate condition, never part of the system itself.
"""
from __future__ import annotations

import heapq
import itertools
from collections import Counter
from datetime import datetime, timedelta
from typing import Callable

from perception.case_builder import Case, CaseBuilder, alert_case_key
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
Analyst = Callable[[Case, Decision, datetime], "str | None"]


class SocLoop:
    """Runs one alert stream through the store-backed pipeline (see module docstring)."""

    def __init__(self, db: KnowledgeDB, *, mode: str, training_end: datetime,
                 cases: CaseBuilder | None = None, gate_delay: timedelta = GATE_DELAY,
                 on_case: Callable[[Case, Decision | None, bool], None] | None = None,
                 gate_options: dict | None = None, analyst: Analyst | None = None,
                 analyst_delay: timedelta = ANALYST_DELAY,
                 detectors: tuple[str, ...] = tuple(DETECTORS),
                 on_alert: Callable[[Case, dict], None] | None = None) -> None:
        if mode not in LEARNING_MODES:
            raise ValueError(f"mode must be one of {LEARNING_MODES}")
        self.analyst = analyst
        self.analyst_delay = analyst_delay
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
                if self.analyst is not None and d.outcome == REVIEW:
                    heapq.heappush(self._reviews, (at + self.analyst_delay, next(self._review_seq), case, d))

    def finish(self, at: datetime) -> None:
        """End of the stream: close the open cases and end the watches."""
        if self._in_training:
            self._end_training()
        for c in self.cases.close_all(at):
            self._closed(c)
        self.monitor.finish(at)

    def _analyst_due(self, now: datetime) -> None:
        while self._reviews and self._reviews[0][0] <= now:
            due, _, case, d = heapq.heappop(self._reviews)
            verdict = self.analyst(case, d, due)
            self.verdicts.append((case.case_id, due, verdict or "none"))
            if verdict == "benign" and self.updater is not None and self.mode != "frozen":
                self.updater.analyst_closed_benign(case, due, "oracle")
            elif verdict == "malicious":
                self._confirmed_malicious(case, d, due)

    def _confirmed_malicious(self, case: Case, d: Decision, at: datetime) -> None:
        a = case.first_alert
        writer = "analyst:oracle"
        if a.get("destination_ip"):
            node = ensure_endpoint(self.db, str(a["destination_ip"]), at, writer)
            self.db.set_fact(node, "reputation", KNOWN_BAD, confidence=1.0, source=SourceSystem.SYSTEM,
                             writer=writer, at=at)
        self.monitor.register(d, at, approved_by=writer)
        if a.get("source_host") and self.db.profile.is_internal_address(str(a["src_ip"])):
            self.monitor.flag_host(str(a["source_host"]), case.case_id, at)

    def _end_training(self) -> None:
        for c in self.cases.close_all(self.training_end, reason="end_of_training"):
            self._closed(c)
        self._in_training = False

    def _closed(self, case: Case) -> None:
        training = case.opened < self.training_end
        decision = self._decisions.pop(case.case_id, None)
        if self.updater is not None and (training or self.mode != "frozen"):
            self.updater.case_closed(case, decision.outcome if decision else "", training=training)
        if self.on_case is not None:
            self.on_case(case, decision, training)
