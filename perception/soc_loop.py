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
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Callable

from perception.case_builder import Case, CaseBuilder
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_updater import GATE_DELAY, KnowledgeUpdater
from perception.network_alert import with_entities
from perception.outcome_monitor import OutcomeMonitor
from perception.triage_gate import Decision, TriageGate

LEARNING_MODES = ("static", "frozen", "gated", "ungated")


class SocLoop:
    """Runs one alert stream through the store-backed pipeline (see module docstring)."""

    def __init__(self, db: KnowledgeDB, *, mode: str, training_end: datetime,
                 cases: CaseBuilder | None = None, gate_delay: timedelta = GATE_DELAY,
                 on_case: Callable[[Case, Decision | None, bool], None] | None = None,
                 gate_options: dict | None = None) -> None:
        if mode not in LEARNING_MODES:
            raise ValueError(f"mode must be one of {LEARNING_MODES}")
        self.db = db
        self.mode = mode
        self.training_end = training_end
        self.cases = cases or CaseBuilder()
        self.monitor = OutcomeMonitor(db)
        self.gate = TriageGate(db, watch=self.monitor.reasons, **(gate_options or {}))
        self.updater = (None if mode == "static"
                        else KnowledgeUpdater(db, gate=mode != "ungated", gate_delay=gate_delay))
        self.on_case = on_case
        self.counts: Counter[str] = Counter()
        self._decisions: dict[str, Decision] = {}
        self._in_training = True

    def process(self, alert: dict, at: datetime) -> None:
        if self._in_training and at >= self.training_end:
            self._end_training()
        if self.updater is not None:
            self.updater.advance(at)
        self.monitor.advance(at)
        a = with_entities(alert, self.db)
        self.monitor.observe(a, at)
        closed, event, case = self.cases.add(a, at)
        for c in closed:
            self._closed(c)
        self.counts["alerts"] += 1
        if event == "opened":
            self.counts["cases_training" if self._in_training else "cases_test"] += 1
            if not self._in_training:
                d = self.gate.triage(case, a, at)
                self._decisions[case.case_id] = d
                if self.updater is not None:
                    self.updater.record_outcome(case, d.outcome, at)
                self.monitor.register(d, at)

    def finish(self, at: datetime) -> None:
        """End of the stream: close the open cases and end the watches."""
        if self._in_training:
            self._end_training()
        for c in self.cases.close_all(at):
            self._closed(c)
        self.monitor.finish(at)

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
