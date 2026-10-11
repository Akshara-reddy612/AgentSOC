"""
perception/triage_gate.py

Triage gate: what a newly opened case costs (design step S6, 2026-10-11; see
experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md).  In this order:

  1. Escalation rules on trusted fields -- contact with a known-bad destination
     (perception/outcome.known_bad_contact) and, from the outcome monitor
     (design step S7), entities under watch.  They are checked first, so a
     learned pattern can never hide them; an escalated case always goes
     through the pipeline and ends in REVIEW.
  2. Learned pattern: the store holds an ALERT_PATTERN edge for this
     signature between these endpoints (learned behind the gate, step S5)
     -> LOW_PRIORITY.  No pipeline run, no LLM call.
  3. Decision cache: the same case key decided before, and nothing the store
     knows about its two endpoints changed since -> the same decision.
     A decision made while the NCE budget was exhausted is not reused once
     the budget allows a call again.
  4. Otherwise the defended pipeline (perception/defended_pipeline.run_downstream)
     runs.  NCE is called only if a function is given and the daily budget
     allows; cases that wanted a call and got none are counted as backlog.

Open decision D7 (policy for unreasoned cases): when NCE did not run and the
pipeline found nothing actionable for a case the store has never learned,
`unreasoned="review"` (default) sends it to an analyst instead of letting it
end NO_ACTIONABLE unseen.  The decision keeps the pipeline's own outcome, so
both policies can be scored.
Network alerts (src_ip / dst_ip / signature_id) and, since Phase 2, host
alerts (detector + structured key); the learned pattern is looked up with
knowledge_updater.pattern_edge.
ERA is not applied to IDS alerts: their text is the rule's message, not
attacker-controlled content.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Callable

from perception.case_builder import Case
from perception.defended_pipeline import run_downstream
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_updater import pattern_edge
from perception.nce_contract import NCEHypothesis
from perception.outcome import LOW_PRIORITY, NO_ACTIONABLE, REVIEW, known_bad_contact

UNREASONED_POLICIES = ("review", "no_actionable")


@dataclass
class Decision:
    case_id: str
    at: datetime
    path: str                       # "baseline" | "cache" | "pipeline"
    outcome: str                    # final outcome (AUTO_APPROVED / REVIEW / LOW_PRIORITY / NO_ACTIONABLE)
    pipeline_outcome: str | None    # run_downstream's own outcome; None if the pipeline did not run
    reasons: list[str]
    nce: str                        # "disabled" | "ran" | "budget_exhausted" | "error" | "not_needed"
    hypotheses: list[dict] = field(default_factory=list)
    store_seq: int = 0              # store version the decision was made on
    escalations: list[str] = field(default_factory=list)   # trusted-field escalation reasons (also in reasons)


class DailyBudget:
    """At most `per_day` NCE calls per calendar day (UTC) of event time."""

    def __init__(self, per_day: int) -> None:
        self.per_day = per_day
        self._day: date | None = None
        self.used = 0

    def available(self, at: datetime) -> bool:
        return at.date() != self._day or self.used < self.per_day

    def take(self, at: datetime) -> bool:
        if at.date() != self._day:
            self._day, self.used = at.date(), 0
        if self.used >= self.per_day:
            return False
        self.used += 1
        return True


class TriageGate:
    """Decides each newly opened case (see module docstring)."""

    def __init__(self, db: KnowledgeDB, *, nce: Callable[[dict], list[NCEHypothesis]] | None = None,
                 budget: DailyBudget | None = None, unreasoned: str = "review",
                 watch: Callable[[dict, datetime], list[str]] | None = None) -> None:
        if unreasoned not in UNREASONED_POLICIES:
            raise ValueError(f"unreasoned must be one of {UNREASONED_POLICIES}")
        self.db = db
        self.nce = nce
        self.budget = budget
        self.unreasoned = unreasoned
        self.watch = watch
        self._cache: dict[tuple, tuple[Decision, tuple[int, int]]] = {}
        self.backlog = 0

    def triage(self, case: Case, alert: dict, at: datetime) -> Decision:
        """`alert` is the case's first alert with entity fields set (perception/network_alert.with_entities)."""
        kg = self.db.graph
        escalations = [r for r in (known_bad_contact(alert, kg),) if r]
        if self.watch is not None:
            escalations += self.watch(alert, at)
        src, dst, pattern_key = pattern_edge(self.db, alert)
        versions = (self.db.node_version(src), self.db.node_version(dst))

        if not escalations:
            if kg.graph.has_edge(src, dst, pattern_key):
                return Decision(case.case_id, at, "baseline", LOW_PRIORITY, None,
                                ["Alert pattern learned as routine for these endpoints."], "not_needed",
                                store_seq=self.db.last_seq())
            cached = self._cache.get(case.key)
            if cached is not None and cached[1] == versions and self._reusable(cached[0], at):
                d = cached[0]
                return Decision(case.case_id, at, "cache", d.outcome, d.pipeline_outcome,
                                [*d.reasons, f"Same decision as {d.case_id} (store unchanged for these endpoints)."],
                                d.nce, d.hypotheses, self.db.last_seq())

        hypotheses, nce_status = self._reason(alert, at)
        res = run_downstream(hypotheses, alert, kg)
        outcome, reasons = res["outcome"], list(res["outcome_reasons"])
        if escalations and outcome != REVIEW:
            outcome, reasons = REVIEW, [*escalations, *reasons]
        elif escalations:
            reasons = [*escalations, *reasons]
        if (outcome == NO_ACTIONABLE and nce_status in ("disabled", "budget_exhausted", "error")
                and self.unreasoned == "review"):
            outcome = REVIEW
            reasons = [*reasons, f"Pattern not learned as routine and not reasoned about (NCE {nce_status})."]
        decision = Decision(case.case_id, at, "pipeline", outcome, res["outcome"], reasons, nce_status,
                            res["hypotheses"], self.db.last_seq(), list(escalations))
        if not escalations:
            self._cache[case.key] = (decision, versions)
        return decision

    def _reason(self, alert: dict, at: datetime) -> tuple[list[NCEHypothesis], str]:
        if self.nce is None:
            return [], "disabled"
        if self.budget is not None and not self.budget.take(at):
            self.backlog += 1
            return [], "budget_exhausted"
        try:
            return self.nce(alert), "ran"
        except Exception:   # noqa: BLE001 -- an NCE failure must not stop triage; the case is unreasoned
            return [], "error"

    def _reusable(self, d: Decision, at: datetime) -> bool:
        if d.nce == "budget_exhausted":
            return self.budget is not None and not self.budget.available(at)
        return d.nce != "error"
