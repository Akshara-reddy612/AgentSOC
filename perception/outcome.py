"""
perception/outcome.py

Alert-level outcome of the defended pipeline (Phase 3 step 3.3, 2026-10-11).

    AUTO_APPROVED  - at least one playbook was auto-approved and none needs review
    LOW_PRIORITY   - feasible hypotheses exist but all are the accounts' normal
                     access (logged expected activity; Phase 4 step 4.0)
    REVIEW         - an analyst must look (any playbook pending review, or an
                     alert-level escalation rule fired)
    NO_ACTIONABLE  - no feasible hypothesis and no escalation rule fired

Escalation rules (independent of NCE):
  1. the alert's TRUSTED destination is on the threat-intel list;
  2. (2026-10-11, step 4.8) ERA flags injection-like content in the alert's
     text (level MEDIUM or HIGH, taking the max of field and incident levels).
     On corpus v2 ERA flagged 0/1000 clean alerts, so this costs no clean-side
     review load, and it also blocks auto-approval of an alert whose text looks
     manipulated.
Rule 1 detail: the alert's TRUSTED destination is on the
threat-intel list.  A proxy that blocks the connection makes T1071 structurally
INFEASIBLE, but an endpoint trying to reach a known-bad destination is itself
a compromise signal, so it must never end as NO_ACTIONABLE.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from perception.entity_binding import trusted_destination_of
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.network_model import KNOWN_BAD

AUTO_APPROVED = "AUTO_APPROVED"
REVIEW = "REVIEW"
NO_ACTIONABLE = "NO_ACTIONABLE"
LOW_PRIORITY = "LOW_PRIORITY"

_REVIEW_STATUSES = {"PENDING_ANALYST_REVIEW", "REJECTED_BY_GUARDRAIL", "DRY_RUN_FAILED"}
_APPROVED_STATUSES = {"AUTO_APPROVED", "DRY_RUN_COMPLETE"}


@dataclass
class AlertOutcome:
    label: str
    reasons: list[str] = field(default_factory=list)


def known_bad_contact(alert: dict, kg: KnowledgeStoreGraph) -> str | None:
    """Reason string if the alert's trusted destination is known-bad, else None."""
    dest = trusted_destination_of(alert)
    if not dest:
        return None
    rep, conf, source = kg.get_destination_reputation(dest)
    if rep == KNOWN_BAD:
        return f"Trusted telemetry shows contact with known-bad destination {dest!r} ({source}, confidence {conf:.2f})."
    return None


def decide(alert: dict, playbook_statuses: list[str], kg: KnowledgeStoreGraph,
           era_level: str | None = None) -> AlertOutcome:
    """Combine per-hypothesis playbook statuses with alert-level escalation rules."""
    escalations: list[str] = []
    kb = known_bad_contact(alert, kg)
    if kb:
        escalations.append(kb)
    if era_level in ("MEDIUM", "HIGH"):
        escalations.append(f"ERA flagged injection-like content in the alert text (level {era_level}).")
    if any(s in _REVIEW_STATUSES for s in playbook_statuses):
        return AlertOutcome(REVIEW, escalations + ["At least one playbook requires analyst review."])
    if escalations:   # escalation rules override auto-approval and low priority
        return AlertOutcome(REVIEW, escalations)
    if any(s in _APPROVED_STATUSES for s in playbook_statuses):
        return AlertOutcome(AUTO_APPROVED, ["Playbook auto-approved by guardrails."])
    if "LOGGED_EXPECTED_ACTIVITY" in playbook_statuses:
        return AlertOutcome(LOW_PRIORITY, ["Only expected (baseline) activity is feasible; logged."])
    return AlertOutcome(NO_ACTIONABLE, ["No structurally feasible hypothesis."])
