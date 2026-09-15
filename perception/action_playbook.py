"""
perception/action_playbook.py

Action and Playbook Layer — the final pipeline stage completing the
Perception → NCE → SSE → RSEM → Action/Playbook chain described in
arXiv:2604.20134.

This module implements three components from the reference paper:

1. **Adaptive Playbook Generator** — builds multi-step workflows pairing
   feasible attack paths with RSEM-ranked defensive actions, using
   primitives REVOKE_SESSION, RESTRICT_PRIVILEGES, ENABLE_MFA,
   QUARANTINE_ACCESS, MONITOR_ONLY.

2. **Policy and Safety Guardrails** — checks workflows against business-
   impact thresholds and compliance requirements, routing high-impact
   plans to analysts and approving lower-risk ones for autonomous
   execution.

3. **Execution Interface** — initiates actions in dry-run mode with audit
   logs and rollback paths for safety.

DESIGN DECISION — ENABLE_MFA as a policy-layer action:

The paper lists ENABLE_MFA as an action primitive, but our RSEM
implementation does not score it structurally (deliberately — MFA-
enablement doesn't reduce cleanly to an edge-removal/containment
computation the way the other 4 actions do, and rsem.py is a locked
file).  ENABLE_MFA is therefore added as a POLICY-LAYER action in this
module, not an RSEM-ranked one — appended as a standard hardening step
for credential-relevant techniques (T1078, T1550, T1484) alongside
whatever RSEM's top-ranked action is, mirroring how real SOC playbooks
bolt on MFA enforcement as a blanket policy action rather than a
graph-containment action.

DESIGN INVARIANT — no locked files modified:

This module follows the exact pattern established by
nce_sse_integration.py and nce_rsem_integration.py: import and
orchestrate the locked modules, never modify them.  All types defined
here are NEW and separate from the existing HypothesisStatus enum and
RSEM data structures.
"""

from __future__ import annotations

import json
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from perception.knowledge_graph import (
    KnowledgeStoreGraph,
    account_node_id,
    host_node_id,
)
from perception.knowledge_store import KnowledgeFact
from perception.nce_rsem_integration import RankedHypothesisResult
from perception.rsem import (
    ActionType,
    ProposedAction,
    ScoredAction,
    _apply_action,
)

if TYPE_CHECKING:
    import networkx as nx


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CREDENTIAL_RELEVANT_TECHNIQUES: frozenset[str] = frozenset({
    "T1078",  # Valid Accounts
    "T1550",  # Use Alternate Authentication Material
    "T1484",  # Domain Policy Modification
})
"""
Techniques for which an ENABLE_MFA policy step is automatically appended.
These are credential-relevant attack techniques where MFA enforcement is
a standard SOC hardening action regardless of graph-computed containment.
"""

GUARDRAIL_BUSINESS_IMPACT_THRESHOLD: float = 0.35
"""
Business-impact threshold for the policy guardrail.

Data-driven value based on observed RSEM business_impact scores across
140 alerts (nce7_scale_results.json + nce8_clean_fp_results.json):

  Observed range: {0.0, 0.25} — all on dynamically-created tier-0 hosts.
  Seeded graph range: 0.25 (tier 0) → 0.50 (tier 1) → 0.75 (tier 2) → 1.00 (tier 3).

0.35 sits between tier-0 (0.25, auto-approve) and tier-1+ (≥0.50, route
to review), ensuring workstation-class hosts get auto-approved while any
server or higher-criticality host requires analyst review.
"""

AUDIT_LOG_PATH: Path = Path(__file__).resolve().parent.parent / "agent" / "action_playbook_audit_log.jsonl"
"""
Append-only JSONL audit log for playbook execution events.
Same pattern as the existing NCE-7/8 API call logs in agent/.
"""


# ---------------------------------------------------------------------------
# PlaybookExecutionStatus
# ---------------------------------------------------------------------------

class PlaybookExecutionStatus(Enum):
    """
    Execution lifecycle status for a playbook or playbook step.

    Deliberately separate from HypothesisStatus in nce_contract.py — this
    enum represents what happened during action execution, not how far
    reasoning/validation progressed through the NCE → SSE → RSEM chain.
    """
    PENDING_GUARDRAIL_CHECK = "PENDING_GUARDRAIL_CHECK"
    AUTO_APPROVED = "AUTO_APPROVED"
    PENDING_ANALYST_REVIEW = "PENDING_ANALYST_REVIEW"
    REJECTED_BY_GUARDRAIL = "REJECTED_BY_GUARDRAIL"
    DRY_RUN_COMPLETE = "DRY_RUN_COMPLETE"
    DRY_RUN_FAILED = "DRY_RUN_FAILED"


# ---------------------------------------------------------------------------
# PlaybookStep
# ---------------------------------------------------------------------------

@dataclass
class PlaybookStep:
    """
    A single step in a multi-step playbook.

    Attributes:
        step_number:      1-indexed position in the playbook.
        action:           The ScoredAction from RSEM (imported, not redefined).
                          For policy actions (ENABLE_MFA), this is a synthetic
                          ScoredAction with all-zero scores — distinguished by
                          is_policy_action=True.
        is_policy_action: True for appended policy steps (ENABLE_MFA), False
                          for RSEM-ranked structural actions.  This flag is
                          the discriminator a future UI should use to branch
                          rendering (e.g., show score breakdown for RSEM steps,
                          show "Policy Action" badge for policy steps).
        status:           Execution status of this individual step.
    """
    step_number: int
    action: ScoredAction
    is_policy_action: bool
    status: PlaybookExecutionStatus


# ---------------------------------------------------------------------------
# Playbook
# ---------------------------------------------------------------------------

@dataclass
class Playbook:
    """
    A complete multi-step workflow for one hypothesis.

    Attributes:
        hypothesis:               The RankedHypothesisResult this playbook
                                  responds to.
        steps:                    Ordered list of PlaybookSteps (1-indexed).
        overall_status:           Aggregate execution status.
        guardrail_decision_reason: Human-readable explanation of why the
                                  playbook was auto-approved or routed to
                                  analyst review.
        dry_run_report:           Populated after execute_playbook_dry_run()
                                  with structured before/after state diffs.
    """
    hypothesis: RankedHypothesisResult
    steps: list[PlaybookStep]
    overall_status: PlaybookExecutionStatus
    guardrail_decision_reason: str = ""
    dry_run_report: str | None = None


# ---------------------------------------------------------------------------
# Adaptive Playbook Generator
# ---------------------------------------------------------------------------

def build_playbook(
    ranked_result: RankedHypothesisResult,
    graph_store: KnowledgeStoreGraph,
) -> Playbook:
    """
    Build a multi-step playbook from an RSEM-ranked hypothesis result.

    Takes RSEM's top-ranked ScoredAction as Step 1.  If the hypothesis's
    technique_id is credential-relevant (T1078, T1550, T1484), appends
    an ENABLE_MFA policy step as Step 2 targeting the same account/host
    as Step 1's action.

    Args:
        ranked_result: A RankedHypothesisResult from the RSEM integration
                       layer (must have at least one ranked_action).
        graph_store:   The KnowledgeStoreGraph (not mutated).

    Returns:
        A Playbook with overall_status = PENDING_GUARDRAIL_CHECK.

    Raises:
        ValueError: If ranked_result has no ranked_actions.
    """
    if not ranked_result.ranked_actions:
        raise ValueError(
            "Cannot build playbook: ranked_result has no ranked_actions. "
            "This should never happen for a FEASIBLE hypothesis that "
            "reached RSEM ranking."
        )

    # Step 1: RSEM's top-ranked action
    top_action = ranked_result.ranked_actions[0]
    step1 = PlaybookStep(
        step_number=1,
        action=top_action,
        is_policy_action=False,
        status=PlaybookExecutionStatus.PENDING_GUARDRAIL_CHECK,
    )

    steps: list[PlaybookStep] = [step1]

    # Step 2 (conditional): ENABLE_MFA for credential-relevant techniques
    technique_id = ranked_result.validated.hypothesis.technique_id
    if technique_id in CREDENTIAL_RELEVANT_TECHNIQUES:
        # Target the same account/host as Step 1
        mfa_proposed = ProposedAction(
            action_type=ActionType.ENABLE_MFA,
            target_account_id=top_action.action.target_account_id,
            target_host_id=top_action.action.target_host_id,
        )
        mfa_scored = ScoredAction(
            action=mfa_proposed,
            containment=0.0,
            business_impact=0.0,
            composite_score=0.0,
            paths_cut=0,
            paths_total_before=0,
        )
        step2 = PlaybookStep(
            step_number=2,
            action=mfa_scored,
            is_policy_action=True,
            status=PlaybookExecutionStatus.PENDING_GUARDRAIL_CHECK,
        )
        steps.append(step2)

    return Playbook(
        hypothesis=ranked_result,
        steps=steps,
        overall_status=PlaybookExecutionStatus.PENDING_GUARDRAIL_CHECK,
    )


# ---------------------------------------------------------------------------
# Policy and Safety Guardrails
# ---------------------------------------------------------------------------

def evaluate_guardrails(playbook: Playbook) -> Playbook:
    """
    Evaluate policy and safety guardrails for a playbook.

    Returns a NEW Playbook with updated statuses (immutable pattern —
    does not mutate the graph or the input playbook's steps in-place).

    Guardrail rules, in priority order:

    1. HARD FLOOR: If Step 1's action_type is QUARANTINE_ACCESS or
       REVOKE_SESSION, ALWAYS route to PENDING_ANALYST_REVIEW.  These
       are the most disruptive/hardest-to-reverse actions and warrant
       human review by design, independent of RSEM's computed impact.

    2. THRESHOLD: If Step 1's business_impact exceeds
       GUARDRAIL_BUSINESS_IMPACT_THRESHOLD (0.35), route to
       PENDING_ANALYST_REVIEW.

    3. Otherwise: AUTO_APPROVED.

    ENABLE_MFA policy steps (if present) are always auto-approved
    regardless of Step 1's routing — MFA enforcement is low-risk/
    non-disruptive by nature.

    Args:
        playbook: A Playbook with overall_status = PENDING_GUARDRAIL_CHECK.

    Returns:
        A new Playbook with updated overall_status, step statuses, and
        guardrail_decision_reason.
    """
    if not playbook.steps:
        return Playbook(
            hypothesis=playbook.hypothesis,
            steps=[],
            overall_status=PlaybookExecutionStatus.REJECTED_BY_GUARDRAIL,
            guardrail_decision_reason="Rejected: playbook has no steps.",
        )

    # Step 1 is always the RSEM-ranked action
    step1 = playbook.steps[0]
    action_type = step1.action.action.action_type
    business_impact = step1.action.business_impact

    # --- Determine routing for Step 1 ---
    hard_floor_types = {ActionType.QUARANTINE_ACCESS, ActionType.REVOKE_SESSION}

    if action_type in hard_floor_types:
        step1_status = PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
        overall_status = PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
        reason = (
            f"Routed to analyst review: action_type={action_type.value} "
            f"requires mandatory human approval (hard floor rule — most "
            f"disruptive/hardest-to-reverse action class)."
        )
    elif business_impact > GUARDRAIL_BUSINESS_IMPACT_THRESHOLD:
        step1_status = PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
        overall_status = PlaybookExecutionStatus.PENDING_ANALYST_REVIEW
        reason = (
            f"Routed to analyst review: business_impact={business_impact:.2f} "
            f"exceeds threshold {GUARDRAIL_BUSINESS_IMPACT_THRESHOLD:.2f}."
        )
    else:
        step1_status = PlaybookExecutionStatus.AUTO_APPROVED
        overall_status = PlaybookExecutionStatus.AUTO_APPROVED
        reason = (
            f"Auto-approved: action_type={action_type.value}, "
            f"business_impact={business_impact:.2f} below threshold "
            f"{GUARDRAIL_BUSINESS_IMPACT_THRESHOLD:.2f}."
        )

    # --- Build updated steps ---
    updated_steps: list[PlaybookStep] = []

    # Update Step 1
    updated_steps.append(PlaybookStep(
        step_number=step1.step_number,
        action=step1.action,
        is_policy_action=step1.is_policy_action,
        status=step1_status,
    ))

    # Update remaining steps (policy actions — always auto-approved)
    for step in playbook.steps[1:]:
        updated_steps.append(PlaybookStep(
            step_number=step.step_number,
            action=step.action,
            is_policy_action=step.is_policy_action,
            status=PlaybookExecutionStatus.AUTO_APPROVED,
        ))

    return Playbook(
        hypothesis=playbook.hypothesis,
        steps=updated_steps,
        overall_status=overall_status,
        guardrail_decision_reason=reason,
        dry_run_report=playbook.dry_run_report,
    )


# ---------------------------------------------------------------------------
# Execution Interface (dry-run only)
# ---------------------------------------------------------------------------

def execute_playbook_dry_run(
    playbook: Playbook,
    graph_store: KnowledgeStoreGraph,
) -> Playbook:
    """
    Execute a playbook in dry-run mode — simulate actions on a graph copy,
    produce a structured before/after report, and discard the copy.

    Only executes if overall_status == AUTO_APPROVED.  Playbooks pending
    analyst review are NOT executed — this function refuses and returns
    the playbook unchanged with a clear message in dry_run_report.

    For RSEM-ranked steps: reuses RSEM's existing _apply_action() on a
    deep copy of the graph to produce a real before/after state diff.
    The live graph_store is NEVER mutated (true dry-run, zero persistent
    state change).

    For ENABLE_MFA policy steps: produces an honest simulation report
    noting that MFA state is not currently modeled in the graph schema.

    Appends an audit log entry to agent/action_playbook_audit_log.jsonl
    (same append-only JSONL pattern as the existing NCE-7/8 API call logs).

    Args:
        playbook:    A Playbook (should be AUTO_APPROVED to execute).
        graph_store: The KnowledgeStoreGraph (NEVER mutated).

    Returns:
        A new Playbook with updated overall_status, dry_run_report, and
        step statuses.
    """
    # --- Refuse non-approved playbooks ---
    if playbook.overall_status != PlaybookExecutionStatus.AUTO_APPROVED:
        return Playbook(
            hypothesis=playbook.hypothesis,
            steps=playbook.steps,
            overall_status=playbook.overall_status,
            guardrail_decision_reason=playbook.guardrail_decision_reason,
            dry_run_report=(
                f"REFUSED: Cannot execute dry-run — playbook status is "
                f"{playbook.overall_status.value}, not AUTO_APPROVED. "
                f"Playbooks pending analyst review must be explicitly "
                f"approved before execution."
            ),
        )

    try:
        report_lines: list[str] = []
        report_lines.append("=" * 60)
        report_lines.append("DRY-RUN EXECUTION REPORT")
        report_lines.append("=" * 60)

        updated_steps: list[PlaybookStep] = []

        for step in playbook.steps:
            report_lines.append("")
            report_lines.append(f"--- Step {step.step_number} ---")
            report_lines.append(
                f"Action: {step.action.action.action_type.value}"
            )
            report_lines.append(
                f"Policy action: {step.is_policy_action}"
            )

            if step.is_policy_action:
                # ENABLE_MFA policy simulation
                target_desc = _describe_target(step.action.action)
                report_lines.append(
                    f"SIMULATED: MFA enforcement flag would be set for "
                    f"{target_desc} -- no MFA state currently modeled in "
                    f"knowledge graph schema; this step represents the "
                    f"intended policy action."
                )
                report_lines.append(
                    f"Rollback: Remove MFA enforcement flag for "
                    f"{target_desc}."
                )
                updated_steps.append(PlaybookStep(
                    step_number=step.step_number,
                    action=step.action,
                    is_policy_action=step.is_policy_action,
                    status=PlaybookExecutionStatus.DRY_RUN_COMPLETE,
                ))
            else:
                # RSEM-ranked action — real graph simulation
                step_report = _simulate_rsem_action(
                    step.action.action, graph_store
                )
                report_lines.extend(step_report)
                updated_steps.append(PlaybookStep(
                    step_number=step.step_number,
                    action=step.action,
                    is_policy_action=step.is_policy_action,
                    status=PlaybookExecutionStatus.DRY_RUN_COMPLETE,
                ))

        report_lines.append("")
        report_lines.append("=" * 60)
        report_lines.append("DRY-RUN COMPLETE -- no persistent state changes.")
        report_lines.append("=" * 60)

        dry_run_report = "\n".join(report_lines)
        overall_status = PlaybookExecutionStatus.DRY_RUN_COMPLETE

    except Exception:
        dry_run_report = (
            f"DRY-RUN FAILED -- an error occurred during simulation:\n"
            f"{traceback.format_exc()}"
        )
        overall_status = PlaybookExecutionStatus.DRY_RUN_FAILED
        updated_steps = playbook.steps

    result = Playbook(
        hypothesis=playbook.hypothesis,
        steps=updated_steps,
        overall_status=overall_status,
        guardrail_decision_reason=playbook.guardrail_decision_reason,
        dry_run_report=dry_run_report,
    )

    # --- Audit log ---
    _write_audit_log(result)

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _describe_target(action: ProposedAction) -> str:
    """Build a human-readable target description from a ProposedAction."""
    parts: list[str] = []
    if action.target_account_id:
        parts.append(f"account {action.target_account_id}")
    if action.target_host_id:
        parts.append(f"host {action.target_host_id}")
    return " on ".join(parts) if parts else "unknown target"


def _simulate_rsem_action(
    action: ProposedAction,
    graph_store: KnowledgeStoreGraph,
) -> list[str]:
    """
    Simulate a single RSEM-ranked action on a graph copy and produce
    a before/after state diff.

    Uses rsem._apply_action() on a deep copy — the live graph is NEVER
    mutated.  The copy is discarded after generating the report.

    Returns a list of report lines.
    """
    lines: list[str] = []
    action_type = action.action_type

    # Snapshot edges BEFORE
    before_edges = _snapshot_relevant_edges(graph_store.graph, action)

    # Deep copy the graph — NEVER modify the live graph
    modified_graph = graph_store.graph.copy()

    # Apply the action to the copy (reuse RSEM's existing logic)
    _apply_action(modified_graph, action)

    # Snapshot edges AFTER
    after_edges = _snapshot_relevant_edges(modified_graph, action)

    # Generate diff
    if action_type == ActionType.MONITOR_ONLY:
        lines.append("No graph changes (MONITOR_ONLY).")
        lines.append("Rollback: N/A — no action taken.")
    else:
        # Find removed edges
        removed = set(before_edges.keys()) - set(after_edges.keys())
        # Find modified edges (e.g., confidence changes for ENABLE_MFA)
        modified = set()
        for key in set(before_edges.keys()) & set(after_edges.keys()):
            if before_edges[key] != after_edges[key]:
                modified.add(key)

        if not removed and not modified:
            lines.append(
                "No edges affected by this action (target may not have "
                "matching edges in the graph)."
            )
            lines.append("Rollback: N/A — no changes to reverse.")
        else:
            if removed:
                lines.append(f"Edges removed ({len(removed)}):")
                for edge_key in sorted(removed):
                    lines.append(
                        f"  Before: {before_edges[edge_key]} [ACTIVE]"
                    )
                    lines.append(
                        f"  After:  {before_edges[edge_key]} [REMOVED]"
                    )
                lines.append(
                    f"Rollback: Restore the {len(removed)} removed edge(s) "
                    f"listed above."
                )
            if modified:
                lines.append(f"Edges modified ({len(modified)}):")
                for edge_key in sorted(modified):
                    lines.append(
                        f"  Before: {before_edges[edge_key]}"
                    )
                    lines.append(
                        f"  After:  {after_edges[edge_key]}"
                    )
                lines.append(
                    "Rollback: Restore original confidence values on the "
                    "modified edge(s)."
                )

    return lines


def _snapshot_relevant_edges(
    graph: "nx.MultiDiGraph",
    action: ProposedAction,
) -> dict[tuple[str, str, str], str]:
    """
    Snapshot edges relevant to the action's targets.

    Returns a dict mapping (u, v, key) -> human-readable description.
    """
    result: dict[tuple[str, str, str], str] = {}

    # Determine which nodes to filter on
    target_nodes: set[str] = set()
    if action.target_account_id:
        target_nodes.add(account_node_id(action.target_account_id))
    if action.target_host_id:
        target_nodes.add(host_node_id(action.target_host_id))

    # Edge types of interest for action simulation
    relevant_edge_types = {
        "GRANTS", "HAS_PRIOR_ACCESS", "MEMBER_OF",
    }

    for u, v, key, data in graph.edges(keys=True, data=True):
        edge_type = data.get("edge_type", "")
        if edge_type not in relevant_edge_types:
            continue

        # Filter to edges involving target nodes
        if not target_nodes or u in target_nodes or v in target_nodes:
            # Build description
            desc = _describe_edge(u, v, key, data)
            result[(u, v, key)] = desc

    return result


def _describe_edge(
    u: str, v: str, key: str, data: dict,
) -> str:
    """Build a human-readable description of a single edge."""
    edge_type = data.get("edge_type", "UNKNOWN")

    if edge_type == "GRANTS":
        al = data.get("access_level")
        if isinstance(al, KnowledgeFact):
            level_str = al.value.name if hasattr(al.value, "name") else str(al.value)
            conf_str = f" (confidence={al.confidence:.2f})"
        else:
            level_str = str(al) if al else "UNKNOWN"
            conf_str = ""
        return f"{u} GRANTS:{level_str} -> {v}{conf_str}"
    elif edge_type == "HAS_PRIOR_ACCESS":
        return f"{u} HAS_PRIOR_ACCESS -> {v}"
    elif edge_type == "MEMBER_OF":
        return f"{u} MEMBER_OF -> {v}"
    else:
        return f"{u} {edge_type} -> {v}"


def _write_audit_log(playbook: Playbook) -> None:
    """
    Append an audit log entry for a playbook execution.

    Same append-only JSONL pattern as the existing NCE-7/8 API call logs.
    Creates the file if it doesn't exist.
    """
    # Extract relevant data for the log entry
    hyp = playbook.hypothesis.validated.hypothesis
    action_types = [
        step.action.action.action_type.value for step in playbook.steps
    ]

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_id": hyp.incident_id,
        "technique_id": hyp.technique_id,
        "source_account": hyp.source_account,
        "target_host": hyp.target_host,
        "action_types": action_types,
        "guardrail_decision": playbook.guardrail_decision_reason,
        "overall_status": playbook.overall_status.value,
        "step_count": len(playbook.steps),
    }

    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        # Audit log write failure should never crash the pipeline.
        # In production this would go to a fallback logger.
        pass
