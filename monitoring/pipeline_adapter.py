"""
monitoring/pipeline_adapter.py

Thin adapter that calls the existing AgentSOC pipeline stages in sequence,
timing each stage and writing results into an EventRecord.

Design invariants
-----------------
- No stage logic is reimplemented here.  Every call is a direct call into
  an existing public function in the perception/ or risk_assessment/ packages.
- NCE defaults to cached outputs from agent/nce7_comparative_results.json and
  agent/nce8_clean_fp_results.json (read-only).  On a cache miss, the event is
  marked NCE_UNAVAILABLE; the LLM is never called unless use_live_nce=True is
  explicitly passed.
- TIMEOUT is checked between every stage.  If time_limit_s is exceeded, the
  adapter raises TimeoutError immediately and the caller sets TIMEOUT status.
  A TIMEOUT event never updates action/decision state.
- The Raw Event → LLM → Action invariant is enforced by the pipeline itself:
  ERA and SSE guardrails run first; SSE-rejected events never reach playbook
  execution.
- All playbook execution is dry-run only (enforced by execute_playbook_dry_run).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from monitoring.models import EventRecord, EventStatus
from perception.pipeline import PerceptionPipeline
from perception.nce_contract import NCEOutput, NCEHypothesis, HypothesisStatus, MissingContextFlag
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_sse_integration import validate_nce_output
from perception.nce_rsem_integration import rank_validated_hypotheses
from perception.rsem import ActionType, ProposedAction, StructuralSimulationEngine
from perception.action_playbook import (
    build_playbook,
    evaluate_guardrails,
    execute_playbook_dry_run,
)
from risk_assessment.orchestrator import assess
from risk_assessment.integration import attach_risk_metadata

# ---------------------------------------------------------------------------
# NCE cache loader
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_NCE7_PATH = _PROJECT_ROOT / "agent" / "nce7_comparative_results.json"
_NCE8_PATH = _PROJECT_ROOT / "agent" / "nce8_clean_fp_results.json"

# Cache: alert_id (str) → record dict from the results file.
# Populated lazily once on first call to _load_nce_cache().
_NCE_CACHE: dict[str, dict] | None = None


def _load_nce_cache() -> dict[str, dict]:
    """
    Load and merge both NCE result files into a single alert_id → record dict.

    READ-ONLY.  The files are never modified by this code.
    Raises RuntimeError if neither file can be read.
    """
    global _NCE_CACHE
    if _NCE_CACHE is not None:
        return _NCE_CACHE

    cache: dict[str, dict] = {}
    loaded_any = False

    for path in (_NCE7_PATH, _NCE8_PATH):
        if not path.exists():
            continue
        try:
            with path.open(encoding="utf-8") as fh:
                records = json.load(fh)
            for rec in records:
                aid = str(rec.get("alert_id", ""))
                if aid:
                    cache[aid] = rec
            loaded_any = True
        except Exception as exc:  # noqa: BLE001
            # Log but continue — partial cache is better than none.
            import logging
            logging.getLogger(__name__).warning(
                "Could not load NCE cache from %s: %s", path, exc
            )

    if not loaded_any:
        raise RuntimeError(
            f"NCE cache files not found or unreadable: {_NCE7_PATH}, {_NCE8_PATH}"
        )

    _NCE_CACHE = cache
    return _NCE_CACHE


def get_nce_cache() -> dict[str, dict]:
    """Public accessor for the NCE cache (used by demo_alerts and tests)."""
    return _load_nce_cache()


def _check_timeout(start: float, limit_s: float, stage: str) -> None:
    """Raise TimeoutError if wall-clock time since start exceeds limit_s."""
    elapsed = time.perf_counter() - start
    if elapsed > limit_s:
        raise TimeoutError(
            f"Event processing timed out after {elapsed:.1f}s "
            f"(limit={limit_s}s, last completed stage before timeout: {stage})"
        )


# ---------------------------------------------------------------------------
# Stage helpers that reconstruct NCEHypothesis objects from cache dicts
# ---------------------------------------------------------------------------

def _hypotheses_from_cache(record: dict, incident_id: str) -> list[Any]:
    """
    Reconstruct a list of NCEHypothesis objects from a cached result record.

    The NCEHypothesis dataclass validates technique_id and flags on construction,
    so any stale cache entries with invalid values will be caught here.
    """
    from perception.nce_contract import HypothesisStatus, MissingContextFlag, NCEHypothesis

    _FLAG_LOOKUP: dict[str, MissingContextFlag] = {f.value: f for f in MissingContextFlag}

    hypotheses = []
    for h in record.get("nce_hypotheses", []):
        # Convert missing_context_flags from strings to enum members
        raw_flags = h.get("missing_context_flags", [])
        flags = []
        for f in raw_flags:
            if isinstance(f, MissingContextFlag):
                flags.append(f)
            elif isinstance(f, str) and f in _FLAG_LOOKUP:
                flags.append(_FLAG_LOOKUP[f])
            # Unknown flag strings are silently dropped (defensive)

        try:
            hyp = NCEHypothesis(
                technique_id=h["technique_id"],
                source_account=h["source_account"],
                source_host=h["source_host"],
                target_host=h["target_host"],
                nce_confidence=float(h["nce_confidence"]),
                supporting_evidence_refs=list(h.get("supporting_evidence_refs", [])),
                missing_context_flags=flags,
                status=HypothesisStatus.GENERATED,
                incident_id=incident_id,
            )
            hypotheses.append(hyp)
        except (KeyError, ValueError):
            # Skip malformed hypothesis entries; logged by caller if list ends up empty
            continue

    return hypotheses


# ---------------------------------------------------------------------------
# Main adapter
# ---------------------------------------------------------------------------

class MonitoringPipelineAdapter:
    """
    Calls the existing AgentSOC pipeline stages in sequence for a single event.

    Usage (called by MonitoringWorker):
        adapter = MonitoringPipelineAdapter()
        adapter.run(alert_dict, record, time_limit_s=30.0, use_live_nce=False)

    After run() returns, record.status is one of:
        DONE, ERROR, TIMEOUT, NCE_UNAVAILABLE

    If TIMEOUT is raised internally, run() re-raises it; the caller sets status.
    """

    def warmup(self) -> None:
        """
        Pre-warm the ERA pipeline (SemanticDetector / SentenceTransformer).

        Runs a dummy alert through Perception + ERA once on worker initialization
        so PyTorch and SentenceTransformer weights are loaded into memory BEFORE real
        events are picked up from the queue.

        Does NOT create an EventRecord or touch MonitoringState.
        """
        try:
            from perception.pipeline import PerceptionPipeline
            from risk_assessment.orchestrator import assess

            dummy_alert = {
                "alert_id": "warmup-dummy-00",
                "source_system": "EDR",
                "event_type": "process_create",
                "timestamp": "2026-07-24T10:00:00+00:00",
                "process_name": "warmup.exe",
            }
            pipeline = PerceptionPipeline(emit_logs=False)
            perc_result = pipeline.run([dummy_alert])
            if perc_result.clusters:
                inc = perc_result.clusters[0].representative
                assess(inc.evidence)
        except Exception as exc:  # noqa: BLE001
            import logging
            logging.getLogger(__name__).warning("ERA pipeline warmup encounter error: %s", exc)

    def run(
        self,
        alert: dict,
        record: EventRecord,
        *,
        time_limit_s: float = 30.0,
        use_live_nce: bool = False,
    ) -> None:
        """
        Run the full pipeline for one alert, populating record in-place.

        Parameters
        ----------
        alert : dict
            Raw alert dict (same format as GUIDE dataset alerts).
        record : EventRecord
            The record to populate. Must already be in MonitoringState.
        time_limit_s : float
            Soft timeout in seconds. Checked between every stage.
        use_live_nce : bool
            If True, call generate_hypotheses() for real (uses API quota).
            If False (default), use cached NCE outputs. On cache miss → NCE_UNAVAILABLE.
        """
        t_start = time.perf_counter()
        alert_id = str(alert.get("alert_id", record.event_id))

        # ------------------------------------------------------------------
        # Stage 0: Populate structured metadata into the record
        # ------------------------------------------------------------------
        record.alert_id = alert_id
        record.source_user = str(alert.get("source_user", ""))
        record.source_host = str(alert.get("source_host", ""))
        record.target_host = str(alert.get("target_host", ""))
        record.event_type = str(alert.get("event_type", ""))
        record.severity = str(alert.get("severity", ""))
        record.processing_started_at = time.time()

        # ------------------------------------------------------------------
        # Stage 1: Perception Pipeline (Normalize → Validate → Contextualize
        #          → Noise Reduction) to get EnrichedIncident + Evidence
        # ------------------------------------------------------------------
        _check_timeout(t_start, time_limit_s, "START")
        t0 = time.perf_counter()
        try:
            from perception.pipeline import PerceptionPipeline
            pipeline = PerceptionPipeline(emit_logs=False)
            perc_result = pipeline.run([alert])

            if perc_result.validation_rejections:
                # Alert failed schema validation — skip all downstream stages
                _, vr = perc_result.validation_rejections[0]
                codes = [e.code for e in vr.errors]
                record.mark_stage(
                    "PERCEPTION", "FAILED",
                    (time.perf_counter() - t0) * 1000,
                    f"Schema rejected: {codes}",
                )
                record.final_decision = "SCHEMA_REJECTED"
                record.status = EventStatus.DONE
                record.processing_finished_at = time.time()
                return

            if not perc_result.clusters:
                record.mark_stage(
                    "PERCEPTION", "SKIPPED",
                    (time.perf_counter() - t0) * 1000,
                    "No clusters produced (normalization error or empty alert)",
                )
                record.final_decision = "SKIPPED"
                record.status = EventStatus.DONE
                record.processing_finished_at = time.time()
                return

            incident = perc_result.clusters[0].representative
            record.mark_stage(
                "PERCEPTION", "OK",
                (time.perf_counter() - t0) * 1000,
                f"clusters={len(perc_result.clusters)}",
            )
        except TimeoutError:
            raise
        except Exception as exc:
            record.mark_stage(
                "PERCEPTION", "FAILED",
                (time.perf_counter() - t0) * 1000,
                str(exc)[:200],
            )
            raise

        # ------------------------------------------------------------------
        # Stage 2: ERA — Evidence Risk Assessment
        # ------------------------------------------------------------------
        _check_timeout(t_start, time_limit_s, "PERCEPTION")
        t0 = time.perf_counter()
        try:
            from risk_assessment.orchestrator import assess
            from risk_assessment.integration import attach_risk_metadata

            bundle = assess(incident.evidence)
            attach_risk_metadata(bundle, incident)

            # Extract top-level risk from the incident-level result
            if bundle.incident_result:
                record.era_risk_level = bundle.incident_result.risk_level
                record.era_risk_score = round(bundle.incident_result.overall_score, 3)
            else:
                record.era_risk_level = "LOW"
                record.era_risk_score = 0.0

            record.mark_stage(
                "ERA", "OK",
                (time.perf_counter() - t0) * 1000,
                f"risk={record.era_risk_level} score={record.era_risk_score:.3f}",
            )
        except TimeoutError:
            raise
        except Exception as exc:
            record.mark_stage(
                "ERA", "FAILED",
                (time.perf_counter() - t0) * 1000,
                str(exc)[:200],
            )
            raise

        # ------------------------------------------------------------------
        # Stage 3: NCE — Narrative Counterfactual Engine
        # Cost-control invariant: ERA runs BEFORE NCE.  High-ERA events still
        # proceed to NCE (ERA is not a filter gate in this pipeline, only in the
        # defended agent).  The T1071 evidentiary filter inside generate_hypotheses
        # is the NCE-internal gate.
        # ------------------------------------------------------------------
        _check_timeout(t_start, time_limit_s, "ERA")
        t0 = time.perf_counter()
        hypotheses = []
        nce_ok = False

        if use_live_nce:
            try:
                from perception.nce_engine import alert_to_nce_input, generate_hypotheses
                nce_input = alert_to_nce_input(alert)
                nce_result = generate_hypotheses(nce_input)
                if nce_result.success and nce_result.output:
                    hypotheses = list(nce_result.output.hypotheses)
                    nce_ok = True
                    record.mark_stage(
                        "NCE", "OK",
                        (time.perf_counter() - t0) * 1000,
                        f"live={len(hypotheses)} hypotheses",
                    )
                else:
                    record.mark_stage(
                        "NCE", "FAILED",
                        (time.perf_counter() - t0) * 1000,
                        f"LLM error: {nce_result.error}",
                    )
            except TimeoutError:
                raise
            except Exception as exc:
                record.mark_stage(
                    "NCE", "FAILED",
                    (time.perf_counter() - t0) * 1000,
                    str(exc)[:200],
                )
                raise
        else:
            # Cache lookup
            try:
                cache = _load_nce_cache()
            except RuntimeError as exc:
                record.mark_stage(
                    "NCE", "UNAVAILABLE",
                    (time.perf_counter() - t0) * 1000,
                    f"Cache load error: {exc}",
                )
                record.final_decision = "NCE_UNAVAILABLE"
                record.status = EventStatus.NCE_UNAVAILABLE
                record.processing_finished_at = time.time()
                return

            cached_rec = cache.get(alert_id)
            if cached_rec is None:
                record.mark_stage(
                    "NCE", "UNAVAILABLE",
                    (time.perf_counter() - t0) * 1000,
                    f"Cache miss for alert_id={alert_id!r}; use_live_nce not enabled",
                )
                record.final_decision = "NCE_UNAVAILABLE"
                record.status = EventStatus.NCE_UNAVAILABLE
                record.processing_finished_at = time.time()
                return

            hypotheses = _hypotheses_from_cache(cached_rec, alert_id)
            if not hypotheses:
                record.mark_stage(
                    "NCE", "UNAVAILABLE",
                    (time.perf_counter() - t0) * 1000,
                    "Cache hit but nce_hypotheses empty or all malformed",
                )
                record.final_decision = "NCE_UNAVAILABLE"
                record.status = EventStatus.NCE_UNAVAILABLE
                record.processing_finished_at = time.time()
                return

            nce_ok = True
            record.mark_stage(
                "NCE", "OK",
                (time.perf_counter() - t0) * 1000,
                f"cached={len(hypotheses)} hypotheses",
            )

        record.nce_hypothesis_count = len(hypotheses)
        record.nce_techniques = [h.technique_id for h in hypotheses]

        # ------------------------------------------------------------------
        # Stage 4: SSE — Structural Simulation Engine
        # ------------------------------------------------------------------
        _check_timeout(t_start, time_limit_s, "NCE")
        t0 = time.perf_counter()
        try:
            from perception.knowledge_graph import KnowledgeStoreGraph
            from perception.nce_contract import NCEOutput
            from perception.nce_sse_integration import validate_nce_output
            from perception.rsem import StructuralSimulationEngine

            kg = KnowledgeStoreGraph()
            sse = StructuralSimulationEngine(kg)

            nce_output = NCEOutput(
                incident_id=alert_id,
                hypotheses=tuple(hypotheses),
            )
            validated_list = validate_nce_output(nce_output, sse)

            feasible = [v for v in validated_list if v.best_sse_verdict.value != "INFEASIBLE"]
            infeasible = [v for v in validated_list if v.best_sse_verdict.value == "INFEASIBLE"]
            record.sse_feasible_count = len(feasible)
            record.sse_infeasible_count = len(infeasible)

            record.mark_stage(
                "SSE", "OK",
                (time.perf_counter() - t0) * 1000,
                f"feasible={len(feasible)} infeasible={len(infeasible)}",
            )
        except TimeoutError:
            raise
        except Exception as exc:
            record.mark_stage(
                "SSE", "FAILED",
                (time.perf_counter() - t0) * 1000,
                str(exc)[:200],
            )
            raise

        # ------------------------------------------------------------------
        # Early exit if all hypotheses are SSE-rejected
        # ------------------------------------------------------------------
        if not feasible:
            record.final_decision = "ALL_INFEASIBLE"
            record.status = EventStatus.DONE
            record.processing_finished_at = time.time()
            return

        # ------------------------------------------------------------------
        # Stage 5: RSEM — Risk Scoring and Evaluation Module
        # ------------------------------------------------------------------
        _check_timeout(t_start, time_limit_s, "SSE")
        t0 = time.perf_counter()
        try:
            from perception.nce_rsem_integration import rank_validated_hypotheses
            from perception.rsem import ActionType, ProposedAction

            top_h = feasible[0].hypothesis
            candidate_actions = [
                ProposedAction(
                    action_type=ActionType.REVOKE_SESSION,
                    target_account_id=top_h.source_account,
                ),
                ProposedAction(
                    action_type=ActionType.RESTRICT_PRIVILEGES,
                    target_account_id=top_h.source_account,
                ),
                ProposedAction(
                    action_type=ActionType.QUARANTINE_ACCESS,
                    target_host_id=top_h.target_host,
                ),
                ProposedAction(
                    action_type=ActionType.MONITOR_ONLY,
                    target_account_id=top_h.source_account,
                ),
            ]

            pipeline_result = rank_validated_hypotheses(
                validated_list, kg, sse, candidate_actions,
            )

            # Get the top-ranked action from the first ranked hypothesis
            top_action = ""
            top_score = 0.0
            if pipeline_result.ranked:
                ranked_actions = pipeline_result.ranked[0].ranked_actions
                if ranked_actions:
                    top_action = ranked_actions[0].action.action_type.value
                    top_score = round(ranked_actions[0].composite_score, 3)

            record.rsem_top_action = top_action
            record.rsem_composite_score = top_score
            record.mark_stage(
                "RSEM", "OK",
                (time.perf_counter() - t0) * 1000,
                f"top_action={top_action} score={top_score:.3f}",
            )
        except TimeoutError:
            raise
        except Exception as exc:
            record.mark_stage(
                "RSEM", "FAILED",
                (time.perf_counter() - t0) * 1000,
                str(exc)[:200],
            )
            raise

        # ------------------------------------------------------------------
        # Stage 6: Action Playbook + Guardrails + Dry-Run
        # ------------------------------------------------------------------
        _check_timeout(t_start, time_limit_s, "RSEM")
        t0 = time.perf_counter()
        try:
            from perception.action_playbook import (
                build_playbook,
                evaluate_guardrails,
                execute_playbook_dry_run,
            )

            if not pipeline_result.ranked:
                record.final_decision = "ALL_INFEASIBLE"
                record.status = EventStatus.DONE
                record.processing_finished_at = time.time()
                return

            top_ranked = pipeline_result.ranked[0]
            playbook = build_playbook(top_ranked, kg)
            playbook = evaluate_guardrails(playbook)

            guardrail_status = playbook.overall_status.value
            record.guardrail_reason = playbook.guardrail_decision_reason or ""

            if guardrail_status == "AUTO_APPROVED":
                playbook = execute_playbook_dry_run(playbook, kg)
                final = playbook.overall_status.value  # DRY_RUN_COMPLETE or DRY_RUN_FAILED
            else:
                final = guardrail_status  # PENDING_ANALYST_REVIEW

            record.final_decision = final
            record.mark_stage(
                "PLAYBOOK", "OK",
                (time.perf_counter() - t0) * 1000,
                f"decision={final}",
            )
        except TimeoutError:
            raise
        except Exception as exc:
            record.mark_stage(
                "PLAYBOOK", "FAILED",
                (time.perf_counter() - t0) * 1000,
                str(exc)[:200],
            )
            raise

        # ------------------------------------------------------------------
        # Done
        # ------------------------------------------------------------------
        record.status = EventStatus.DONE
        record.processing_finished_at = time.time()
