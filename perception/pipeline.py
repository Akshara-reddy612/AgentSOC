"""
perception/pipeline.py

Orchestrates the full Phase 1 Perception Layer pipeline:

  Raw alert dict
      |
  Alert Normalization        (normalizer.py)
      |
  Schema Validation          (schema_validation.py)
      |
  Situational Contextualization  (contextualizer.py)
      |
  Noise Reduction            (noise_reducer.py)
      |
  Enriched Incidents / Clusters

Each stage is wrapped in a StageLogger from pipeline_logging.py, so every
run produces per-stage timing and redacted I/O summaries.

The pipeline is fail-fast per alert:
  - Normalization errors -> PipelineResult.normalization_error (alert skipped)
  - Validation failures  -> PipelineResult.validation_rejections (alert excluded from enrichment)
  - Contextualization / noise-reduction errors -> PipelineResult.errors

Valid, enriched alerts flow through to noise reduction and appear in
PipelineResult.clusters.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from perception.contextualizer import Contextualizer
from perception.knowledge_store import InMemoryKnowledgeStore
from perception.models import EnrichedIncident
from perception.noise_reducer import IncidentCluster, NoiseReducer
from perception.normalizer import AlertNormalizer
from perception.pipeline_logging import (
    PipelineLogEntry,
    StageLogger,
    make_alert_summary,
    make_cluster_list_summary,
    make_incident_summary,
    make_raw_alert_summary,
    make_validation_summary,
)
from perception.schema_validation import AlertSchemaValidator, ValidationResult


# ---------------------------------------------------------------------------
# Pipeline result
# ---------------------------------------------------------------------------

@dataclass
class PipelineResult:
    """
    The output of running the full pipeline over a batch of raw alerts.

    Attributes:
        clusters            — deduplicated/clustered EnrichedIncidents
        validation_rejections — list of (alert_id, ValidationResult) for rejected alerts
        normalization_errors  — list of (raw_alert, error_message) for parse failures
        errors              — unexpected errors in contextualization or noise-reduction
        log                 — per-stage structured log entries (all runs)
    """
    clusters: list[IncidentCluster] = field(default_factory=list)
    validation_rejections: list[tuple[str, ValidationResult]] = field(default_factory=list)
    normalization_errors: list[tuple[dict[str, Any], str]] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    log: list[PipelineLogEntry] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------

class PerceptionPipeline:
    """
    The Phase 1 Perception Layer pipeline.

    Wires together:
      AlertNormalizer -> AlertSchemaValidator -> Contextualizer -> NoiseReducer

    All instances are injected via the constructor for testability.  If not
    provided, in-memory defaults are used.
    """

    def __init__(
        self,
        normalizer: AlertNormalizer | None = None,
        validator: AlertSchemaValidator | None = None,
        contextualizer: Contextualizer | None = None,
        reducer: NoiseReducer | None = None,
        store: InMemoryKnowledgeStore | None = None,
        emit_logs: bool = True,
    ) -> None:
        _store = store or InMemoryKnowledgeStore()
        self._normalizer = normalizer or AlertNormalizer()
        self._validator = validator or AlertSchemaValidator()
        self._contextualizer = contextualizer or Contextualizer(store=_store)
        self._reducer = reducer or NoiseReducer()
        self._emit_logs = emit_logs

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, raw_alerts: list[dict[str, Any]]) -> PipelineResult:
        """
        Run the full pipeline over a batch of raw alert dicts.

        Args:
            raw_alerts: List of raw alert dicts as loaded from JSON or a collector.

        Returns:
            PipelineResult with clusters, rejections, errors, and log entries.
        """
        result = PipelineResult()
        enriched_incidents: list[EnrichedIncident] = []

        for raw in raw_alerts:
            alert_id = str(raw.get("alert_id", "<unknown>"))

            # ── Stage 1: Normalization ──────────────────────────────────
            raw_summary = make_raw_alert_summary(raw)
            with StageLogger(
                "Normalization",
                input_summary=raw_summary,
                log_store=result.log,
                emit=self._emit_logs,
            ) as norm_logger:
                try:
                    alert = self._normalizer.normalize(raw)
                    norm_logger.set_output(make_alert_summary(alert))
                except (ValueError, KeyError) as exc:
                    error_msg = f"{type(exc).__name__}: {exc}"
                    result.normalization_errors.append((raw, error_msg))
                    norm_logger.set_output({"error": error_msg})
                    raise  # Let StageLogger record the error, then skip

            # ── Stage 2: Schema Validation ──────────────────────────────
            with StageLogger(
                "SchemaValidation",
                input_summary=make_alert_summary(alert),
                log_store=result.log,
                emit=self._emit_logs,
            ) as val_logger:
                validation = self._validator.validate(alert)
                val_logger.set_output(make_validation_summary(validation))

            if not validation.is_valid:
                result.validation_rejections.append((alert_id, validation))
                continue  # Skip this alert — do not proceed to contextualization

            # ── Stage 3: Contextualization ──────────────────────────────
            try:
                with StageLogger(
                    "Contextualization",
                    input_summary=make_alert_summary(alert),
                    log_store=result.log,
                    emit=self._emit_logs,
                ) as ctx_logger:
                    incident = self._contextualizer.contextualize(alert)
                    ctx_logger.set_output(make_incident_summary(incident))
                enriched_incidents.append(incident)
            except Exception as exc:  # noqa: BLE001
                result.errors.append((alert_id, f"{type(exc).__name__}: {exc}"))
                continue

        # ── Stage 4: Noise Reduction ────────────────────────────────────
        if enriched_incidents:
            with StageLogger(
                "NoiseReduction",
                input_summary={"incident_count": len(enriched_incidents)},
                log_store=result.log,
                emit=self._emit_logs,
            ) as nr_logger:
                result.clusters = self._reducer.reduce(enriched_incidents)
                nr_logger.set_output(make_cluster_list_summary(result.clusters))

        return result

    def run_from_file(self, path: str | Path) -> PipelineResult:
        """
        Load raw alerts from a JSON file and run the pipeline.

        The JSON file must contain a list of alert dicts at the top level.
        """
        file_path = Path(path)
        with file_path.open(encoding="utf-8") as fh:
            raw_alerts: list[dict[str, Any]] = json.load(fh)
        if not isinstance(raw_alerts, list):
            raise ValueError(
                f"Expected a JSON array in {file_path}, got {type(raw_alerts).__name__}"
            )
        return self.run(raw_alerts)
