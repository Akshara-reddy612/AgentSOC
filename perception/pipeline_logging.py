"""
perception/pipeline_logging.py

Structured pipeline logger used by every stage.

Per-log-entry fields:
  - stage_name
  - start_time (UTC datetime)
  - end_time (UTC datetime)
  - duration_ms (float)
  - input_summary (trust-level counts only — NEVER raw free-text values)
  - output_summary (trust-level counts only — NEVER raw free-text values)
  - success (bool)
  - error_message (str | None, only when success=False)

Log Redaction Rule (enforced structurally, not by pattern matching):
  Input/output summaries are constructed from field COUNT metadata only —
  e.g. "3 structured fields, 2 free-text fields" — and never include the
  actual TrustedField.value of any FREE_TEXT field.  Logging raw evidence
  would defeat the trust-separation purpose of this pipeline.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from perception.models import (
    Alert,
    DerivedContext,
    EnrichedIncident,
    Evidence,
    ImmutableContext,
    TrustLevel,
)

# ---------------------------------------------------------------------------
# Standard Python logger (outputs JSON lines to stderr by default)
# ---------------------------------------------------------------------------

_log = logging.getLogger("perception.pipeline")
if not _log.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _log.addHandler(_handler)
    _log.setLevel(logging.DEBUG)


# ---------------------------------------------------------------------------
# Log entry model
# ---------------------------------------------------------------------------

@dataclass
class PipelineLogEntry:
    """
    A single structured log entry for one pipeline stage execution.

    All fields are plain Python types so the entry can be serialised to JSON
    for downstream latency analysis (Phase 5).
    """
    stage_name: str
    start_time: str          # ISO-8601 UTC
    end_time: str            # ISO-8601 UTC
    duration_ms: float
    input_summary: dict[str, Any]
    output_summary: dict[str, Any]
    success: bool
    error_message: str | None = None


# ---------------------------------------------------------------------------
# Summary builders — these are the redaction boundary
# ---------------------------------------------------------------------------

def _count_trusted_fields(obj: Any) -> dict[str, int]:
    """
    Count fields by trust level on a TrustedField-bearing object.

    Returns e.g. {"STRUCTURED": 3, "FREE_TEXT": 2, "DERIVED": 4}
    Never inspects or logs field values.
    """
    from perception.models import TrustedField  # local to avoid circular at module level

    counts: dict[str, int] = {}
    if obj is None:
        return counts

    # Dataclass-aware traversal
    fields_to_check: list[Any] = []

    if hasattr(obj, "__dataclass_fields__"):
        for attr in obj.__dataclass_fields__:
            val = getattr(obj, attr, None)
            if isinstance(val, TrustedField):
                fields_to_check.append(val)
            elif isinstance(val, dict):
                for v in val.values():
                    if isinstance(v, TrustedField):
                        fields_to_check.append(v)

    for tf in fields_to_check:
        level_name = tf.trust_level.value
        counts[level_name] = counts.get(level_name, 0) + 1

    return counts


def _summarise_alert(alert: Alert | None) -> dict[str, Any]:
    """
    Build a redacted summary of an Alert — counts only, no free-text values.
    """
    if alert is None:
        return {"type": "Alert", "present": False}

    counts = _count_trusted_fields(alert)
    return {
        "type": "Alert",
        "alert_id": alert.alert_id,
        "source_system": alert.source_system.value,
        "field_trust_counts": counts,
    }


def _summarise_enriched_incident(incident: EnrichedIncident | None) -> dict[str, Any]:
    """
    Build a redacted summary of an EnrichedIncident — counts only.
    """
    if incident is None:
        return {"type": "EnrichedIncident", "present": False}

    ic_counts = _count_trusted_fields(incident.immutable_context)
    dc_counts = _count_trusted_fields(incident.derived_context)
    ev_counts = _count_trusted_fields(incident.evidence)

    return {
        "type": "EnrichedIncident",
        "alert_id": incident.alert_id,
        "immutable_context_field_counts": ic_counts,
        "derived_context_field_counts": dc_counts,
        "evidence_field_counts": ev_counts,
        # Derived flags as bools — these are DERIVED trust, safe to log
        "derived_flags": {
            "no_prior_access": incident.derived_context.no_prior_access.value,
            "cross_zone_access": incident.derived_context.cross_zone_access.value,
            "high_criticality_target": incident.derived_context.high_criticality_target.value,
            "privilege_escalation_risk": incident.derived_context.privilege_escalation_risk.value,
        },
    }


def _summarise_generic(obj: Any, label: str) -> dict[str, Any]:
    """
    Generic redacted summary for objects that don't have a dedicated summariser.
    Counts TrustedField attributes by trust level, logs nothing else.
    """
    if obj is None:
        return {"type": label, "present": False}
    counts = _count_trusted_fields(obj)
    summary: dict[str, Any] = {"type": label, "field_trust_counts": counts}
    if hasattr(obj, "__len__"):
        summary["count"] = len(obj)  # type: ignore[arg-type]
    return summary


def _summarise_list(items: list[Any], label: str) -> dict[str, Any]:
    """Summary for a list of objects."""
    return {"type": label, "count": len(items)}


def _summarise_validation_result(result: Any) -> dict[str, Any]:
    """Summarise a ValidationResult without leaking free-text content."""
    if result is None:
        return {"type": "ValidationResult", "present": False}
    return {
        "type": "ValidationResult",
        "alert_id": getattr(result, "alert_id", None),
        "is_valid": getattr(result, "is_valid", None),
        "error_count": len(getattr(result, "errors", [])),
        "error_codes": [e.code for e in getattr(result, "errors", [])],
    }


# ---------------------------------------------------------------------------
# Stage logger context manager
# ---------------------------------------------------------------------------

class StageLogger:
    """
    Context-manager style logger for a single pipeline stage.

    Usage::

        with StageLogger("Normalization", input_summary) as logger:
            result = do_work()
            logger.set_output(result)

    On __exit__, logs the entry and appends it to `log_store` if provided.
    """

    def __init__(
        self,
        stage_name: str,
        input_summary: dict[str, Any],
        log_store: list[PipelineLogEntry] | None = None,
        emit: bool = True,
    ) -> None:
        self.stage_name = stage_name
        self.input_summary = input_summary
        self._log_store = log_store
        self._emit = emit
        self._output_summary: dict[str, Any] = {}
        self._start: datetime | None = None
        self._entry: PipelineLogEntry | None = None

    def set_output(self, summary: dict[str, Any]) -> None:
        self._output_summary = summary

    def __enter__(self) -> "StageLogger":
        self._start = datetime.now(tz=timezone.utc)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        end = datetime.now(tz=timezone.utc)
        start = self._start or end
        duration_ms = (end - start).total_seconds() * 1000.0
        success = exc_type is None
        error_msg: str | None = None
        if not success and exc_val is not None:
            error_msg = f"{type(exc_val).__name__}: {exc_val}"

        entry = PipelineLogEntry(
            stage_name=self.stage_name,
            start_time=start.isoformat(),
            end_time=end.isoformat(),
            duration_ms=round(duration_ms, 3),
            input_summary=self.input_summary,
            output_summary=self._output_summary,
            success=success,
            error_message=error_msg,
        )
        self._entry = entry

        if self._log_store is not None:
            self._log_store.append(entry)

        if self._emit:
            _log.info(json.dumps(_entry_to_dict(entry)))

        # Do not suppress exceptions
        return False

    @property
    def entry(self) -> PipelineLogEntry | None:
        return self._entry


def _entry_to_dict(entry: PipelineLogEntry) -> dict[str, Any]:
    return {
        "stage": entry.stage_name,
        "start": entry.start_time,
        "end": entry.end_time,
        "duration_ms": entry.duration_ms,
        "input": entry.input_summary,
        "output": entry.output_summary,
        "success": entry.success,
        "error": entry.error_message,
    }


# ---------------------------------------------------------------------------
# Public helpers for building stage-specific summaries
# ---------------------------------------------------------------------------

def make_alert_summary(alert: Alert) -> dict[str, Any]:
    return _summarise_alert(alert)


def make_incident_summary(incident: EnrichedIncident) -> dict[str, Any]:
    return _summarise_enriched_incident(incident)


def make_validation_summary(result: Any) -> dict[str, Any]:
    return _summarise_validation_result(result)


def make_cluster_list_summary(clusters: list[Any]) -> dict[str, Any]:
    return _summarise_list(clusters, "IncidentCluster")


def make_raw_alert_summary(raw: dict[str, Any]) -> dict[str, Any]:
    """Summarise a raw (pre-normalisation) alert dict by key count only."""
    return {
        "type": "RawAlert",
        "alert_id": raw.get("alert_id", "<unknown>"),
        "field_count": len(raw),
        # We list only the field NAMES (not values) of free-text fields
        "field_names": sorted(raw.keys()),
    }
