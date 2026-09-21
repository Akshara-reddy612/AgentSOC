"""
monitoring/models.py

Core data models for the real-time monitoring layer.

These models are purely data containers — no pipeline logic lives here.
All fields are plain Python types so the Streamlit dashboard can render them
without importing any heavy pipeline modules.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# EventStatus
# ---------------------------------------------------------------------------

class EventStatus(str, Enum):
    """Lifecycle status of a single monitored event."""

    QUEUED = "QUEUED"           # In the queue, not yet processed
    PROCESSING = "PROCESSING"   # Worker has picked it up
    DONE = "DONE"               # Pipeline completed successfully
    ERROR = "ERROR"             # Unhandled exception in the pipeline
    TIMEOUT = "TIMEOUT"         # Soft timeout exceeded; result discarded
    DROPPED = "DROPPED"         # Queue was full; event never entered pipeline
    NCE_UNAVAILABLE = "NCE_UNAVAILABLE"  # Cache miss and live LLM not enabled


# ---------------------------------------------------------------------------
# StageInfo
# ---------------------------------------------------------------------------

@dataclass
class StageInfo:
    """Per-stage execution trace for one event."""

    status: str = "PENDING"   # "OK", "FAILED", "SKIPPED", "UNAVAILABLE"
    latency_ms: float = 0.0
    detail: str = ""          # Short human-readable note (no raw free-text)


# ---------------------------------------------------------------------------
# EventRecord
# ---------------------------------------------------------------------------

@dataclass
class EventRecord:
    """
    Single event's full journey through the monitoring pipeline.

    Fields that could contain attacker-controlled content (raw alert fields)
    are stored only as summary metadata, never replayed to the LLM or used
    in security decisions.  The record is append-only after creation:
    status and stage traces are updated in-place by the worker, but no field
    may be set to a lower lifecycle state.
    """

    # Identity
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = ""          # Copied from raw alert's alert_id if present
    source_tag: str = ""              # "replay", "jsonl", "api"
    received_at: float = field(default_factory=time.time)

    # Status
    status: EventStatus = EventStatus.QUEUED
    error_text: str = ""

    # Metadata from the raw alert (structured fields only — safe to display)
    alert_id: str = ""
    source_user: str = ""
    source_host: str = ""
    target_host: str = ""
    event_type: str = ""
    severity: str = ""

    # Stage-level outcomes (populated by the worker as stages complete)
    era_risk_level: str = ""          # "LOW", "MEDIUM", "HIGH", or ""
    era_risk_score: float = 0.0
    nce_hypothesis_count: int = 0
    nce_techniques: list[str] = field(default_factory=list)
    sse_feasible_count: int = 0
    sse_infeasible_count: int = 0
    rsem_top_action: str = ""
    rsem_composite_score: float = 0.0
    final_decision: str = ""          # "AUTO_APPROVED", "PENDING_ANALYST_REVIEW",
                                      # "DRY_RUN_COMPLETE", "ALL_INFEASIBLE",
                                      # "NCE_UNAVAILABLE", "SKIPPED", ...
    guardrail_reason: str = ""

    # Per-stage timing and status trace
    stage_trace: dict[str, StageInfo] = field(default_factory=dict)

    # Processing timestamps
    processing_started_at: float = 0.0
    processing_finished_at: float = 0.0

    @property
    def total_latency_ms(self) -> float:
        """Wall-clock time from received to finished (ms), or 0 if still processing."""
        if self.processing_finished_at > 0 and self.processing_started_at > 0:
            return (self.processing_finished_at - self.processing_started_at) * 1000.0
        return 0.0

    def mark_stage(self, name: str, status: str, latency_ms: float, detail: str = "") -> None:
        """Record the outcome of a single pipeline stage."""
        self.stage_trace[name] = StageInfo(
            status=status,
            latency_ms=latency_ms,
            detail=detail,
        )
