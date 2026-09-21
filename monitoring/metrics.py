"""
monitoring/metrics.py

Aggregate metrics snapshot for the Live Monitoring Dashboard.

MonitoringMetrics is a plain frozen dataclass — a point-in-time snapshot that
can be passed to Streamlit without locking.  The mutable counters live in
MonitoringState (monitoring/state.py) and are copied into a snapshot here.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class MonitoringMetrics:
    """
    Immutable point-in-time snapshot of aggregate monitoring statistics.

    Created by MonitoringState.get_metrics() and consumed by the dashboard.
    All counts represent events since the monitoring session started (or last
    clear).  Per-stage latencies are simple exponential moving averages
    (alpha=0.2) updated by the worker.
    """

    # Throughput
    total_received: int = 0
    total_processed: int = 0
    total_errors: int = 0
    total_timeouts: int = 0
    total_dropped: int = 0
    total_nce_unavailable: int = 0

    # Pipeline outcomes
    all_infeasible: int = 0       # Events where all NCE hypotheses were SSE-rejected
    analyst_review: int = 0       # Events where guardrail → PENDING_ANALYST_REVIEW
    auto_approved: int = 0        # Events where guardrail → AUTO_APPROVED
    dry_run_complete: int = 0     # Events where dry-run executed

    # ERA risk distribution
    era_low: int = 0
    era_medium: int = 0
    era_high: int = 0

    # NCE / SSE aggregate
    hypotheses_generated: int = 0
    hypotheses_feasible: int = 0
    hypotheses_infeasible: int = 0

    # Per-stage average latencies (ms) — 0.0 means no data yet
    avg_era_ms: float = 0.0
    avg_nce_ms: float = 0.0
    avg_sse_ms: float = 0.0
    avg_rsem_ms: float = 0.0
    avg_total_ms: float = 0.0

    # Queue state at snapshot time
    queue_depth: int = 0

    # Throughput: events per minute (EMA, updated every 60s)
    events_per_min: float = 0.0

    # Snapshot timestamp
    snapshot_at: float = field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        """Fraction of received events that completed without error/timeout/drop."""
        if self.total_received == 0:
            return 0.0
        ok = self.total_processed
        return ok / self.total_received

    @property
    def defense_rate(self) -> float:
        """Fraction of processed events where SSE blocked all hypotheses."""
        processed = self.total_processed
        if processed == 0:
            return 0.0
        return self.all_infeasible / processed
