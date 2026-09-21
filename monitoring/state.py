"""
monitoring/state.py

Process-wide singleton that holds all live monitoring state.

Design:
  - MonitoringState wraps a collections.deque(maxlen=500) of EventRecord objects.
  - A threading.Lock guards all mutations.
  - The singleton is obtained via get_monitoring_state() which uses
    @st.cache_resource when running under Streamlit, or a module-level
    singleton when called from tests or the worker thread directly.
  - Aggregate counters are updated atomically by update_event().
  - get_metrics() takes a snapshot of counters (no lock held across the copy)
    and returns a frozen MonitoringMetrics.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import TYPE_CHECKING

from monitoring.models import EventRecord, EventStatus
from monitoring.metrics import MonitoringMetrics

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# MonitoringState
# ---------------------------------------------------------------------------

_EMA_ALPHA = 0.2   # Exponential moving average alpha for latency smoothing


class MonitoringState:
    """
    Bounded in-memory state for the live monitoring layer.

    Thread-safe: all public methods acquire self._lock.
    """

    def __init__(self, maxlen: int = 500) -> None:
        self._lock = threading.Lock()
        self._events: deque[EventRecord] = deque(maxlen=maxlen)

        # Aggregate counters (updated by update_event / add_event)
        self._total_received: int = 0
        self._total_processed: int = 0
        self._total_errors: int = 0
        self._total_timeouts: int = 0
        self._total_dropped: int = 0
        self._total_nce_unavailable: int = 0
        self._all_infeasible: int = 0
        self._analyst_review: int = 0
        self._auto_approved: int = 0
        self._dry_run_complete: int = 0
        self._era_low: int = 0
        self._era_medium: int = 0
        self._era_high: int = 0
        self._hypotheses_generated: int = 0
        self._hypotheses_feasible: int = 0
        self._hypotheses_infeasible: int = 0

        # EMA latencies (ms)
        self._avg_era_ms: float = 0.0
        self._avg_nce_ms: float = 0.0
        self._avg_sse_ms: float = 0.0
        self._avg_rsem_ms: float = 0.0
        self._avg_total_ms: float = 0.0

        # Throughput tracking
        self._events_per_min: float = 0.0
        self._last_epm_update: float = time.time()
        self._events_since_last_epm: int = 0

        # Queue depth (set externally by worker)
        self._queue_depth: int = 0

        # Session start
        self._session_started_at: float = time.time()

    # ------------------------------------------------------------------
    # Write methods (called by the worker thread)
    # ------------------------------------------------------------------

    def add_event(self, record: EventRecord) -> None:
        """Add a new EventRecord to the deque and increment received counter."""
        with self._lock:
            self._events.append(record)
            self._total_received += 1
            self._events_since_last_epm += 1
            self._update_epm_if_needed()

    def update_event(self, record: EventRecord) -> None:
        """
        Update aggregate counters based on the terminal state of a record.

        Called once per event when the worker finishes processing it.
        The record is already in the deque (added by add_event); this call
        only updates the aggregate counters — the record object itself is
        mutated in-place by the worker before this call.
        """
        with self._lock:
            status = record.status
            if status == EventStatus.DONE:
                self._total_processed += 1
                self._update_outcome_counters(record)
                self._update_latency_ema(record)
            elif status == EventStatus.ERROR:
                self._total_errors += 1
            elif status == EventStatus.TIMEOUT:
                self._total_timeouts += 1
            elif status == EventStatus.DROPPED:
                self._total_dropped += 1
            elif status == EventStatus.NCE_UNAVAILABLE:
                self._total_nce_unavailable += 1
                # Still count as processed for throughput purposes
                self._total_processed += 1

    def set_queue_depth(self, depth: int) -> None:
        """Called by the worker to update the queue depth snapshot."""
        with self._lock:
            self._queue_depth = depth

    def clear(self) -> None:
        """Reset all state. Called from the dashboard 'Clear' button."""
        with self._lock:
            self._events.clear()
            self._total_received = 0
            self._total_processed = 0
            self._total_errors = 0
            self._total_timeouts = 0
            self._total_dropped = 0
            self._total_nce_unavailable = 0
            self._all_infeasible = 0
            self._analyst_review = 0
            self._auto_approved = 0
            self._dry_run_complete = 0
            self._era_low = 0
            self._era_medium = 0
            self._era_high = 0
            self._hypotheses_generated = 0
            self._hypotheses_feasible = 0
            self._hypotheses_infeasible = 0
            self._avg_era_ms = 0.0
            self._avg_nce_ms = 0.0
            self._avg_sse_ms = 0.0
            self._avg_rsem_ms = 0.0
            self._avg_total_ms = 0.0
            self._events_per_min = 0.0
            self._events_since_last_epm = 0
            self._last_epm_update = time.time()
            self._queue_depth = 0
            self._session_started_at = time.time()

    # ------------------------------------------------------------------
    # Read methods (called by Streamlit dashboard thread)
    # ------------------------------------------------------------------

    def get_snapshot(self, last_n: int = 50) -> list[EventRecord]:
        """Return the most recent *last_n* events (copy of references)."""
        with self._lock:
            events = list(self._events)
        return events[-last_n:]

    def get_all_events(self) -> list[EventRecord]:
        """Return all buffered events (copy of references)."""
        with self._lock:
            return list(self._events)

    def get_metrics(self) -> MonitoringMetrics:
        """Return a frozen snapshot of all aggregate counters."""
        with self._lock:
            return MonitoringMetrics(
                total_received=self._total_received,
                total_processed=self._total_processed,
                total_errors=self._total_errors,
                total_timeouts=self._total_timeouts,
                total_dropped=self._total_dropped,
                total_nce_unavailable=self._total_nce_unavailable,
                all_infeasible=self._all_infeasible,
                analyst_review=self._analyst_review,
                auto_approved=self._auto_approved,
                dry_run_complete=self._dry_run_complete,
                era_low=self._era_low,
                era_medium=self._era_medium,
                era_high=self._era_high,
                hypotheses_generated=self._hypotheses_generated,
                hypotheses_feasible=self._hypotheses_feasible,
                hypotheses_infeasible=self._hypotheses_infeasible,
                avg_era_ms=self._avg_era_ms,
                avg_nce_ms=self._avg_nce_ms,
                avg_sse_ms=self._avg_sse_ms,
                avg_rsem_ms=self._avg_rsem_ms,
                avg_total_ms=self._avg_total_ms,
                queue_depth=self._queue_depth,
                events_per_min=self._events_per_min,
            )

    @property
    def event_count(self) -> int:
        """Current number of events in the deque."""
        with self._lock:
            return len(self._events)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_outcome_counters(self, record: EventRecord) -> None:
        """Must be called under self._lock."""
        decision = record.final_decision
        if decision == "ALL_INFEASIBLE":
            self._all_infeasible += 1
        elif decision == "PENDING_ANALYST_REVIEW":
            self._analyst_review += 1
        elif decision == "AUTO_APPROVED":
            self._auto_approved += 1
        elif decision == "DRY_RUN_COMPLETE":
            self._dry_run_complete += 1

        level = record.era_risk_level
        if level == "LOW":
            self._era_low += 1
        elif level == "MEDIUM":
            self._era_medium += 1
        elif level == "HIGH":
            self._era_high += 1

        self._hypotheses_generated += record.nce_hypothesis_count
        self._hypotheses_feasible += record.sse_feasible_count
        self._hypotheses_infeasible += record.sse_infeasible_count

    def _update_latency_ema(self, record: EventRecord) -> None:
        """EMA update for per-stage latencies. Must be called under self._lock."""
        def _ema(current: float, sample: float) -> float:
            if current == 0.0:
                return sample
            return _EMA_ALPHA * sample + (1 - _EMA_ALPHA) * current

        trace = record.stage_trace
        if "ERA" in trace and trace["ERA"].status == "OK":
            self._avg_era_ms = _ema(self._avg_era_ms, trace["ERA"].latency_ms)
        if "NCE" in trace and trace["NCE"].status == "OK":
            self._avg_nce_ms = _ema(self._avg_nce_ms, trace["NCE"].latency_ms)
        if "SSE" in trace and trace["SSE"].status == "OK":
            self._avg_sse_ms = _ema(self._avg_sse_ms, trace["SSE"].latency_ms)
        if "RSEM" in trace and trace["RSEM"].status == "OK":
            self._avg_rsem_ms = _ema(self._avg_rsem_ms, trace["RSEM"].latency_ms)
        if record.total_latency_ms > 0:
            self._avg_total_ms = _ema(self._avg_total_ms, record.total_latency_ms)

    def _update_epm_if_needed(self) -> None:
        """Recompute events-per-minute if >=60s have elapsed. Under self._lock."""
        now = time.time()
        elapsed = now - self._last_epm_update
        if elapsed >= 60.0:
            self._events_per_min = self._events_since_last_epm / (elapsed / 60.0)
            self._events_since_last_epm = 0
            self._last_epm_update = now


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_SINGLETON: MonitoringState | None = None
_SINGLETON_LOCK = threading.Lock()


def get_monitoring_state() -> MonitoringState:
    """
    Return the process-wide MonitoringState singleton.

    When called from the Streamlit app this should be wrapped in
    @st.cache_resource so Streamlit manages the lifetime.  When called from
    tests or the worker thread it returns a module-level singleton.
    """
    global _SINGLETON
    if _SINGLETON is None:
        with _SINGLETON_LOCK:
            if _SINGLETON is None:
                _SINGLETON = MonitoringState()
    return _SINGLETON


def reset_monitoring_state() -> None:
    """
    Replace the singleton with a fresh instance.

    Used in tests to get a clean slate between test cases.
    NOT safe to call while the worker thread is running.
    """
    global _SINGLETON
    with _SINGLETON_LOCK:
        _SINGLETON = MonitoringState()
