"""
monitoring/worker.py

Single worker thread for the live monitoring layer.

Architecture & Invariants:
  - Consumes raw alert dicts (or pre-constructed EventRecords) from a bounded
    queue.Queue(maxsize=200).
  - Single daemon thread (MonitoringWorker).
  - Each item is processed through MonitoringPipelineAdapter.
  - One bad event (exception, malformed JSON, timeout) NEVER stops the loop:
    exceptions are caught, recorded as ERROR on the EventRecord, and the loop continues.
  - Soft timeout (time_limit_s) is checked between stages.  If exceeded,
    the event status is set to TIMEOUT. A TIMEOUT event NEVER updates
    action/decision state.
  - Backpressure: if queue is full when an ingestion source calls submit_event(),
    the event is dropped immediately, recorded in state as DROPPED, and counted.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Any

from monitoring.models import EventRecord, EventStatus
from monitoring.pipeline_adapter import MonitoringPipelineAdapter
from monitoring.state import MonitoringState, get_monitoring_state


class MonitoringWorker:
    """
    Worker thread that pulls events from an in-memory queue and runs them
    through the pipeline adapter.
    """

    def __init__(
        self,
        event_queue: queue.Queue | None = None,
        state: MonitoringState | None = None,
        adapter: MonitoringPipelineAdapter | None = None,
        time_limit_s: float = 30.0,
        use_live_nce: bool = False,
    ) -> None:
        self.queue: queue.Queue = event_queue if event_queue is not None else queue.Queue(maxsize=200)
        self.state: MonitoringState = state if state is not None else get_monitoring_state()
        self.adapter: MonitoringPipelineAdapter = adapter if adapter is not None else MonitoringPipelineAdapter()
        self.time_limit_s: float = time_limit_s
        self.use_live_nce: bool = use_live_nce

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._running = False

    def start(self) -> None:
        """Start the background worker thread."""
        if self._running and self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._worker_loop,
            name="MonitoringWorkerThread",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the worker thread to stop and wait up to *timeout* seconds."""
        self._stop_event.set()
        self._running = False
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    @property
    def is_running(self) -> bool:
        """True if the worker thread is active."""
        return self._running and self._thread is not None and self._thread.is_alive()

    def submit_event(self, alert_dict: dict, source_tag: str = "custom") -> EventRecord:
        """
        Public submission API for ingestion sources.

        Attempts to put (alert_dict, record) into the queue.
        If the queue is full (backpressure), marks the record as DROPPED,
        adds it directly to state, and updates counters without enqueuing.
        """
        correlation_id = str(alert_dict.get("alert_id", ""))
        record = EventRecord(
            correlation_id=correlation_id,
            source_tag=source_tag,
            alert_id=correlation_id,
            source_user=str(alert_dict.get("source_user", "")),
            source_host=str(alert_dict.get("source_host", "")),
            target_host=str(alert_dict.get("target_host", "")),
            event_type=str(alert_dict.get("event_type", "")),
            severity=str(alert_dict.get("severity", "")),
            status=EventStatus.QUEUED,
        )

        # Add to state immediately so it appears in the UI
        self.state.add_event(record)
        self.state.set_queue_depth(self.queue.qsize())

        try:
            self.queue.put_nowait((alert_dict, record))
            self.state.set_queue_depth(self.queue.qsize())
        except queue.Full:
            # Backpressure: drop newest event when queue is full
            record.status = EventStatus.DROPPED
            record.error_text = "Queue full (backpressure: dropped newest event)"
            record.final_decision = "DROPPED"
            record.processing_finished_at = time.time()
            self.state.update_event(record)

        return record

    def _worker_loop(self) -> None:
        """Main loop executed by the worker thread."""
        # Pre-warm ERA pipeline once on worker startup before processing queue items
        try:
            self.adapter.warmup()
        except Exception as exc:  # noqa: BLE001
            logger.warning("MonitoringWorker pre-warm encounter error: %s", exc)

        while not self._stop_event.is_set():
            self.state.set_queue_depth(self.queue.qsize())
            try:
                item = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue

            alert_dict, record = item
            record.status = EventStatus.PROCESSING
            record.processing_started_at = time.time()

            try:
                self.adapter.run(
                    alert=alert_dict,
                    record=record,
                    time_limit_s=self.time_limit_s,
                    use_live_nce=self.use_live_nce,
                )
            except TimeoutError as exc:
                record.status = EventStatus.TIMEOUT
                record.error_text = str(exc)
                record.final_decision = "TIMEOUT"
                record.processing_finished_at = time.time()
            except Exception as exc:  # noqa: BLE001
                record.status = EventStatus.ERROR
                record.error_text = f"Unhandled exception: {exc}"
                record.final_decision = "ERROR"
                record.processing_finished_at = time.time()
            finally:
                self.queue.task_done()
                self.state.update_event(record)
                self.state.set_queue_depth(self.queue.qsize())


# Singleton worker instance
_WORKER_SINGLETON: MonitoringWorker | None = None
_WORKER_LOCK = threading.Lock()


def get_monitoring_worker() -> MonitoringWorker:
    """Get or create the process-wide worker singleton."""
    global _WORKER_SINGLETON
    if _WORKER_SINGLETON is None:
        with _WORKER_LOCK:
            if _WORKER_SINGLETON is None:
                _WORKER_SINGLETON = MonitoringWorker()
    return _WORKER_SINGLETON
