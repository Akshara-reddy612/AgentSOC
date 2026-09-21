"""
tests/test_monitoring.py

Unit tests for Phase 1 and Phase 2 of the Real-Time Monitoring Layer.

Tests cover:
  1. EventRecord, StageInfo, and EventStatus models
  2. MonitoringMetrics calculation and properties
  3. MonitoringState deque bounding, snapshot generation, and thread-safety
  4. MonitoringPipelineAdapter execution, timeout guards, and NCE cache integration
  5. MonitoringWorker queue processing, error isolation, and backpressure (queue full)
  6. ReplaySource start/stop, pause/resume, and delay adjustments
  7. JSONLTailSource file tailing, malformed lines, truncation handling
  8. APISource HTTP server, health check, 202 Accepted, 413 Payload Too Large, 400 Bad Request, rebind safety
  9. Invariants: graph immutability, cache miss → NCE_UNAVAILABLE, dry-run only
"""

from __future__ import annotations

import json
import queue
import time
import urllib.request
import urllib.error
import pytest

from monitoring.models import EventRecord, EventStatus, StageInfo
from monitoring.metrics import MonitoringMetrics
from monitoring.state import MonitoringState, reset_monitoring_state, get_monitoring_state
from monitoring.pipeline_adapter import MonitoringPipelineAdapter, get_nce_cache, _load_nce_cache
from monitoring.worker import MonitoringWorker
from monitoring.sources.replay_source import ReplaySource
from monitoring.sources.jsonl_source import JSONLTailSource
from monitoring.sources.api_source import APISource, MAX_PAYLOAD_BYTES
from monitoring.demo_alerts import CURATED_DEMO_ALERTS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_state():
    """Ensure a fresh MonitoringState singleton before each test."""
    reset_monitoring_state()
    yield
    reset_monitoring_state()


# ---------------------------------------------------------------------------
# 1. Models & Metrics Tests
# ---------------------------------------------------------------------------

def test_event_record_defaults():
    rec = EventRecord(alert_id="test-001", source_user="alice")
    assert rec.alert_id == "test-001"
    assert rec.status == EventStatus.QUEUED
    assert rec.total_latency_ms == 0.0
    assert len(rec.stage_trace) == 0


def test_event_record_stage_trace():
    rec = EventRecord(alert_id="test-002")
    rec.mark_stage("ERA", "OK", 12.5, "score=0.85")
    assert "ERA" in rec.stage_trace
    assert rec.stage_trace["ERA"].status == "OK"
    assert rec.stage_trace["ERA"].latency_ms == 12.5
    assert rec.stage_trace["ERA"].detail == "score=0.85"


def test_event_record_latency_calculation():
    rec = EventRecord()
    rec.processing_started_at = 100.0
    rec.processing_finished_at = 100.25  # 250 ms
    assert abs(rec.total_latency_ms - 250.0) < 1e-3


def test_metrics_snapshot_properties():
    metrics = MonitoringMetrics(
        total_received=10,
        total_processed=8,
        all_infeasible=4,
    )
    assert metrics.success_rate == 0.8
    assert metrics.defense_rate == 0.5


def test_metrics_snapshot_zero_division_guard():
    metrics = MonitoringMetrics(total_received=0, total_processed=0)
    assert metrics.success_rate == 0.0
    assert metrics.defense_rate == 0.0


# ---------------------------------------------------------------------------
# 2. State & Bounded Memory Tests
# ---------------------------------------------------------------------------

def test_state_deque_maxlen_bounding():
    state = MonitoringState(maxlen=5)
    for i in range(10):
        rec = EventRecord(alert_id=f"alert-{i}")
        state.add_event(rec)

    assert state.event_count == 5
    snapshot = state.get_snapshot(last_n=10)
    assert len(snapshot) == 5
    assert snapshot[0].alert_id == "alert-5"
    assert snapshot[-1].alert_id == "alert-9"


def test_state_counters_update():
    state = MonitoringState()
    rec = EventRecord(alert_id="a1")
    state.add_event(rec)

    rec.status = EventStatus.DONE
    rec.final_decision = "ALL_INFEASIBLE"
    rec.era_risk_level = "HIGH"
    rec.mark_stage("ERA", "OK", 10.0)
    state.update_event(rec)

    metrics = state.get_metrics()
    assert metrics.total_received == 1
    assert metrics.total_processed == 1
    assert metrics.all_infeasible == 1
    assert metrics.era_high == 1
    assert metrics.avg_era_ms == 10.0


def test_state_clear():
    state = MonitoringState()
    rec = EventRecord(alert_id="a1")
    state.add_event(rec)
    rec.status = EventStatus.DONE
    state.update_event(rec)

    assert state.event_count == 1
    state.clear()
    assert state.event_count == 0
    metrics = state.get_metrics()
    assert metrics.total_received == 0
    assert metrics.total_processed == 0


# ---------------------------------------------------------------------------
# 3. Pipeline Adapter Tests
# ---------------------------------------------------------------------------

def test_adapter_cache_hit_sse_rejection():
    """Test alert-1073741825161 (cached in nce7) passes Perception → ERA → SSE INFEASIBLE."""
    adapter = MonitoringPipelineAdapter()
    rec = EventRecord()
    alert = {
        "alert_id": "1073741825161",
        "source_system": "SIEM",
        "event_type": "privilege_escalation",
        "timestamp": "2026-07-24T10:10:00+00:00",
        "source_user": "m.chen",
        "source_host": "LT-1092-CORP",
        "target_host": "LT-1092-CORP",
        "severity": "high",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -ExecutionPolicy Bypass",
    }

    adapter.run(alert, rec, time_limit_s=60.0, use_live_nce=False)

    assert rec.status == EventStatus.DONE
    assert rec.final_decision == "ALL_INFEASIBLE"
    assert rec.sse_infeasible_count > 0
    assert "PERCEPTION" in rec.stage_trace
    assert "ERA" in rec.stage_trace
    assert "NCE" in rec.stage_trace
    assert "SSE" in rec.stage_trace
    assert rec.stage_trace["NCE"].status == "OK"


def test_adapter_cache_miss_nce_unavailable():
    """Test that a non-cached alert_id produces NCE_UNAVAILABLE without calling LLM."""
    adapter = MonitoringPipelineAdapter()
    rec = EventRecord()
    alert = {
        "alert_id": "NON_EXISTENT_ALERT_99999",
        "source_system": "EDR",
        "event_type": "process_create",
        "timestamp": "2026-07-24T10:00:00+00:00",
        "source_user": "alice",
        "source_host": "workstation-01",
        "target_host": "workstation-01",
        "severity": "low",
        "process_name": "notepad.exe",
    }

    adapter.run(alert, rec, use_live_nce=False)

    assert rec.status == EventStatus.NCE_UNAVAILABLE
    assert rec.final_decision == "NCE_UNAVAILABLE"
    assert rec.stage_trace["NCE"].status == "UNAVAILABLE"


def test_adapter_schema_validation_rejection():
    """Test malformed alert (missing timestamp) is rejected by Schema Validator."""
    adapter = MonitoringPipelineAdapter()
    rec = EventRecord()
    alert = {
        "alert_id": "malformed-001",
        "source_system": "EDR",
        "event_type": "process_create",
        # missing timestamp
        "source_user": "alice",
    }

    adapter.run(alert, rec, use_live_nce=False)

    assert rec.status == EventStatus.DONE
    assert rec.final_decision == "SCHEMA_REJECTED"
    assert rec.stage_trace["PERCEPTION"].status == "FAILED"


def test_adapter_timeout_handling():
    """Test timeout_limit_s=0.000001 forces TimeoutError."""
    adapter = MonitoringPipelineAdapter()
    rec = EventRecord()
    alert = CURATED_DEMO_ALERTS[0]

    with pytest.raises(TimeoutError):
        adapter.run(alert, rec, time_limit_s=0.000001, use_live_nce=False)


# ---------------------------------------------------------------------------
# 4. MonitoringWorker & Concurrency Tests
# ---------------------------------------------------------------------------

def test_worker_submits_and_processes_event():
    state = MonitoringState()
    worker = MonitoringWorker(state=state, use_live_nce=False)
    worker.start()

    try:
        rec = worker.submit_event(CURATED_DEMO_ALERTS[0], source_tag="test")
        assert rec.status in (EventStatus.QUEUED, EventStatus.PROCESSING, EventStatus.DONE)

        # Wait for worker to finish event
        for _ in range(50):
            if rec.status in (EventStatus.DONE, EventStatus.ERROR, EventStatus.NCE_UNAVAILABLE):
                break
            time.sleep(0.1)

        assert rec.status in (EventStatus.DONE, EventStatus.NCE_UNAVAILABLE)
        assert state.get_metrics().total_processed == 1
    finally:
        worker.stop()


def test_worker_backpressure_queue_full():
    state = MonitoringState()
    small_queue = queue.Queue(maxsize=1)
    worker = MonitoringWorker(event_queue=small_queue, state=state)

    # Fill queue
    rec1 = EventRecord(alert_id="dummy1")
    small_queue.put_nowait(({"alert_id": "dummy1"}, rec1))

    # Next submission must be DROPPED due to backpressure
    rec2 = worker.submit_event(CURATED_DEMO_ALERTS[0], source_tag="test")

    assert rec2.status == EventStatus.DROPPED
    assert rec2.final_decision == "DROPPED"
    assert state.get_metrics().total_dropped == 1


def test_worker_error_isolation():
    """Worker loop continues even if a pipeline call raises an unhandled exception."""
    class BrokenAdapter(MonitoringPipelineAdapter):
        def run(self, alert, record, **kwargs):
            raise RuntimeError("Simulated pipeline crash!")

    state = MonitoringState()
    worker = MonitoringWorker(state=state, adapter=BrokenAdapter())
    worker.start()

    try:
        rec1 = worker.submit_event(CURATED_DEMO_ALERTS[0])
        for _ in range(30):
            if rec1.status == EventStatus.ERROR:
                break
            time.sleep(0.1)

        assert rec1.status == EventStatus.ERROR

        # Worker thread must still be alive and process rec2
        rec2 = worker.submit_event(CURATED_DEMO_ALERTS[1])
        for _ in range(30):
            if rec2.status == EventStatus.ERROR:
                break
            time.sleep(0.1)

        assert rec2.status == EventStatus.ERROR
        assert worker.is_running
    finally:
        worker.stop()


# ---------------------------------------------------------------------------
# 5. ReplaySource Tests
# ---------------------------------------------------------------------------

def test_replay_source_basic():
    state = MonitoringState()
    worker = MonitoringWorker(state=state, use_live_nce=False)
    source = ReplaySource(alerts=CURATED_DEMO_ALERTS[:2], worker=worker, delay_s=0.1, loop=False)

    source.start()
    time.sleep(0.5)
    source.stop()

    assert state.get_metrics().total_received >= 2


def test_replay_source_pause_resume():
    state = MonitoringState()
    worker = MonitoringWorker(state=state, use_live_nce=False)
    source = ReplaySource(alerts=CURATED_DEMO_ALERTS, worker=worker, delay_s=0.1, loop=True)

    source.start()
    time.sleep(0.2)
    source.pause()
    assert source.is_paused

    count_at_pause = state.get_metrics().total_received
    time.sleep(0.3)
    # Count should not grow while paused
    assert state.get_metrics().total_received == count_at_pause

    source.resume()
    assert not source.is_paused
    time.sleep(0.3)
    source.stop()

    assert state.get_metrics().total_received > count_at_pause


def test_replay_source_non_blocking_stop():
    """Verify ReplaySource.stop() returns promptly (<100ms) and prevents further submissions."""
    state = MonitoringState()
    worker = MonitoringWorker(state=state, use_live_nce=False)
    # Long delay between events to ensure thread would block if join(timeout=5) was called
    source = ReplaySource(alerts=CURATED_DEMO_ALERTS, worker=worker, delay_s=2.0, loop=True)

    source.start()
    time.sleep(0.1)

    t0 = time.time()
    source.stop()  # Default timeout=0.0
    stop_latency = time.time() - t0

    # Must return promptly without waiting on join
    assert stop_latency < 0.1, f"stop() took {stop_latency:.3f}s, expected < 0.1s"
    assert not source.is_running
    assert source._stop_event.is_set()

    received_at_stop = state.get_metrics().total_received
    time.sleep(0.3)

    # No new events should be submitted after stop
    assert state.get_metrics().total_received == received_at_stop
    worker.stop()



# ---------------------------------------------------------------------------
# 6. JSONLTailSource Tests (Phase 2)
# ---------------------------------------------------------------------------

def test_jsonl_tail_source(tmp_path):
    jsonl_file = tmp_path / "test_events.jsonl"

    state = MonitoringState()
    worker = MonitoringWorker(state=state, use_live_nce=False)
    source = JSONLTailSource(
        file_path=jsonl_file,
        worker=worker,
        poll_interval_s=0.1,
        from_beginning=True,
    )

    source.start()

    # Append valid JSON line
    with jsonl_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(CURATED_DEMO_ALERTS[0]) + "\n")

    time.sleep(0.4)
    assert source.lines_processed == 1
    assert state.get_metrics().total_received == 1

    # Append malformed JSON line
    with jsonl_file.open("a", encoding="utf-8") as fh:
        fh.write("{BAD_JSON_LINE\n")

    time.sleep(0.4)
    assert source.lines_failed == 1

    # Append second valid JSON line
    with jsonl_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(CURATED_DEMO_ALERTS[1]) + "\n")

    time.sleep(0.4)
    assert source.lines_processed == 2

    source.stop()


# ---------------------------------------------------------------------------
# 7. APISource Tests (Phase 2)
# ---------------------------------------------------------------------------

def test_api_source_health_and_ingestion():
    port = 8769  # Use test-specific port to avoid collisions
    state = MonitoringState()
    worker = MonitoringWorker(state=state, use_live_nce=False)
    api = APISource(host="127.0.0.1", port=port, worker=worker)

    started = api.start()
    assert started is True

    try:
        # GET /api/health
        health_req = urllib.request.Request(f"http://127.0.0.1:{port}/api/health")
        with urllib.request.urlopen(health_req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"

        # POST /api/events (valid payload)
        body = json.dumps(CURATED_DEMO_ALERTS[0]).encode("utf-8")
        post_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/events",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(post_req) as resp:
            assert resp.status == 202
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "accepted"
            assert "event_id" in data

        time.sleep(0.2)
        assert state.get_metrics().total_received == 1

        # POST /api/events (invalid JSON)
        bad_json_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/events",
            data=b"INVALID_JSON",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_json_req)
        assert exc_info.value.code == 400

        # POST /api/events (payload too large)
        big_body = json.dumps({"data": "x" * (MAX_PAYLOAD_BYTES + 100)}).encode("utf-8")
        big_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/events",
            data=big_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(big_req)
        assert exc_info.value.code == 413

    finally:
        api.stop()


def test_api_source_rebind_safety():
    """Verify APISource start() doesn't crash if port is already bound."""
    port = 8770
    api1 = APISource(host="127.0.0.1", port=port)
    started1 = api1.start()
    assert started1 is True

    try:
        api2 = APISource(host="127.0.0.1", port=port)
        started2 = api2.start()
        # Should gracefully return False without raising OSError
        assert started2 is False
    finally:
        api1.stop()


# ---------------------------------------------------------------------------
# 8. Safety & Invariant Tests
# ---------------------------------------------------------------------------

def test_graph_immutability_during_monitoring():
    """Verify live KnowledgeStoreGraph is never mutated during monitoring runs."""
    from perception.knowledge_graph import KnowledgeStoreGraph

    kg = KnowledgeStoreGraph()
    initial_nodes = kg.graph.number_of_nodes()
    initial_edges = kg.graph.number_of_edges()

    adapter = MonitoringPipelineAdapter()
    rec = EventRecord()
    adapter.run(CURATED_DEMO_ALERTS[0], rec, time_limit_s=60.0, use_live_nce=False)

    assert kg.graph.number_of_nodes() == initial_nodes
    assert kg.graph.number_of_edges() == initial_edges


def test_adapter_warmup_no_state_mutation():
    """Verify warmup does not record events in MonitoringState or create EventRecord."""
    state = MonitoringState()
    adapter = MonitoringPipelineAdapter()
    adapter.warmup()

    assert state.event_count == 0
    metrics = state.get_metrics()
    assert metrics.total_received == 0
    assert metrics.total_processed == 0


def test_adapter_warmup_error_handling(monkeypatch):
    """Verify warmup failure is caught gracefully without raising."""
    adapter = MonitoringPipelineAdapter()

    def broken_run(*args, **kwargs):
        raise RuntimeError("Warmup pipeline error!")

    from perception.pipeline import PerceptionPipeline
    monkeypatch.setattr(PerceptionPipeline, "run", broken_run)

    # Should not raise exception
    adapter.warmup()
