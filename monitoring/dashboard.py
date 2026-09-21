"""
monitoring/dashboard.py

Streamlit Live Monitoring Dashboard UI component for AgentSOC 2.0.

This tab renders real-time telemetry from the MonitoringState singleton:
  - Header & Status metrics (Events processed, Defense rate, Infeasible count, Analyst reviews)
  - Control Panel (Start Replay, Pause, Resume, Speed Slider, Clear State)
  - Live Event Feed (Table of recent events with status badges)
  - Event Detail & Trace Inspector (collapsible per-stage execution trace)
  - System Invariants & Guardrail Telemetry (Graph immutability, zero-blended confidence)

Decorated with `@st.fragment(run_every=2)` for automatic 2-second live refresh.
Button actions mutate state/replay controllers directly within the fragment
WITHOUT calling `st.rerun()`, preserving fragment isolation and keeping the UI
undimmed and responsive during replay processing.
"""

from __future__ import annotations

import time
from typing import Any

import streamlit as st

from monitoring.models import EventRecord, EventStatus
from monitoring.state import get_monitoring_state
from monitoring.worker import get_monitoring_worker
from monitoring.sources.replay_source import get_replay_source


@st.fragment(run_every=2)
def render_live_monitoring_tab(st_param: Any = None) -> None:
    """
    Render the full Live Monitoring Dashboard tab in Streamlit.

    Refreshes automatically every 2 seconds via @st.fragment(run_every=2).
    """
    state = get_monitoring_state()
    worker = get_monitoring_worker()
    replay = get_replay_source()

    # Automatic worker start if not running
    if not worker.is_running:
        worker.start()

    st.markdown("### 📡 AgentSOC 2.0 — Real-Time Pipeline Monitoring")
    st.markdown(
        "Live event monitoring wrapping the existing Perception → ERA → NCE → SSE → RSEM → Action Playbook pipeline."
    )

    # -----------------------------------------------------------------------
    # Control Bar
    # -----------------------------------------------------------------------
    col_c1, col_c2, col_c3, col_c4, col_c5 = st.columns([1.5, 1.2, 1.2, 2.5, 1.0])

    with col_c1:
        if not replay.is_running:
            if st.button("▶️ Start Replay", type="primary", use_container_width=True):
                replay.reset()
                replay.start()
        else:
            if replay.is_paused:
                if st.button("▶️ Resume Replay", type="primary", use_container_width=True):
                    replay.resume()
            else:
                if st.button("⏸️ Pause Replay", use_container_width=True):
                    replay.pause()

    with col_c2:
        if replay.is_running:
            if st.button("⏹️ Stop Replay", use_container_width=True):
                replay.stop()

    with col_c3:
        if st.button("🗑️ Clear State", use_container_width=True):
            state.clear()

    with col_c4:
        new_delay = st.slider(
            "Replay Speed (sec/event)",
            min_value=0.5,
            max_value=5.0,
            value=float(replay.delay_s),
            step=0.5,
        )
        if abs(new_delay - replay.delay_s) > 1e-3:
            replay.set_delay(new_delay)

    with col_c5:
        st.button("🔄 Refresh", use_container_width=True)

    # -----------------------------------------------------------------------
    # Key KPI Metric Cards & Processing Status
    # -----------------------------------------------------------------------
    metrics = state.get_metrics()

    completed_terminal = (
        metrics.total_processed
        + metrics.total_errors
        + metrics.total_timeouts
        + metrics.total_dropped
    )
    pending = max(0, metrics.total_received - completed_terminal)
    total_alerts = len(replay.alerts) if replay.alerts else 5

    # Replay & processing status banner
    if replay.is_running or pending > 0:
        if replay.is_paused:
            st.info(
                f"⏸️ **Replay Paused** — Completed {metrics.total_processed}/{total_alerts} events | "
                f"Received: {metrics.total_received} | Processed: {metrics.total_processed} | Pending: {pending}"
            )
        else:
            st.info(
                f"🔄 **Processing replay — {metrics.total_processed}/{total_alerts} completed** | "
                f"Received: {metrics.total_received} | Processed: {metrics.total_processed} | Pending: {pending}"
            )
    elif metrics.total_processed >= total_alerts or (replay.current_index >= total_alerts and total_alerts > 0):
        st.success(f"✅ **Replay Completed** — Processed {metrics.total_processed}/{total_alerts} events.")
    elif metrics.total_processed > 0:
        st.success(f"✅ **Processing Completed** — Processed {metrics.total_processed}/{metrics.total_received} events.")

    st.markdown("---")

    m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
    with m_col1:
        st.metric("Total Received", f"{metrics.total_received}")
    with m_col2:
        st.metric("Processed (OK)", f"{metrics.total_processed}")
    with m_col3:
        st.metric("Structural Defense Rate", f"{metrics.defense_rate:.1%}")
    with m_col4:
        st.metric("Analyst Reviews", f"{metrics.analyst_review}")
    with m_col5:
        st.metric("Avg Latency", f"{metrics.avg_total_ms:.1f} ms")

    st.markdown("---")

    # -----------------------------------------------------------------------
    # Live Events Feed & Inspector
    # -----------------------------------------------------------------------
    st.markdown("#### 📋 Event Stream (Recent 50 Events)")

    events = state.get_snapshot(last_n=50)

    if not events:
        st.info("No events recorded yet. Click **▶️ Start Replay** to launch the curated 5-alert demo stream.")
    else:
        # Build summary table rows
        rows = []
        for rec in reversed(events):
            rows.append({
                "Event ID / Correlation": rec.alert_id or rec.event_id[:8],
                "Source User": rec.source_user or "-",
                "Source Host": rec.source_host or "-",
                "Target Host": rec.target_host or "-",
                "ERA Risk": rec.era_risk_level or "LOW",
                "SSE Feasible / Infeasible": f"{rec.sse_feasible_count} / {rec.sse_infeasible_count}",
                "Top RSEM Action": rec.rsem_top_action or "NONE",
                "Final Decision": rec.final_decision,
                "Status": rec.status.value,
                "Latency": f"{rec.total_latency_ms:.1f} ms" if rec.total_latency_ms > 0 else "-",
            })

        # Render summary table
        st.dataframe(rows, use_container_width=True)

        # -------------------------------------------------------------------
        # Event Detail & Complete Trace Inspector
        # -------------------------------------------------------------------
        st.markdown("#### 🔍 Deep Trace Inspector")
        event_options = {
            f"Event #{i+1}: {rec.alert_id} ({rec.final_decision})": rec
            for i, rec in enumerate(reversed(events))
        }

        selected_label = st.selectbox("Select event to view complete stage trace:", list(event_options.keys()))
        if selected_label:
            selected_rec: EventRecord = event_options[selected_label]
            _render_event_detail_trace(st, selected_rec)

    # -----------------------------------------------------------------------
    # Invariants & System Telemetry Footer
    # -----------------------------------------------------------------------
    st.markdown("---")
    st.markdown("#### 🛡️ Active Safety Invariants & Telemetry")

    inv_col1, inv_col2, inv_col3 = st.columns(3)
    with inv_col1:
        st.markdown("""
        <div style="background:#1e293b; padding:12px; border-radius:8px; border-left:4px solid #3b82f6;">
            <strong>🔒 Non-Actionable LLM Output:</strong><br/>
            Raw Event → LLM → Action path strictly prohibited. Every NCE hypothesis must independently pass SSE structural verification.
        </div>
        """, unsafe_allow_html=True)
    with inv_col2:
        st.markdown("""
        <div style="background:#1e293b; padding:12px; border-radius:8px; border-left:4px solid #10b981;">
            <strong>⚡ Graph Immutability & Dry-Run:</strong><br/>
            Graph traversals and action simulations operate on <code>graph.copy()</code>. Zero live KnowledgeStore Graph mutations.
        </div>
        """, unsafe_allow_html=True)
    with inv_col3:
        st.markdown("""
        <div style="background:#1e293b; padding:12px; border-radius:8px; border-left:4px solid #f59e0b;">
            <strong>🎯 Confidence Unblended:</strong><br/>
            <code>nce_confidence</code> is advisory only. Never averaged with SSE <code>path_confidence</code> or RSEM composite scores.
        </div>
        """, unsafe_allow_html=True)


def _render_event_detail_trace(st_context: Any, rec: EventRecord) -> None:
    """Render full stage-by-stage execution trace for a selected event."""
    with st.expander(f"🔬 Trace Details — Alert {rec.alert_id}", expanded=True):
        st.markdown(f"**Correlation ID:** `{rec.correlation_id}` | **Status:** `{rec.status.value}` | **Final Decision:** `{rec.final_decision}`")
        if rec.guardrail_reason:
            st.warning(f"**Guardrail Reason:** {rec.guardrail_reason}")

        st.markdown("##### Stage-by-Stage Telemetry")

        stages = ["PERCEPTION", "ERA", "NCE", "SSE", "RSEM", "PLAYBOOK"]
        cols = st.columns(len(stages))

        for idx, stage in enumerate(stages):
            info = rec.stage_trace.get(stage)
            with cols[idx]:
                if info is None:
                    st.markdown(f"**{stage}**\n`NOT_REACHED`")
                else:
                    color = "#10b981" if info.status == "OK" else ("#f59e0b" if info.status == "SKIPPED" else "#ef4444")
                    st.markdown(
                        f"<div style='border:1px solid {color}; padding:8px; border-radius:6px; font-size:0.85rem;'>"
                        f"<strong>{stage}</strong><br/>"
                        f"<span style='color:{color}; font-weight:bold;'>{info.status}</span><br/>"
                        f"<small>{info.latency_ms:.1f} ms</small><br/>"
                        f"<small style='color:#aaa;'>{info.detail[:40]}</small>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

        st.markdown("---")
        st.markdown("##### Summary Record JSON")
        st.json({
            "alert_id": rec.alert_id,
            "source_user": rec.source_user,
            "source_host": rec.source_host,
            "target_host": rec.target_host,
            "era_risk_level": rec.era_risk_level,
            "era_risk_score": rec.era_risk_score,
            "nce_techniques": rec.nce_techniques,
            "sse_feasible_count": rec.sse_feasible_count,
            "sse_infeasible_count": rec.sse_infeasible_count,
            "rsem_top_action": rec.rsem_top_action,
            "rsem_composite_score": rec.rsem_composite_score,
            "final_decision": rec.final_decision,
        })
