"""
monitoring/__init__.py

Real-Time Monitoring Layer for AgentSOC.

This package wraps the existing pipeline (NCE → SSE → RSEM → Action/Playbook)
with a live-event queue, single worker thread, bounded in-memory state, and a
Streamlit dashboard tab.

Architecture:
    producer thread(s) → queue.Queue(maxsize=200) → MonitoringWorker (single thread)
    → MonitoringPipelineAdapter → [existing pipeline, unchanged]
    → MonitoringState (deque maxlen=500) → Streamlit dashboard (st.fragment)

Invariants (never broken by this package):
  - No Raw Event → LLM → Action path.
  - ERA and SSE guardrails run first; filtered events never call NCE.
  - All actions remain dry-run only.
  - Existing pipeline entry points are called; no stage logic is duplicated.
  - NCE defaults to cached outputs; live LLM is opt-in via use_live_nce flag.
  - TIMEOUT events do not update action/decision state.
  - DROPPED events are counted and do not enter the pipeline.
"""
