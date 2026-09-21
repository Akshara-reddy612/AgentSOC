"""
monitoring/sources/replay_source.py

Replay event source for the real-time monitoring layer.

Loops or single-runs over a list of alert dictionaries at a configurable replay interval,
submitting each alert to a MonitoringWorker. Supports start, stop, pause, resume, reset,
and speed control.
"""

from __future__ import annotations

import threading
import time
from typing import Sequence

from monitoring.worker import MonitoringWorker, get_monitoring_worker


class ReplaySource:
    """
    Replays a list of raw alert dicts into a MonitoringWorker on a background thread.
    """

    def __init__(
        self,
        alerts: Sequence[dict],
        worker: MonitoringWorker | None = None,
        delay_s: float = 2.0,
        loop: bool = False,
    ) -> None:
        self.alerts: list[dict] = list(alerts)
        self.worker: MonitoringWorker = worker if worker is not None else get_monitoring_worker()
        self.delay_s: float = delay_s
        self.loop: bool = loop

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # set = running, clear = paused
        self._current_index: int = 0
        self._running = False

    def reset(self) -> None:
        """Reset replay position back to start."""
        self._current_index = 0

    def start(self) -> None:
        """Start replaying alerts in the background."""
        if self._running and self._thread is not None and self._thread.is_alive():
            return

        if not self.worker.is_running:
            self.worker.start()

        self._stop_event.clear()
        self._pause_event.set()
        self._running = True
        self._thread = threading.Thread(
            target=self._replay_loop,
            name="ReplaySourceThread",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 0.0) -> None:
        """Stop the replay thread cleanly without blocking the UI thread."""
        self._stop_event.set()
        self._pause_event.set()  # Unblock if paused
        self._running = False
        if timeout > 0 and self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._thread = None

    def pause(self) -> None:
        """Pause replay."""
        self._pause_event.clear()

    def resume(self) -> None:
        """Resume replay."""
        self._pause_event.set()

    def set_delay(self, delay_s: float) -> None:
        """Adjust delay between events in seconds."""
        self.delay_s = max(0.1, delay_s)

    @property
    def is_paused(self) -> bool:
        return not self._pause_event.is_set()

    @property
    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

    @property
    def current_index(self) -> int:
        return self._current_index

    def _replay_loop(self) -> None:
        """Main loop feeding alerts into the worker."""
        if not self.alerts:
            self._running = False
            return

        while not self._stop_event.is_set():
            # Handle pause
            self._pause_event.wait()
            if self._stop_event.is_set():
                break

            if self._current_index >= len(self.alerts):
                if self.loop:
                    self._current_index = 0
                else:
                    break

            alert = self.alerts[self._current_index]
            self.worker.submit_event(alert, source_tag="replay")
            self._current_index += 1

            # Sleep in small increments so stop/pause responds quickly
            sleep_needed = self.delay_s
            start_sleep = time.time()
            while time.time() - start_sleep < sleep_needed:
                if self._stop_event.is_set():
                    break
                time.sleep(0.05)

        self._running = False


# Process-wide ReplaySource singleton
_REPLAY_SINGLETON: ReplaySource | None = None
_REPLAY_LOCK = threading.Lock()


def get_replay_source(
    alerts: Sequence[dict] | None = None,
    delay_s: float = 2.0,
    loop: bool = False,
) -> ReplaySource:
    """Get or create the process-wide ReplaySource singleton."""
    global _REPLAY_SINGLETON
    if _REPLAY_SINGLETON is None:
        with _REPLAY_LOCK:
            if _REPLAY_SINGLETON is None:
                from monitoring.demo_alerts import CURATED_DEMO_ALERTS
                alert_list = list(alerts) if alerts is not None else CURATED_DEMO_ALERTS
                _REPLAY_SINGLETON = ReplaySource(alerts=alert_list, delay_s=delay_s, loop=loop)
    return _REPLAY_SINGLETON
