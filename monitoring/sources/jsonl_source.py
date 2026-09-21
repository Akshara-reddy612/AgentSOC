"""
monitoring/sources/jsonl_source.py

JSONL file-tailing event source for the real-time monitoring layer.

Tails a target JSONL file on a background daemon thread, parsing newly appended
lines as JSON alert dicts and submitting them to a MonitoringWorker.

Failure handling:
  - Missing file: waits gracefully for the file to be created.
  - Partial / incomplete line writing: tracks file offset and handles incomplete trailing lines.
  - Malformed JSON line: logs warning, skips broken line, continues tailing without crashing.
  - File truncation / rotation: resets file offset if size shrinks.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

from monitoring.worker import MonitoringWorker, get_monitoring_worker

logger = logging.getLogger(__name__)


class JSONLTailSource:
    """
    Background thread that tails a .jsonl file for new alert records.
    """

    def __init__(
        self,
        file_path: str | Path,
        worker: MonitoringWorker | None = None,
        poll_interval_s: float = 0.5,
        from_beginning: bool = False,
    ) -> None:
        self.file_path: Path = Path(file_path).resolve()
        self.worker: MonitoringWorker = worker if worker is not None else get_monitoring_worker()
        self.poll_interval_s: float = poll_interval_s
        self.from_beginning: bool = from_beginning

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._running = False
        self._last_offset: int = 0
        self._lines_processed: int = 0
        self._lines_failed: int = 0

    def start(self) -> None:
        """Start the file tailing thread."""
        if self._running and self._thread is not None and self._thread.is_alive():
            return

        if not self.worker.is_running:
            self.worker.start()

        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._tail_loop,
            name="JSONLTailSourceThread",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop tailing."""
        self._stop_event.set()
        self._running = False
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    @property
    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

    @property
    def lines_processed(self) -> int:
        return self._lines_processed

    @property
    def lines_failed(self) -> int:
        return self._lines_failed

    def _tail_loop(self) -> None:
        """Main loop tracking file offset and reading lines."""
        # Initial offset setup
        if self.file_path.exists() and not self.from_beginning:
            self._last_offset = self.file_path.stat().st_size
        else:
            self._last_offset = 0

        buffer = ""

        while not self._stop_event.is_set():
            if not self.file_path.exists():
                time.sleep(self.poll_interval_s)
                continue

            try:
                current_size = self.file_path.stat().st_size

                # Handle file truncation/rotation
                if current_size < self._last_offset:
                    self._last_offset = 0
                    buffer = ""

                if current_size > self._last_offset:
                    with self.file_path.open("r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(self._last_offset)
                        chunk = fh.read()
                        self._last_offset = fh.tell()

                    buffer += chunk
                    lines = buffer.split("\n")

                    # Keep incomplete trailing line in buffer
                    buffer = lines.pop()

                    for line in lines:
                        line_str = line.strip()
                        if not line_str:
                            continue
                        self._process_line(line_str)

            except Exception as exc:  # noqa: BLE001
                logger.warning("Error reading JSONL file %s: %s", self.file_path, exc)

            time.sleep(self.poll_interval_s)

        self._running = False

    def _process_line(self, line: str) -> None:
        """Parse single JSON line and submit to worker."""
        try:
            data = json.loads(line)
            if not isinstance(data, dict):
                logger.warning("Skipping JSONL line (not a dict): %r", line[:100])
                self._lines_failed += 1
                return

            self.worker.submit_event(data, source_tag="jsonl")
            self._lines_processed += 1
        except json.JSONDecodeError as exc:
            logger.warning("Skipping malformed JSON line: %s (error: %s)", line[:100], exc)
            self._lines_failed += 1
