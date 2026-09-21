"""
monitoring/sources/api_source.py

Localhost-only HTTP API ingestion server for the real-time monitoring layer.

Uses Python standard library `http.server.ThreadingHTTPServer` bound strictly to
`127.0.0.1:8765`. Zero external web server dependencies (no FastAPI, Flask, etc.).

Features & Invariants:
  - Localhost binding: strictly `127.0.0.1` (never `0.0.0.0`).
  - Payload size cap: max 64 KB (65536 bytes). Excess returns 413 Payload Too Large.
  - Rerun safety: process-wide singleton guard prevents port rebound errors
    ("Address already in use") when Streamlit reruns or start() is called repeatedly.
  - Endpoint `POST /api/events`: parses JSON alert dict, submits to MonitoringWorker,
    returns 202 Accepted.
  - Endpoint `GET /api/health`: returns 200 OK.
  - Invalid JSON / non-dict payload returns 400 Bad Request.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from monitoring.worker import MonitoringWorker, get_monitoring_worker

logger = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES = 65536  # 64 KB cap
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


class _APIRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for API ingestion."""

    # Disable default stdout logging for each request
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def _send_json(self, status: int, data: dict) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/health":
            self._send_json(HTTPStatus.OK, {"status": "ok", "service": "AgentSOC Monitoring API"})
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not Found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/events":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not Found"})
            return

        # Check Content-Length header
        content_length_str = self.headers.get("Content-Length")
        if not content_length_str:
            self._send_json(HTTPStatus.LENGTH_REQUIRED, {"error": "Length Required"})
            return

        try:
            content_length = int(content_length_str)
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid Content-Length"})
            return

        if content_length > MAX_PAYLOAD_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": f"Payload exceeds maximum size of {MAX_PAYLOAD_BYTES} bytes"},
            )
            return

        # Read body
        try:
            body_bytes = self.rfile.read(content_length)
            payload = json.loads(body_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON payload: {exc}"})
            return

        if not isinstance(payload, dict):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "JSON payload must be an object/dict"},
            )
            return

        # Submit to worker
        worker: MonitoringWorker = getattr(self.server, "monitoring_worker", get_monitoring_worker())
        record = worker.submit_event(payload, source_tag="api")

        self._send_json(
            HTTPStatus.ACCEPTED,
            {
                "status": "accepted",
                "event_id": record.event_id,
                "correlation_id": record.correlation_id,
            },
        )


class APISource:
    """
    Localhost-only HTTP server for submitting events over HTTP POST.
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        worker: MonitoringWorker | None = None,
    ) -> None:
        self.host: str = host
        self.port: int = port
        self.worker: MonitoringWorker = worker if worker is not None else get_monitoring_worker()

        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> bool:
        """
        Start the HTTP server thread.

        Returns True if newly started, False if already running (rerun guard).
        """
        if self._running and self._server is not None:
            return False

        if not self.worker.is_running:
            self.worker.start()

        # Check if port is already in use
        if _is_port_in_use(self.host, self.port):
            logger.info("APISource port %s:%s already in use; skipping bind", self.host, self.port)
            self._running = True
            return False

        try:
            server = ThreadingHTTPServer((self.host, self.port), _APIRequestHandler)
            server.monitoring_worker = self.worker  # type: ignore[attr-defined]
            self._server = server
        except OSError as exc:
            logger.warning("Could not bind APISource to %s:%s: %s", self.host, self.port, exc)
            return False

        self._running = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="APISourceThread",
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        """Shutdown the HTTP server."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self._running = False
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    @property
    def is_running(self) -> bool:
        return self._running


def _is_port_in_use(host: str, port: int) -> bool:
    """Check if a local socket port is currently listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        return s.connect_ex((host, port)) == 0


# Singleton server guard
_API_SERVER_INSTANCE: APISource | None = None
_API_LOCK = threading.Lock()


def get_api_source(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> APISource:
    """Get or create the process-wide APISource singleton."""
    global _API_SERVER_INSTANCE
    if _API_SERVER_INSTANCE is None:
        with _API_LOCK:
            if _API_SERVER_INSTANCE is None:
                _API_SERVER_INSTANCE = APISource(host=host, port=port)
    return _API_SERVER_INSTANCE
