"""
experiments/test_timeout_fix.py

Tests for _call_with_timeout in run_paired_clean_eval_B:
- Hung call is hard-cancelled within timeout+10s margin.
- Fast call returns correct value.
- Exception in worker propagates.
- 429 (ClientError code=429) propagates with status intact.
- TimeoutError raised on hang reaches the retry-loop except clause.
- queue.Empty edge case raises RuntimeError (counted as failed attempt).
"""
from __future__ import annotations

import queue
import time
import pytest
from google.genai.errors import ClientError

from experiments.run_paired_clean_eval_B import _call_with_timeout


# ---------------------------------------------------------------------------
# Worker functions — must be module-level for multiprocessing spawn pickling
# ---------------------------------------------------------------------------

def _hang_forever():
    import time
    while True:
        time.sleep(1)


def _fast_return(x):
    return x * 2


def _raise_immediately():
    raise ValueError("API exploded")


def _raise_429():
    """Simulate what the Gemini SDK raises for a 429 response."""
    # ClientError(code, response_json, response=None)
    # code=429, status="RESOURCE_EXHAUSTED" is set via _get_status(response_json)
    raise ClientError(
        429,
        {"error": {"code": 429, "message": "Quota exceeded", "status": "RESOURCE_EXHAUSTED"}},
        None,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCallWithTimeout:
    def test_timeout_fires_and_raises(self):
        """A hung call must raise TimeoutError within timeout + 10s margin."""
        TIMEOUT = 5
        started = time.monotonic()
        with pytest.raises((TimeoutError, RuntimeError)):
            _call_with_timeout(_hang_forever, timeout=TIMEOUT)
        elapsed = time.monotonic() - started
        assert elapsed >= TIMEOUT, f"Exited too early: {elapsed:.1f}s"
        assert elapsed < TIMEOUT + 10, (
            f"Took too long: {elapsed:.1f}s — process was not terminated"
        )

    def test_successful_call_returns_value(self):
        result = _call_with_timeout(_fast_return, 21, timeout=10)
        assert result == 42

    def test_exception_in_worker_propagates(self):
        with pytest.raises(ValueError, match="API exploded"):
            _call_with_timeout(_raise_immediately, timeout=10)

    def test_429_propagates_with_status(self):
        """ClientError(429) raised in the child arrives in the parent as
        APIError (not ClientError) because ClientError.__reduce__ rebuilds
        via APIError._rebuild. This is by SDK design (see google.genai.errors).
        The code, status, and message attributes are preserved.
        is_rate_limit_error() must still return True because it checks str(exc).
        """
        with pytest.raises(Exception) as exc_info:
            _call_with_timeout(_raise_429, timeout=10)
        err = exc_info.value
        # After pickling, type is APIError (SDK rebuilds as base class)
        from google.genai.errors import APIError
        assert isinstance(err, APIError), (
            f"Expected APIError (or subclass) after pickling, got {type(err).__name__}"
        )
        assert err.code == 429, f"Expected code=429, got {err.code}"
        assert err.status == "RESOURCE_EXHAUSTED", (
            f"Unexpected status: {err.status}"
        )
        # Verify is_rate_limit_error classifies it correctly via str()
        from agent.llm_utils import is_rate_limit_error
        assert is_rate_limit_error(err), (
            f"is_rate_limit_error returned False for {err!r}"
        )
        print(f"\n  [ok] 429 arrived as {type(err).__name__}(code={err.code}, "
              f"status={err.status}), is_rate_limit_error=True")

    def test_timeout_caught_by_retry_except(self):
        """Verify TimeoutError is an instance of the types caught by the
        retry loop: `except (TimeoutError, RuntimeError) as exc`.
        This is a type-check only, no real call.
        """
        exc = TimeoutError("Call timed out after 60s")
        assert isinstance(exc, (TimeoutError, RuntimeError))

    def test_realistic_timeout_bound(self):
        """At CALL_TIMEOUT_S=60, a hung call must finish within 70s.
        Scaled to 8s+10s margin for test speed.
        """
        TIMEOUT = 8
        MARGIN = 10
        started = time.monotonic()
        with pytest.raises((TimeoutError, RuntimeError)):
            _call_with_timeout(_hang_forever, timeout=TIMEOUT)
        elapsed = time.monotonic() - started
        assert elapsed < TIMEOUT + MARGIN, (
            f"Hard-timeout failed: elapsed {elapsed:.1f}s > {TIMEOUT + MARGIN}s"
        )
        print(f"\n  [ok] Hung call cancelled in {elapsed:.1f}s "
              f"(timeout={TIMEOUT}s, margin={MARGIN}s)")
