"""
perception/case_builder.py

Case builder: noise reduction with memory (design step S4, 2026-10-11; see
experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md).

perception/noise_reducer.py clusters the incidents of one batch.  A live
stream needs memory across time: alerts with the same key join the case that
is already open instead of being triaged again, so the pipeline (and NCE)
runs once per case, not once per alert.

  - Key: structured fields only (for network alerts: signature id, source and
    destination address).  Free text never enters the key, so text variations
    cannot split a case (same rule as NoiseReducer).
  - A case closes when no alert has joined it for `idle` time, or at the first
    alert after it has been open for `max_duration`; that alert opens a new case,
    so a pattern that never stops is re-examined once per `max_duration`
    (against a store that may have learned something since).
  - Time is the alerts' own time (replay-safe); the caller feeds alerts in time
    order.  Closing idle cases costs O(1) per alert.
The two windows are open design decision D3 (to be tuned on the training
window only); the defaults are the initial choice.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Hashable

IDLE = timedelta(hours=1)
MAX_DURATION = timedelta(hours=24)


def network_case_key(alert: dict) -> tuple:
    return (alert["signature_id"], alert["src_ip"], alert["dst_ip"])


def alert_case_key(alert: dict) -> tuple:
    """Network alerts: signature + addresses.  Host alerts (Phase 2): detector + its structured key."""
    if alert.get("kind") == "host":
        return ("host", alert["detector"], *alert["detector_key"])
    return network_case_key(alert)


@dataclass
class Case:
    case_id: str
    key: tuple
    opened: datetime
    last_seen: datetime
    first_alert: dict
    alert_count: int = 1
    sensors: set[str] = field(default_factory=set)
    closed: datetime | None = None
    close_reason: str | None = None        # "idle" | "max_duration" | "end_of_stream" (or a caller's reason)


class CaseBuilder:
    """Groups a time-ordered alert stream into cases (see module docstring)."""

    def __init__(self, idle: timedelta = IDLE, max_duration: timedelta = MAX_DURATION,
                 key: Callable[[dict], Hashable] = network_case_key) -> None:
        self.idle = idle
        self.max_duration = max_duration
        self._key = key
        self._open: OrderedDict[Hashable, Case] = OrderedDict()   # least recently seen first
        self._next_id = 1
        self._clock: datetime | None = None

    @property
    def open_cases(self) -> list[Case]:
        return list(self._open.values())

    def add(self, alert: dict, at: datetime) -> tuple[list[Case], str, Case]:
        """
        One alert at time `at`.  Returns (cases closed by this step, "opened" or
        "attached", the alert's case).
        """
        if self._clock is not None and at < self._clock:
            raise ValueError(f"alerts must arrive in time order ({at} < {self._clock})")
        self._clock = at
        closed = self._close_idle(at)
        k = self._key(alert)
        case = self._open.get(k)
        if case is not None and at - case.opened >= self.max_duration:
            closed.append(self._close(k, at, "max_duration"))
            case = None
        if case is None:
            case = Case(case_id=f"case-{self._next_id}", key=tuple(k) if isinstance(k, tuple) else (k,),
                        opened=at, last_seen=at, first_alert=alert)
            self._next_id += 1
            self._open[k] = case
            event = "opened"
        else:
            case.alert_count += 1
            case.last_seen = at
            self._open.move_to_end(k)
            event = "attached"
        if alert.get("sensor"):
            case.sensors.add(alert["sensor"])
        return closed, event, case

    def close_all(self, at: datetime, reason: str = "end_of_stream") -> list[Case]:
        """Close every open case (end of the stream, or a boundary such as the end of a training window)."""
        return [self._close(k, at, reason) for k in list(self._open)]

    def _close_idle(self, now: datetime) -> list[Case]:
        closed = []
        while self._open:
            k, case = next(iter(self._open.items()))
            if now - case.last_seen < self.idle:
                break
            closed.append(self._close(k, case.last_seen + self.idle, "idle"))
        return closed

    def _close(self, k: Hashable, at: datetime, reason: str) -> Case:
        case = self._open.pop(k)
        case.closed, case.close_reason = at, reason
        return case
