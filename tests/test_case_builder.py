"""Design step S4 (2026-10-11): case builder — noise reduction with memory across a time-ordered stream."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from perception.case_builder import CaseBuilder

T0 = datetime(2025, 1, 6, 10, 0, tzinfo=timezone.utc)
H = timedelta(hours=1)


def _a(sid=1, src="172.16.1.3", dst="172.16.0.3", sensor="companyrouter2", text="x"):
    return {"signature_id": sid, "src_ip": src, "dst_ip": dst, "sensor": sensor, "raw_log_line": text}


def test_same_key_attaches_other_key_opens():
    cb = CaseBuilder()
    _, e1, c1 = cb.add(_a(), T0)
    _, e2, c2 = cb.add(_a(text="different free text, same structured key"), T0 + timedelta(minutes=5))
    _, e3, c3 = cb.add(_a(dst="172.16.0.2"), T0 + timedelta(minutes=6))
    assert (e1, e2, e3) == ("opened", "attached", "opened")
    assert c1 is c2 and c1.alert_count == 2 and c1.last_seen == T0 + timedelta(minutes=5)
    assert c3 is not c1 and c3.case_id == "case-2"


def test_router_copies_join_one_case():
    cb = CaseBuilder()
    cb.add(_a(sensor="companyrouter"), T0)
    _, event, case = cb.add(_a(sensor="companyrouter2"), T0 + timedelta(seconds=3))
    assert event == "attached" and case.sensors == {"companyrouter", "companyrouter2"}


def test_idle_case_closes_at_idle_time_and_key_reopens():
    cb = CaseBuilder(idle=H)
    _, _, first = cb.add(_a(), T0)
    closed, event, second = cb.add(_a(), T0 + H + timedelta(seconds=1))
    assert closed == [first] and first.close_reason == "idle" and first.closed == T0 + H
    assert event == "opened" and second is not first


def test_other_keys_expire_while_the_stream_moves_on():
    cb = CaseBuilder(idle=H)
    _, _, a = cb.add(_a(sid=1), T0)
    _, _, b = cb.add(_a(sid=2), T0 + timedelta(minutes=30))
    closed, _, _ = cb.add(_a(sid=3), T0 + timedelta(minutes=80))       # a idle 80 min, b idle 50 min
    assert closed == [a] and [c.case_id for c in cb.open_cases] == [b.case_id, "case-3"]


def test_case_rolls_over_after_max_duration():
    cb = CaseBuilder(idle=H, max_duration=timedelta(hours=24))
    _, _, first = cb.add(_a(), T0)
    t = T0
    while t < T0 + timedelta(hours=23, minutes=30):
        t += timedelta(minutes=30)
        cb.add(_a(), t)
    closed, event, second = cb.add(_a(), T0 + timedelta(hours=24))
    assert closed == [first] and first.close_reason == "max_duration" and first.alert_count == 48
    assert event == "opened" and second.opened == T0 + timedelta(hours=24)


def test_time_order_is_enforced_and_end_closes_everything():
    cb = CaseBuilder()
    cb.add(_a(sid=1), T0)
    cb.add(_a(sid=2), T0 + timedelta(minutes=1))
    with pytest.raises(ValueError):
        cb.add(_a(), T0)
    closed = cb.close_all(T0 + timedelta(minutes=2))
    assert len(closed) == 2 and all(c.close_reason == "end_of_stream" for c in closed) and not cb.open_cases
