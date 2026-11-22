"""Checklist A3 flooding: junk events are novel, unlabelled, on the attacker's footholds, and in time order."""
import pytest

from experiments.dedale_flood import FLOOD_END, FOOTHOLDS, RID_BASE, flood
from perception.host_detection import DETECTORS


def test_flood_is_in_order_on_footholds_and_unlabelled():
    f = flood(5)
    assert [t for t, _ in f] == sorted(t for t, _ in f)
    starts = dict(FOOTHOLDS)
    assert all(starts[e["host"]] < t < FLOOD_END and e["rid"] <= RID_BASE for t, e in f)


def test_every_flood_event_has_its_own_lineage_key():
    f = flood(5)
    keys = {DETECTORS["lineage"].key(e) for _, e in f}
    assert None not in keys and len(keys) == len(f)


def test_rate_must_be_positive():
    with pytest.raises(ValueError):
        flood(0)
