"""
Handover (2026-10-20): the demo server reads everything dataset-specific from
soc_server/datasets.py; DEDALE is registered.  Building the entry loads no data.
"""
from __future__ import annotations

import pytest

from soc_server.datasets import DATASETS, Dataset, load


def test_dedale_is_registered_and_consistent():
    assert "dedale" in DATASETS
    ds = load("dedale")
    assert isinstance(ds, Dataset) and ds.label == "DEDALE"
    assert ds.training_start < ds.training_end <= ds.demo_start
    assert set(ds.sources) == {"host", "network"}
    assert set(ds.injections) == {"suppress", "fake_approval", "steer"} and ds.injector and ds.injection_cache
    assert ds.comparison is not None and ds.comparison.exists()
    assert set(ds.comparison_runs) >= {"no learning (static)", "learning behind the gate"}


def test_unknown_dataset_is_refused():
    with pytest.raises(SystemExit):
        load("nope")
