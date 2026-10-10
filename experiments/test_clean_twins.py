"""
experiments/test_clean_twins.py

Guards the paired corpus used by Experiment 1: the committed clean-twin file
must stay a true twin of the contaminated 320 (same alert, payload removed),
and the analysis must keep exactly the 206 pairs whose historical clean input
was genuinely clean.
"""
from __future__ import annotations

import json

from experiments.analyze_paired_valid import valid_pair_ids
from experiments.build_clean_twins import CONTAM_JSON, OUT_JSON, verify


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_committed_twins_verify_against_contaminated_corpus():
    twins, contam = _load(OUT_JSON), _load(CONTAM_JSON)
    assert len(twins) == len(contam) == 320
    assert verify(twins, contam) == []


def test_valid_pair_count_is_206():
    valid, invalid = valid_pair_ids()
    assert len(valid) == 206
    assert len(invalid) == 114
    assert sum("contaminated" in r for r in invalid.values()) == 108
