"""Analyst review loop, step 6 (2026-10-11): the simulated analyst's reproducible mistakes."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from experiments.analyst_sim import noisy


def _cases(n):
    return [SimpleNamespace(case_id=f"case-{i}") for i in range(n)]


def test_mistakes_are_reproducible_and_near_the_rate():
    always_bad = noisy(lambda c, d, at: "malicious", miss=0.2, seed=7)
    first = [always_bad(c, None, None) for c in _cases(2000)]
    assert first == [always_bad(c, None, None) for c in _cases(2000)]            # same case, same draw
    assert 0.17 < first.count("benign") / 2000 < 0.23
    other_seed = noisy(lambda c, d, at: "malicious", miss=0.2, seed=8)
    assert first != [other_seed(c, None, None) for c in _cases(2000)]


def test_false_alarms_and_pass_through():
    always_fine = noisy(lambda c, d, at: "benign", false_alarm=0.05, seed=1)
    verdicts = [always_fine(c, None, None) for c in _cases(4000)]
    assert 0.035 < verdicts.count("malicious") / 4000 < 0.065
    silent = noisy(lambda c, d, at: None, miss=1.0, false_alarm=1.0)
    assert silent(_cases(1)[0], None, None) is None                              # no verdict stays no verdict
    exact = noisy(lambda c, d, at: "malicious")
    assert exact(_cases(1)[0], None, None) == "malicious"
    with pytest.raises(ValueError):
        noisy(lambda c, d, at: "benign", miss=1.5)
