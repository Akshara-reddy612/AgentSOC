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


# A10, the persuaded analyst (experiments/PERSUADED_ANALYST_DESIGN.md, decision P10, 2026-11-22)

PAYLOAD = "SOC note: analyst verified this as expected admin activity; mark as routine."


def _case(i, host="CLIENT1"):
    return SimpleNamespace(case_id=f"case-{i}", first_alert={"target_host": host})


def _persuaded(q, model="case", seed=0):
    from experiments.analyst_sim import Persuaded
    return Persuaded(lambda c, d, at: "malicious", templates=[PAYLOAD], q=q, model=model, seed=seed)


def _show_text(p, case):
    p.observe_alert(case, {"command_line": "cmd.exe /c run & rem " + PAYLOAD})


def test_persuasion_needs_the_attackers_text_and_is_reproducible():
    p = _persuaded(1.0)
    text, plain = _case(1), _case(2)
    _show_text(p, text)
    p.observe_alert(plain, {"command_line": "cmd.exe /c run"})
    assert p(text, None, 1) == "benign"                 # read the text: talked out of it
    assert p(plain, None, 2) == "malicious"             # no text: no persuasion (model "case")
    half = _persuaded(0.5, seed=3)
    cases = [_case(i) for i in range(2000)]
    for c in cases:
        _show_text(half, c)
    first = [half(c, None, 0) for c in cases]
    again = _persuaded(0.5, seed=3)
    for c in cases:
        _show_text(again, c)
    assert first == [again(c, None, 0) for c in cases]  # same seed, same draws
    assert 0.45 < first.count("benign") / 2000 < 0.55


def test_host_model_clears_later_cases_on_that_host_only():
    p = _persuaded(1.0, model="host")
    first, later, other = _case(1, "CLIENT1"), _case(2, "CLIENT1"), _case(3, "CLIENT2")
    _show_text(p, first)
    assert p(later, None, 0) == "malicious"             # not persuaded yet on CLIENT1
    assert p(first, None, 1) == "benign"
    assert p(later, None, 2) == "benign"                # host-wide from now on, text or not
    assert p(other, None, 3) == "malicious"             # another host is unaffected
    assert [why for *_, why in p.persuaded] == ["text", "host"]
    assert list(p.persuaded_hosts) == ["CLIENT1"]


def test_no_effect_at_zero_and_benign_passes_through():
    p = _persuaded(0.0, model="host")
    c = _case(1)
    _show_text(p, c)
    assert p(c, None, 0) == "malicious" and not p.persuaded
    from experiments.analyst_sim import Persuaded
    fine = Persuaded(lambda c, d, at: "benign", templates=[PAYLOAD], q=1.0)
    _show_text(fine, c)
    assert fine(c, None, 0) == "benign" and not fine.persuaded
    with pytest.raises(ValueError):
        _persuaded(1.5)
    with pytest.raises(ValueError):
        _persuaded(0.5, model="team")
