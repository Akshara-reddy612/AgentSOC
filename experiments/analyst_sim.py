"""
experiments/analyst_sim.py

Simulated analyst variations for the review-loop evaluation (analyst review
loop, step 6, 2026-10-11): an analyst who makes mistakes.

`noisy(analyst, miss=..., false_alarm=..., seed=...)` wraps a simulated
analyst (e.g. the DEDALE oracle) so that a "malicious" verdict becomes
"benign" with probability `miss` and a "benign" verdict becomes "malicious"
with probability `false_alarm`.  The draw is a hash of (seed, case id), so a
case gets the same draw in every run and the runs are reproducible; changing
the seed gives an independent draw.  Scorer side only, like the oracle.
"""
from __future__ import annotations

import hashlib
from typing import Callable


def _u(seed: int, tag: str, case_id: str) -> float:
    """A reproducible uniform draw in [0, 1) for this case."""
    h = hashlib.sha256(f"{seed}:{tag}:{case_id}".encode("utf-8")).digest()
    return int.from_bytes(h[:8], "big") / 2**64


def noisy(analyst: Callable, *, miss: float = 0.0, false_alarm: float = 0.0, seed: int = 0) -> Callable:
    """The same analyst, wrong on a reproducible share of its verdicts (see module docstring)."""
    if not (0.0 <= miss <= 1.0 and 0.0 <= false_alarm <= 1.0):
        raise ValueError("miss and false_alarm are probabilities")

    def wrapped(case, decision, at):
        verdict = analyst(case, decision, at)
        if verdict == "malicious" and _u(seed, "miss", case.case_id) < miss:
            return "benign"
        if verdict == "benign" and _u(seed, "false_alarm", case.case_id) < false_alarm:
            return "malicious"
        return verdict

    return wrapped


PERSUASION_MODELS = ("case", "host")


class Persuaded:
    """
    A10 (`experiments/PERSUADED_ANALYST_DESIGN.md`, decision P10, 2026-11-22): an analyst whom the attacker's
    own text can talk out of a `malicious` verdict.  Scorer side, like the oracle it wraps.

    - A case "shows the attacker's text" when a command line among its alerts so far contains one of the
      payload `templates` (what the analyst reads in the case view).  Alerts arrive through `observe_alert`,
      the same hook the oracle uses.
    - model "case": a `malicious` verdict on such a case becomes `benign` with probability `q`
      (a reproducible draw per case, as in `noisy`).
    - model "host": as "case"; and once persuaded on a host, the analyst also clears every later
      `malicious` verdict on that host, text or not (the bound: the analyst accepts the story).
    With q = 0 it returns the wrapped analyst's verdict unchanged.
    """

    def __init__(self, analyst: Callable, *, templates, q: float, model: str = "case", seed: int = 0) -> None:
        if not 0.0 <= q <= 1.0:
            raise ValueError("q is a probability")
        if model not in PERSUASION_MODELS:
            raise ValueError(f"model must be one of {PERSUASION_MODELS}")
        self.analyst, self.templates, self.q, self.model, self.seed = analyst, tuple(templates), q, model, seed
        self._text_cases: set[str] = set()
        self.persuaded_hosts: dict[str, object] = {}           # host -> time of the first persuasion
        self.persuaded: list[tuple[str, str, object, str]] = []  # (case id, host, time, "text" | "host")

    def observe_alert(self, case, alert: dict) -> None:
        cmd = alert.get("command_line") or ""
        if cmd and any(t in cmd for t in self.templates):
            self._text_cases.add(case.case_id)

    def __call__(self, case, decision, at):
        verdict = self.analyst(case, decision, at)
        if verdict != "malicious" or self.q <= 0.0:
            return verdict
        host = str(case.first_alert.get("target_host") or "")
        if self.model == "host" and host in self.persuaded_hosts:
            self.persuaded.append((case.case_id, host, at, "host"))
            return "benign"
        if case.case_id in self._text_cases and _u(self.seed, "persuade", case.case_id) < self.q:
            self.persuaded_hosts.setdefault(host, at)
            self.persuaded.append((case.case_id, host, at, "text"))
            return "benign"
        return verdict
