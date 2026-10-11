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
