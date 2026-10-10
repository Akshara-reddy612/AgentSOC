"""
experiments/metrics.py

Wilson 95% CI and exact McNemar's test for paired binary data.
"""
from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class WilsonCI:
    """Wilson score interval for a binomial proportion."""
    successes: int
    total: int
    proportion: float
    lower: float
    upper: float

    def __str__(self) -> str:
        return (
            f"{self.successes}/{self.total} = {self.proportion:.4f} "
            f"[{self.lower:.4f}, {self.upper:.4f}]"
        )


def wilson_ci(successes: int, total: int, z: float = 1.96) -> WilsonCI:
    """
    Compute Wilson score interval for proportion = successes/total.

    Parameters
    ----------
    successes : int
        Number of successes (0 <= successes <= total).
    total : int
        Total number of trials (> 0).
    z : float
        Z-score for the confidence level. Default 1.96 (95%).

    Returns
    -------
    WilsonCI with proportion, lower, upper bounds.
    """
    if total == 0:
        return WilsonCI(successes=0, total=0, proportion=0.0,
                        lower=0.0, upper=0.0)
    p_hat = successes / total
    z2 = z * z
    denom = 1 + z2 / total
    centre = (p_hat + z2 / (2 * total)) / denom
    spread = (z / denom) * math.sqrt(
        p_hat * (1 - p_hat) / total + z2 / (4 * total * total)
    )
    lower = max(0.0, centre - spread)
    upper = min(1.0, centre + spread)
    return WilsonCI(
        successes=successes,
        total=total,
        proportion=p_hat,
        lower=lower,
        upper=upper,
    )


@dataclass(frozen=True)
class McNemarResult:
    """Result of exact McNemar's test on a 2x2 discordant table."""
    b: int  # condition1=negative, condition2=positive
    c: int  # condition1=positive, condition2=negative
    a: int  # both negative
    d: int  # both positive
    n: int
    p_value: float

    def __str__(self) -> str:
        return (
            f"a={self.a} b={self.b} c={self.c} d={self.d} n={self.n} "
            f"discordant={self.b + self.c} p={self.p_value:.6f}"
        )


def exact_mcnemar(a: int, b: int, c: int, d: int) -> McNemarResult:
    """
    Exact McNemar's test using the binomial distribution.

    2x2 table:
                    Condition2=no_actionable  Condition2=actionable
    Cond1=no_act         a                        b
    Cond1=act            c                        d

    The test is on the discordant pair (b, c): under H0, b ~ Binom(b+c, 0.5).
    Two-sided p-value = 2 * min(P(X<=min(b,c)), 0.5).

    Parameters
    ----------
    a, b, c, d : int
        Counts in the 2x2 table.

    Returns
    -------
    McNemarResult with exact two-sided p-value.
    """
    from math import comb
    n_discord = b + c
    if n_discord == 0:
        return McNemarResult(b=b, c=c, a=a, d=d, n=a+b+c+d, p_value=1.0)

    # Two-sided exact binomial test
    k = min(b, c)
    # P(X <= k) under Binom(n_discord, 0.5)
    p_tail = sum(comb(n_discord, i) for i in range(k + 1)) / (2 ** n_discord)
    p_value = min(2.0 * p_tail, 1.0)

    return McNemarResult(
        b=b, c=c, a=a, d=d,
        n=a + b + c + d,
        p_value=p_value,
    )
