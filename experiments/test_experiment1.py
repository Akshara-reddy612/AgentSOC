"""
experiments/test_experiment1.py

Pre-flight tests for Experiment 1:
1. Wilson CI against a known value
2. Exact McNemar on a hand-computed table
3. Shared graph is not mutated across SSE.check() calls
"""
from __future__ import annotations
import pytest
import sys
sys.path.insert(0, ".")

from experiments.metrics import wilson_ci, exact_mcnemar


# ── Wilson CI known-value test ──────────────────────────────────────────────

class TestWilsonCI:
    def test_known_value(self):
        """Wilson CI for 30/100 should contain 0.30 and match hand-computed bounds."""
        ci = wilson_ci(30, 100)
        assert ci.successes == 30
        assert ci.total == 100
        assert abs(ci.proportion - 0.30) < 1e-10
        # Hand-computed Wilson 95% for p=0.30, n=100:
        # centre = (0.30 + 1.96^2/(200)) / (1 + 1.96^2/100)
        #        = (0.30 + 0.019208) / (1 + 0.038416)
        #        = 0.319208 / 1.038416 = 0.30741
        # spread = (1.96/1.038416) * sqrt(0.30*0.70/100 + 1.96^2/40000)
        #        = 1.887478 * sqrt(0.0021 + 0.00009604)
        #        = 1.887478 * sqrt(0.00219604)
        #        = 1.887478 * 0.046863 = 0.08845
        # lower = 0.30741 - 0.08845 = 0.2190
        # upper = 0.30741 + 0.08845 = 0.3959
        assert 0.21 < ci.lower < 0.23, f"lower={ci.lower}"
        assert 0.38 < ci.upper < 0.40, f"upper={ci.upper}"

    def test_zero(self):
        """Wilson CI for 0/50."""
        ci = wilson_ci(0, 50)
        assert ci.proportion == 0.0
        assert ci.lower == 0.0
        assert ci.upper > 0.0  # Should not be exactly 0

    def test_all(self):
        """Wilson CI for 50/50."""
        ci = wilson_ci(50, 50)
        assert ci.proportion == 1.0
        assert ci.upper == 1.0
        assert ci.lower < 1.0

    def test_empty(self):
        ci = wilson_ci(0, 0)
        assert ci.proportion == 0.0


# ── Exact McNemar hand-computed test ────────────────────────────────────────

class TestMcNemar:
    def test_hand_computed(self):
        """McNemar on a=50, b=5, c=15, d=30.
        Discordant = 20, k=min(5,15)=5.
        P(X<=5) under Binom(20, 0.5) = sum_{i=0}^{5} C(20,i) / 2^20
        = (1+20+190+1140+4845+15504) / 1048576
        = 21700 / 1048576 = 0.020695
        p_two_sided = 2 * 0.020695 = 0.041389
        """
        result = exact_mcnemar(a=50, b=5, c=15, d=30)
        assert result.b == 5
        assert result.c == 15
        assert result.n == 100
        # Check p-value against hand computation
        assert abs(result.p_value - 0.04139) < 0.001, f"p={result.p_value}"

    def test_symmetric(self):
        """When b == c, p-value should be 1.0."""
        result = exact_mcnemar(a=40, b=10, c=10, d=40)
        assert result.p_value == 1.0

    def test_no_discordant(self):
        """When b == c == 0, p-value should be 1.0."""
        result = exact_mcnemar(a=50, b=0, c=0, d=50)
        assert result.p_value == 1.0


# ── Graph non-mutation test ─────────────────────────────────────────────────

class TestGraphNonMutation:
    def test_sse_check_does_not_mutate_graph(self):
        """SSE.check() must NOT add/remove nodes or edges."""
        from perception.knowledge_graph import KnowledgeStoreGraph
        from perception.sse import StructuralSimulationEngine

        kg = KnowledgeStoreGraph()
        sse = StructuralSimulationEngine(kg)

        nodes_before = set(kg.graph.nodes)
        edges_before = set((u, v, k) for u, v, k in kg.graph.edges(keys=True))

        # Run a variety of checks with GUIDE-like hostnames
        test_cases = [
            ("jsmith", "WKSTN-7363", "SRV-FILE8632", "T1078"),
            ("svc_backup", "LT-3357-CORP", "server-db01", "T1550"),
            ("m.chen", "unknown", "185.220.101.5", "T1071"),
            ("a.patel", "WKSTN-2234", "WKSTN-2234", "T1484"),
            ("helpdesk_admin", "LT-2983-CORP", "server-dc01", "T1562"),
        ]
        for acct, src, tgt, tech in test_cases:
            sse.check(acct, src, tgt, tech)

        nodes_after = set(kg.graph.nodes)
        edges_after = set((u, v, k) for u, v, k in kg.graph.edges(keys=True))

        assert nodes_before == nodes_after, (
            f"Nodes changed: added={nodes_after - nodes_before}, "
            f"removed={nodes_before - nodes_after}"
        )
        assert edges_before == edges_after, (
            f"Edges changed: added={edges_after - edges_before}, "
            f"removed={edges_before - edges_after}"
        )
