"""
Regression test (2026-10-10): SSE.check() must return each structurally
distinct path once.  networkx.all_simple_paths yields the same node path once
per parallel edge on a MultiDiGraph, which previously duplicated PathResults
and inflated RSEM containment.
"""
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.sse import StructuralSimulationEngine


def _paths(results):
    return [tuple(r.edge_path) for r in results]


def test_parallel_edges_do_not_duplicate_paths():
    sse = StructuralSimulationEngine(KnowledgeStoreGraph())
    # svc_backup -> server-db01 has two parallel edges: HAS_PRIOR_ACCESS and GRANTS:ADMIN.
    t1078 = _paths(sse.check("svc_backup", "workstation-01", "server-db01", "T1078"))
    assert len(t1078) == 2
    assert len(set(t1078)) == 2
    t1550 = _paths(sse.check("svc_backup", "workstation-01", "server-db01", "T1550"))
    assert len(t1550) == 1


def test_no_duplicate_paths_for_any_seeded_pair():
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    accounts = ["alice", "bob", "charlie", "mallory", "svc_backup"]
    hosts = ["workstation-01", "workstation-02", "server-db01", "server-dc01", "server-web01", "WKSTN-9998"]
    techniques = ["T1078", "T1021.001", "T1021.002", "T1550", "T1484", "T1562"]
    for a in accounts:
        for h in hosts:
            for t in techniques:
                paths = _paths(sse.check(a, "workstation-01", h, t))
                assert len(paths) == len(set(paths)), (a, h, t, paths)
