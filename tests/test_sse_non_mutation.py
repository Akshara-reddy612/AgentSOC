import pytest
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.sse import StructuralSimulationEngine, SSEVerdict

def test_sse_check_does_not_mutate_graph():
    """
    Assert that calling check() twice with an unseen external IP against the 
    same graph instance produces the SAME verdict both times, and assert the 
    graph's node count is unchanged after check() returns.
    """
    graph = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(graph)
    
    initial_node_count = len(graph.graph.nodes)
    
    # Run a T1071 check on an unseen external IP
    source_account = "helpdesk_admin"
    source_host = "WKSTN-04471"
    target_host = "1.2.3.4"
    technique_id = "T1071"
    
    res1 = sse.check(source_account, source_host, target_host, technique_id)
    node_count_after_first = len(graph.graph.nodes)
    
    res2 = sse.check(source_account, source_host, target_host, technique_id)
    node_count_after_second = len(graph.graph.nodes)
    
    def _best_verdict(results):
        if not results:
            return SSEVerdict.INFEASIBLE
        return max(results, key=lambda x: x.path_confidence).verdict
        
    assert _best_verdict(res1) == _best_verdict(res2), "Verdict changed on second call"
    
    assert initial_node_count == node_count_after_first, "Graph node count changed after first call"
    assert initial_node_count == node_count_after_second, "Graph node count changed after second call"
