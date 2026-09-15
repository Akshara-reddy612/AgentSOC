"""Investigate edge creation during lazy host node creation."""
from perception.knowledge_graph import KnowledgeStoreGraph

kg = KnowledgeStoreGraph()
print(f"Initial nodes: {kg.graph.number_of_nodes()}")
print(f"Initial edges: {kg.graph.number_of_edges()}")

# Create a host node for an external IP
node_id = kg.get_or_create_host_node("185.41.181.108")
print(f"After create IP node: nodes={kg.graph.number_of_nodes()}, edges={kg.graph.number_of_edges()}")
print(f"Node: {node_id}")

# Check edges involving this node
for u, v, d in kg.graph.edges(data=True):
    if u == node_id or v == node_id:
        print(f"  Edge: {u} -> {v}, type={d.get('edge_type', '?')}")

# Create an account node too
acct_id = kg.get_or_create_account_node("helpdesk_admin")
print(f"After create account node: nodes={kg.graph.number_of_nodes()}, edges={kg.graph.number_of_edges()}")
for u, v, d in kg.graph.edges(data=True):
    if u == acct_id or v == acct_id:
        print(f"  Edge: {u} -> {v}, type={d.get('edge_type', '?')}")
