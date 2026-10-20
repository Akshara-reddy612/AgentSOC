"""
Investigate WHY T1071 is almost always FEASIBLE.
Check which zones have outbound EGRESS on port 443/80.
"""
import sys
sys.path.insert(0, ".")

from perception.knowledge_graph import KnowledgeStoreGraph
from perception.knowledge_store import KnowledgeFact

gs = KnowledgeStoreGraph()
g = gs.graph

# Find all EGRESS edges
print("ALL EGRESS EDGES IN THE GRAPH:")
print("=" * 80)
egress_count = 0
for u, v, data in g.edges(data=True):
    if data.get("edge_type") == "EGRESS":
        egress_count += 1
        port_fact = data.get("port")
        port_val = port_fact.value if isinstance(port_fact, KnowledgeFact) else port_fact
        reach = data.get("reachable")
        conf = reach.confidence if isinstance(reach, KnowledgeFact) else 1.0
        print(f"  {u} --[EGRESS port={port_val} conf={conf}]--> {v}")

print(f"\nTotal EGRESS edges: {egress_count}")

# Find all zones
print("\n\nALL ZONES:")
zones = [n for n in g.nodes if "zone:" in str(n).lower() or g.nodes[n].get("node_type") == "ZoneNode"]
for z in sorted(zones):
    print(f"  {z}")

# Check which zones have port 443/80 egress
print("\n\nZONES WITH OUTBOUND 443/80 EGRESS:")
zones_with_web_egress = set()
for u, v, data in g.edges(data=True):
    if data.get("edge_type") == "EGRESS":
        port_fact = data.get("port")
        port_val = port_fact.value if isinstance(port_fact, KnowledgeFact) else port_fact
        if port_val in (443, 80):
            zones_with_web_egress.add(u)
            print(f"  {u} --> {v} (port={port_val})")

# Check: which hosts are in zones with web egress?
print("\n\nHOSTS IN ZONES WITH WEB EGRESS:")
for zone in sorted(zones_with_web_egress):
    hosts_in_zone = []
    for n in g.nodes:
        zone_for_n = gs.get_host_zone(n)
        if zone_for_n == zone:
            hosts_in_zone.append(n)
    print(f"  Zone {zone}: {len(hosts_in_zone)} hosts")
    for h in sorted(hosts_in_zone)[:10]:
        print(f"    {h}")
    if len(hosts_in_zone) > 10:
        print(f"    ... and {len(hosts_in_zone)-10} more")

# Test: does lazy node creation put new hosts in a zone with web egress?
print("\n\nLAZY NODE CREATION TEST:")
test_hosts = ["NONEXISTENT-HOST", "185.53.192.8", "LT-6633-CORP", "unknown"]
for h in test_hosts:
    node = gs.get_or_create_host_node(h)
    zone = gs.get_host_zone(node)
    print(f"  {h} -> node={node}, zone={zone}")
    # Check if this zone has 443/80 egress
    has_egress = zone in zones_with_web_egress if zone else False
    print(f"    Zone has web egress: {has_egress}")
