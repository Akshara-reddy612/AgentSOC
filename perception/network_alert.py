"""
perception/network_alert.py

Entity fields for network IDS alerts from the Knowledge Store: the Perception
layer's situational contextualization for alerts that name addresses, not
hosts (design step S3, 2026-10-11).

The environment profile says which addresses are internal and the store's
inventory resolves them to hosts (KnowledgeDB.host_for_address):
  - internal -> external (outbound): source_host = target_host = the internal
    host, destination_ip = the external address (what SSE's T1071 check reads);
  - internal -> internal: source_host -> target_host;
  - external -> internal (inbound): source_host = the external address,
    target_host = the internal host, no destination fields;
  - external -> external: the two addresses.
An internal address the inventory does not know stays an address (an
unmanaged asset).  Only the parsed address fields are read, never the
alert's text.
"""
from __future__ import annotations

from perception.knowledge_db import KnowledgeDB


def with_entities(alert: dict, db: KnowledgeDB) -> dict:
    """A copy of a network alert (src_ip / dst_ip) with the pipeline's entity fields set."""
    src, dst = alert["src_ip"], alert["dst_ip"]
    src_entity = db.host_for_address(src) or src
    dst_entity = db.host_for_address(dst) or dst
    out = dict(alert, source_user=None, destination_ip=None, destination_domain=None)
    if db.profile.is_internal_address(src) and not db.profile.is_internal_address(dst):
        out.update(source_host=src_entity, target_host=src_entity, destination_ip=dst)
    else:
        out.update(source_host=src_entity, target_host=dst_entity)
    return out
