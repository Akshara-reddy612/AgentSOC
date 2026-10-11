"""
dedale/environment.py

DEDALE's environment as its operator would know it (CMDB / network plan): the
address ranges, zones and company hosts of the RESCOUSSE testbed, from its
documentation (dedale.inria.fr/rescousse.html; recorded in
experiments/DEDALE_DATA_NOTES.md).  Design step S3.

Not in here (design invariant I4): the attacker's machines or anything else
from the attack scenario, the timeline or the labels.  The external zone
(172.19.0.0/16: simulated internet clients, remote employees' home machines,
an SMTP server and the attacker) and the internet router network
(172.18.0.0/16) are simply "external".

Where the documentation is silent, these are ASSUMPTIONS, not facts:
  - Egress: the testbed is connected to the internet and documents no egress
    filtering, so the company zones use egress mode "open".
  - Internal reachability: no firewall rules between company zones are
    documented; they are modelled as reachable (EGRESS 445/3389/443/80) with
    confidence 0.8 instead of 1.0.
  - Client addresses: client i has 172.16.1.(i+1) (documented range
    172.16.1.2-.254, numbered from the first address); confidence 0.9 until
    checked against the Windows logs' own addresses.
  - 30 internal Windows clients, one per AURA user-behaviour log
    (internal_company_client_windows_1..30).
  - Criticality tiers: domain controller 3; log, mail and VPN servers and
    routers 2; web server 1; clients 0.
Host ids are the names the logs use (Windows agent names CLIENTn, the Linux
server "internalserver", the routers' syslog names); the other servers'
names are not in the data seen so far.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from perception.environment import EnvironmentProfile
from perception.knowledge_db import KnowledgeDB
from perception.knowledge_graph import HostClass, host_node_id, zone_node_id
from perception.knowledge_store import KnowledgeFact
from perception.source_systems import SourceSystem

COMPANY_ZONES = ("CLIENTS", "SERVERS", "DMZ", "NETWORK")
OPEN = {"mode": "open"}

DEDALE_PROFILE = EnvironmentProfile(
    name="DEDALE (RESCOUSSE testbed)",
    internal_networks=("172.16.0.0/16", "172.17.0.0/16", "10.8.0.0/16", "127.0.0.0/8", "169.254.0.0/16"),
    internal_domain_suffixes=(".breach.local",),
    internal_hostname_pattern=r"^(CLIENT\d+|internalserver|logserver|dmzserver|webserver|vpnserver|companyrouter2?)$",
    zone_egress_policy={zone: OPEN for zone in COMPANY_ZONES},
)


@dataclass(frozen=True)
class InventoryHost:
    host_id: str
    host_class: HostClass
    criticality_tier: int
    zone: str
    addresses: tuple[str, ...]
    services: tuple[str, ...] = ()
    address_confidence: float = 1.0


INVENTORY: tuple[InventoryHost, ...] = (
    *(InventoryHost(f"CLIENT{i}", HostClass.WORKSTATION, 0, "CLIENTS", (f"172.16.1.{i + 1}",),
                    address_confidence=0.9) for i in range(1, 31)),
    InventoryHost("internalserver", HostClass.DOMAIN_CONTROLLER, 3, "SERVERS", ("172.16.0.2",), ("SMB",)),
    InventoryHost("logserver", HostClass.LOG_SERVER, 2, "SERVERS", ("172.16.0.3",), ("HTTP",)),
    InventoryHost("dmzserver", HostClass.MAIL_SERVER, 2, "DMZ", ("172.17.0.2",), ("SMTP", "IMAP", "HTTP")),
    InventoryHost("webserver", HostClass.WEB_SERVER, 1, "DMZ", ("172.17.0.3",), ("HTTP", "HTTPS")),
    InventoryHost("vpnserver", HostClass.VPN_GATEWAY, 2, "DMZ", ("172.17.0.5",), ("VPN",)),
    InventoryHost("companyrouter", HostClass.ROUTER, 2, "NETWORK", ("172.16.255.1",)),
    InventoryHost("companyrouter2", HostClass.ROUTER, 2, "NETWORK", ("172.16.0.1", "172.16.1.1", "172.16.255.2")),
)

_INTERNAL_PORTS = ((445, "SMB"), (3389, "RDP"), (443, "HTTPS"), (80, "HTTP"))
_INTERNET_PORTS = ((443, "HTTPS"), (80, "HTTP"))
_WRITER = "config:dedale"


def _fact(value, at: datetime, confidence: float = 1.0) -> KnowledgeFact:
    return KnowledgeFact(value=value, version=1, confidence=confidence, source=SourceSystem.KNOWLEDGE_STORE,
                         timestamp=at)


def seed_store(db: KnowledgeDB, at: datetime) -> None:
    """Write DEDALE's zones, hosts and zone reachability into a store created with DEDALE_PROFILE."""
    if db.profile.to_dict() != DEDALE_PROFILE.to_dict():
        raise ValueError("seed_store needs a store created with DEDALE_PROFILE")
    with db.batch():
        for zone in (*COMPANY_ZONES, "EXTERNAL"):
            attrs = {"node_type": "ZoneNode", "zone_id": zone, "security_zone": zone}
            if zone in db.profile.zone_egress_policy:
                attrs["egress_policy"] = _fact(dict(db.profile.zone_egress_policy[zone]), at)
            db.add_node(zone_node_id(zone), attrs, writer=_WRITER, at=at, learned_from="config")
        for h in INVENTORY:
            node = host_node_id(h.host_id)
            db.add_node(node, {
                "node_type": "HostNode", "host_id": h.host_id,
                "host_class": _fact(h.host_class, at), "criticality_tier": _fact(h.criticality_tier, at),
                "zone_id": _fact(h.zone, at), "exposed_services": _fact(list(h.services), at),
                "ip_addresses": _fact(list(h.addresses), at, h.address_confidence), "first_seen": at,
            }, writer=_WRITER, at=at, learned_from="config")
            db.add_edge(node, zone_node_id(h.zone), "HOSTED_IN", {"edge_type": "HOSTED_IN"},
                        writer=_WRITER, at=at, learned_from="config")
        for src in COMPANY_ZONES:
            for dst, ports, confidence in ([(z, _INTERNAL_PORTS, 0.8) for z in COMPANY_ZONES]
                                           + [("EXTERNAL", _INTERNET_PORTS, 1.0)]):
                for port, protocol in ports:
                    db.add_edge(zone_node_id(src), zone_node_id(dst), f"EGRESS:{port}", {
                        "edge_type": "EGRESS", "port": _fact(port, at, confidence),
                        "protocol": _fact(protocol, at, confidence), "reachable": _fact(True, at, confidence),
                    }, writer=_WRITER, at=at, learned_from="config")
