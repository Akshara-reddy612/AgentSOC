"""
perception/knowledge_graph.py

NetworkX-backed Knowledge Store Graph for the Structural Simulation Engine.

Wraps a networkx.MultiDiGraph with typed nodes (HostNode, AccountNode,
ZoneNode, GroupNode, ServiceNode) and typed edges (GRANTS, EGRESS,
HOSTED_IN, HAS_PRIOR_ACCESS, DEPENDS_ON, MEMBER_OF).

Every fact-bearing attribute is wrapped in the existing KnowledgeFact
dataclass from perception.knowledge_store — this module reuses, never
reinvents, that dataclass.

The graph is seeded from InMemoryKnowledgeStore's existing toy data
(lossless migration) and supports lazy node creation for dynamically
encountered hostnames from GUIDE alert data.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any

import networkx as nx

from perception.knowledge_store import InMemoryKnowledgeStore, KnowledgeFact
from perception.source_systems import SourceSystem


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class HostClass(Enum):
    """Classification of a host's functional role in the enterprise."""
    WORKSTATION = "WORKSTATION"
    FILE_SERVER = "FILE_SERVER"
    LAPTOP_CORP = "LAPTOP_CORP"
    DOMAIN_CONTROLLER = "DOMAIN_CONTROLLER"
    DB_SERVER = "DB_SERVER"
    UNKNOWN = "UNKNOWN"


class AccountType(Enum):
    """Classification of an account's privilege category."""
    STANDARD_USER = "STANDARD_USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    LOCAL_ADMIN = "LOCAL_ADMIN"
    DOMAIN_ADMIN = "DOMAIN_ADMIN"


class AccessLevel(IntEnum):
    """
    Ordered access levels for >= comparisons in SSE constraint matching.

    IntEnum so that AccessLevel.ADMIN >= AccessLevel.RDP is True.
    """
    READ = 1
    RDP = 2
    ADMIN = 3
    DOMAIN_ADMIN = 4


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_KS = SourceSystem.KNOWLEDGE_STORE
_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)


def _fact(value: Any, confidence: float = 1.0) -> KnowledgeFact:
    """Convenience builder for graph seed data, reusing KnowledgeFact."""
    return KnowledgeFact(
        value=value,
        version=1,
        confidence=confidence,
        source=_KS,
        timestamp=_NOW,
    )


# ---------------------------------------------------------------------------
# Host classification — pure function
# ---------------------------------------------------------------------------

# Pattern-based classification for synthetic GUIDE hostnames (case-insensitive)
_HOST_PATTERNS: list[tuple[re.Pattern[str], HostClass, float]] = [
    (re.compile(r"^WKSTN-\d+$", re.IGNORECASE), HostClass.WORKSTATION, 0.8),
    (re.compile(r"^SRV-FILE\d+$", re.IGNORECASE), HostClass.FILE_SERVER, 0.8),
    (re.compile(r"^LT-\d+-CORP$", re.IGNORECASE), HostClass.LAPTOP_CORP, 0.8),
]


def _build_exact_host_map() -> dict[str, HostClass]:
    """
    Build exact-match host classification from InMemoryKnowledgeStore seed data.

    Reads the store's _asset_info keys and maps each to a HostClass based on
    the zone and criticality attributes.  This ensures we don't hardcode
    duplicate hostname strings — the mapping is derived from the single source
    of truth in InMemoryKnowledgeStore.
    """
    store = InMemoryKnowledgeStore()
    mapping: dict[str, HostClass] = {}
    for host_id, asset_fact in store._asset_info.items():
        info = asset_fact.value
        zone = info.get("zone", "UNKNOWN")
        criticality = info.get("criticality", "unknown")

        if zone == "WORKSTATION":
            mapping[host_id] = HostClass.WORKSTATION
        elif zone == "DMZ" and criticality == "critical":
            mapping[host_id] = HostClass.DOMAIN_CONTROLLER
        elif zone == "DATABASE":
            mapping[host_id] = HostClass.DB_SERVER
        elif zone == "WEB":
            mapping[host_id] = HostClass.FILE_SERVER
        else:
            mapping[host_id] = HostClass.UNKNOWN
    return mapping


_EXACT_HOST_MAP: dict[str, HostClass] = _build_exact_host_map()


def classify_host(hostname: str) -> tuple[HostClass, float]:
    """
    Classify a hostname into a HostClass with a confidence score.

    Pure function — no side effects, no graph access.

    Returns:
        (HostClass, confidence) where confidence is:
        - 1.0 for exact matches against known toy hostnames
        - 0.8 for pattern matches against synthetic GUIDE templates
        - 0.0 for unrecognised hostnames (classified as UNKNOWN)
    """
    # Exact match first (case-insensitive via lowercase lookup)
    lower = hostname.lower()
    if lower in _EXACT_HOST_MAP:
        return (_EXACT_HOST_MAP[lower], 1.0)

    # Pattern match against synthetic templates
    for pattern, host_class, confidence in _HOST_PATTERNS:
        if pattern.match(hostname):
            return (host_class, confidence)

    return (HostClass.UNKNOWN, 0.0)


# ---------------------------------------------------------------------------
# HostClass -> default attributes for lazy node creation
# ---------------------------------------------------------------------------

_HOST_CLASS_DEFAULTS: dict[HostClass, dict[str, Any]] = {
    HostClass.WORKSTATION: {
        "criticality_tier": 0,
        "zone_id": "WORKSTATION",
        "exposed_services": [],
    },
    HostClass.FILE_SERVER: {
        "criticality_tier": 1,
        "zone_id": "WEB",
        "exposed_services": ["SMB", "HTTP"],
    },
    HostClass.LAPTOP_CORP: {
        "criticality_tier": 0,
        "zone_id": "WORKSTATION",
        "exposed_services": [],
    },
    HostClass.DOMAIN_CONTROLLER: {
        "criticality_tier": 3,
        "zone_id": "DMZ",
        "exposed_services": ["LDAP", "KERBEROS", "DNS", "RDP"],
    },
    HostClass.DB_SERVER: {
        "criticality_tier": 2,
        "zone_id": "DATABASE",
        "exposed_services": ["SQL", "SMB"],
    },
    HostClass.UNKNOWN: {
        "criticality_tier": 0,
        "zone_id": "UNKNOWN",
        "exposed_services": [],
    },
}

# Known account -> AccountType mapping.  Privilege tiers from
# InMemoryKnowledgeStore seed data + GUIDE synthetic account names.
_KNOWN_ACCOUNTS: dict[str, AccountType] = {
    "alice": AccountType.STANDARD_USER,
    "bob": AccountType.DOMAIN_ADMIN,       # "admin" privilege tier
    "charlie": AccountType.STANDARD_USER,
    "svc_backup": AccountType.SERVICE_ACCOUNT,  # "privileged" tier
    "mallory": AccountType.STANDARD_USER,
    # GUIDE synthetic account names (synth_fields.py ACCOUNT_NAMES)
    "jsmith": AccountType.STANDARD_USER,
    "a.patel": AccountType.STANDARD_USER,
    "m.chen": AccountType.STANDARD_USER,
    "helpdesk_admin": AccountType.LOCAL_ADMIN,
}


# ---------------------------------------------------------------------------
# Node ID helpers (public — tests and SSE import these)
# ---------------------------------------------------------------------------

def host_node_id(host_id: str) -> str:
    """Canonical graph node ID for a host."""
    return f"host:{host_id.lower()}"


def account_node_id(account_id: str) -> str:
    """Canonical graph node ID for an account."""
    return f"account:{account_id.lower()}"


def zone_node_id(zone_id: str) -> str:
    """Canonical graph node ID for a network zone."""
    return f"zone:{zone_id.upper()}"


def group_node_id(group_id: str) -> str:
    """Canonical graph node ID for a security group."""
    return f"group:{group_id.lower()}"


def service_node_id(service_id: str) -> str:
    """Canonical graph node ID for a service."""
    return f"service:{service_id.lower()}"


# ---------------------------------------------------------------------------
# KnowledgeStoreGraph
# ---------------------------------------------------------------------------

class KnowledgeStoreGraph:
    """
    NetworkX MultiDiGraph-backed knowledge store.

    Seeded from InMemoryKnowledgeStore's existing toy data (lossless
    migration) and supports lazy node creation for dynamically encountered
    hostnames via get_or_create_host_node / get_or_create_account_node.

    Every fact-bearing attribute is wrapped in KnowledgeFact from
    perception.knowledge_store.

    Node types: HostNode, AccountNode, ZoneNode, GroupNode, ServiceNode.
    Edge types: GRANTS, EGRESS, HOSTED_IN, HAS_PRIOR_ACCESS, DEPENDS_ON, MEMBER_OF.
    """

    def __init__(self, store: InMemoryKnowledgeStore | None = None) -> None:
        self._store = store or InMemoryKnowledgeStore()
        self._graph = nx.MultiDiGraph()
        self._seed_from_store()
        self._seed_additional_topology()

    @property
    def graph(self) -> nx.MultiDiGraph:
        """Direct access to the underlying NetworkX graph."""
        return self._graph

    # ------------------------------------------------------------------
    # Lazy node creation (idempotent)
    # ------------------------------------------------------------------

    def get_or_create_host_node(self, hostname: str) -> str:
        """
        Return the node ID for ``hostname``, creating the node if absent.

        New nodes inherit class-level defaults from classify_host() with
        the classification's confidence — lower than authored (1.0) seed
        data for pattern-matched hosts, 0.0 for unknowns.

        Idempotent: calling twice for the same hostname returns the same
        node ID without duplicating or modifying the existing node.
        """
        node_id = host_node_id(hostname)
        if node_id in self._graph:
            return node_id

        host_class, confidence = classify_host(hostname)
        defaults = _HOST_CLASS_DEFAULTS.get(
            host_class, _HOST_CLASS_DEFAULTS[HostClass.UNKNOWN]
        )

        self._graph.add_node(
            node_id,
            node_type="HostNode",
            host_id=hostname.lower(),
            host_class=_fact(host_class, confidence),
            criticality_tier=_fact(defaults["criticality_tier"], confidence),
            zone_id=_fact(defaults["zone_id"], confidence),
            exposed_services=_fact(list(defaults["exposed_services"]), confidence),
            first_seen=_NOW,
        )

        # HOSTED_IN edge to zone
        z_id = defaults["zone_id"]
        z_node = zone_node_id(z_id)
        if z_node not in self._graph:
            self._graph.add_node(
                z_node,
                node_type="ZoneNode",
                zone_id=z_id,
                security_zone=z_id,
            )
        self._graph.add_edge(
            node_id, z_node,
            key="HOSTED_IN",
            edge_type="HOSTED_IN",
        )

        return node_id

    def get_or_create_account_node(self, account_id: str) -> str:
        """
        Return the node ID for ``account_id``, creating the node if absent.

        Known accounts (from seed data and GUIDE synthetic names) get their
        mapped AccountType at confidence 0.9.  Unknown accounts default to
        STANDARD_USER at confidence 0.3.

        Idempotent.
        """
        node_id = account_node_id(account_id)
        if node_id in self._graph:
            return node_id

        lower_id = account_id.lower()
        if lower_id in _KNOWN_ACCOUNTS:
            acct_type = _KNOWN_ACCOUNTS[lower_id]
            confidence = 0.9
        else:
            acct_type = AccountType.STANDARD_USER
            confidence = 0.3

        self._graph.add_node(
            node_id,
            node_type="AccountNode",
            account_id=lower_id,
            account_type=_fact(acct_type, confidence),
            mfa_enabled=_fact(False, confidence),
            home_host_id=None,
        )

        return node_id

    def get_host_zone(self, host_node_id_str: str) -> str | None:
        """Return the zone node ID for a host, or None if not found."""
        for _, v, data in self._graph.out_edges(host_node_id_str, data=True):
            if data.get("edge_type") == "HOSTED_IN":
                return v
        return None

    # ------------------------------------------------------------------
    # Seed methods (private)
    # ------------------------------------------------------------------

    def _seed_from_store(self) -> None:
        """Lossless migration of InMemoryKnowledgeStore data into the graph."""

        # Privilege tier string -> AccountType
        privilege_to_type = {
            "standard": AccountType.STANDARD_USER,
            "admin": AccountType.DOMAIN_ADMIN,
            "privileged": AccountType.SERVICE_ACCOUNT,
        }

        # Criticality string -> integer tier
        criticality_to_tier = {
            "low": 0, "medium": 1, "high": 2, "critical": 3, "unknown": 0,
        }

        # 1. Users -> AccountNodes
        for user_id, priv_fact in self._store._user_privilege.items():
            node_id = account_node_id(user_id)
            acct_type = privilege_to_type.get(
                priv_fact.value, AccountType.STANDARD_USER
            )
            self._graph.add_node(
                node_id,
                node_type="AccountNode",
                account_id=user_id,
                account_type=_fact(acct_type, priv_fact.confidence),
                mfa_enabled=_fact(False, 1.0),
                home_host_id=None,
            )

        # 2. Hosts -> HostNodes + HOSTED_IN edges
        for host_id_str, asset_fact in self._store._asset_info.items():
            node_id = host_node_id(host_id_str)
            info = asset_fact.value  # {"criticality": str, "zone": str}
            host_class, _ = classify_host(host_id_str)
            crit_str = info.get("criticality", "unknown")
            zone_str = info.get("zone", "UNKNOWN")

            self._graph.add_node(
                node_id,
                node_type="HostNode",
                host_id=host_id_str,
                host_class=_fact(host_class, asset_fact.confidence),
                criticality_tier=_fact(
                    criticality_to_tier.get(crit_str, 0),
                    asset_fact.confidence,
                ),
                zone_id=_fact(zone_str, asset_fact.confidence),
                exposed_services=_fact(
                    list(
                        _HOST_CLASS_DEFAULTS.get(host_class, {}).get(
                            "exposed_services", []
                        )
                    ),
                    asset_fact.confidence,
                ),
                first_seen=_NOW,
            )

            # HOSTED_IN edge
            z_node = zone_node_id(zone_str)
            if z_node not in self._graph:
                self._graph.add_node(
                    z_node,
                    node_type="ZoneNode",
                    zone_id=zone_str,
                    security_zone=zone_str,
                )
            self._graph.add_edge(
                node_id, z_node,
                key="HOSTED_IN",
                edge_type="HOSTED_IN",
            )

        # 3. Topology -> ZoneNodes + EGRESS edges (only reachable pairs)
        for (src_zone, dst_zone), topo_fact in self._store._topology.items():
            src_node = zone_node_id(src_zone)
            dst_node = zone_node_id(dst_zone)
            for zn, zid in [(src_node, src_zone), (dst_node, dst_zone)]:
                if zn not in self._graph:
                    self._graph.add_node(
                        zn,
                        node_type="ZoneNode",
                        zone_id=zid,
                        security_zone=zid,
                    )
            if topo_fact.value:  # reachable = True
                for port, protocol in [
                    (445, "SMB"), (3389, "RDP"), (443, "HTTPS"), (80, "HTTP"),
                ]:
                    self._graph.add_edge(
                        src_node, dst_node,
                        key=f"EGRESS:{port}",
                        edge_type="EGRESS",
                        port=_fact(port, topo_fact.confidence),
                        protocol=_fact(protocol, topo_fact.confidence),
                        reachable=topo_fact,
                    )

        # 4. Access baseline -> HAS_PRIOR_ACCESS edges
        for (user_id, host_id_str), access_fact in self._store._access_baseline.items():
            acct_node = account_node_id(user_id)
            h_node = host_node_id(host_id_str)
            if acct_node in self._graph and h_node in self._graph:
                self._graph.add_edge(
                    acct_node, h_node,
                    key="HAS_PRIOR_ACCESS",
                    edge_type="HAS_PRIOR_ACCESS",
                    has_access=access_fact,
                )

    def _seed_additional_topology(self) -> None:
        """
        Seed additional realistic topology beyond the pure migration.

        Provides:
        - MANAGEMENT and EXTERNAL zones
        - EGRESS from DMZ and WORKSTATION to EXTERNAL (C2 testing)
        - Direct GRANTS: svc_backup ADMIN on server-db01
        - Group-mediated path: bob -> domain-admins -> server-dc01 DOMAIN_ADMIN
        - Additional GRANTS for graph richness
        - A ServiceNode on server-db01
        - Low-confidence GRANTS edge for CONDITIONALLY_FEASIBLE testing
        """
        # --- Ensure additional zones exist ---
        for z_id in ("MANAGEMENT", "EXTERNAL", "UNKNOWN"):
            zn = zone_node_id(z_id)
            if zn not in self._graph:
                self._graph.add_node(
                    zn,
                    node_type="ZoneNode",
                    zone_id=z_id,
                    security_zone=z_id,
                )

        # --- EGRESS to EXTERNAL (for C2 / T1071 testing) ---
        for src_zone in ("DMZ", "WORKSTATION"):
            for port, protocol in [(443, "HTTPS"), (80, "HTTP")]:
                self._graph.add_edge(
                    zone_node_id(src_zone), zone_node_id("EXTERNAL"),
                    key=f"EGRESS:{port}",
                    edge_type="EGRESS",
                    port=_fact(port, 1.0),
                    protocol=_fact(protocol, 1.0),
                    reachable=_fact(True, 1.0),
                )

        # --- Direct GRANTS: svc_backup -> server-db01 with ADMIN ---
        svc_node = account_node_id("svc_backup")
        db_node = host_node_id("server-db01")
        self._graph.add_edge(
            svc_node, db_node,
            key="GRANTS:ADMIN",
            edge_type="GRANTS",
            access_level=_fact(AccessLevel.ADMIN, 1.0),
        )

        # --- Group-mediated path: bob -> domain-admins -> server-dc01 ---
        da_group = group_node_id("domain-admins")
        self._graph.add_node(
            da_group,
            node_type="GroupNode",
            group_id="domain-admins",
            privilege_level="domain_admin",
        )

        bob_node = account_node_id("bob")
        self._graph.add_edge(
            bob_node, da_group,
            key="MEMBER_OF",
            edge_type="MEMBER_OF",
            membership_fact=_fact(True, 1.0),
        )

        dc_node = host_node_id("server-dc01")
        self._graph.add_edge(
            da_group, dc_node,
            key="GRANTS:DOMAIN_ADMIN",
            edge_type="GRANTS",
            access_level=_fact(AccessLevel.DOMAIN_ADMIN, 1.0),
        )

        # --- Additional GRANTS for graph richness ---
        alice_node = account_node_id("alice")
        ws01_node = host_node_id("workstation-01")
        self._graph.add_edge(
            alice_node, ws01_node,
            key="GRANTS:READ",
            edge_type="GRANTS",
            access_level=_fact(AccessLevel.READ, 1.0),
        )

        # --- ServiceNode: db-primary hosted on server-db01 ---
        svc_id = "db-primary"
        svc_svc_node = service_node_id(svc_id)
        self._graph.add_node(
            svc_svc_node,
            node_type="ServiceNode",
            service_id=svc_id,
            hosted_on_host_id="server-db01",
            business_impact_score=_fact(3, 1.0),
            dependents=["web-app", "reporting-service"],
        )

        # --- Low-confidence GRANTS for CONDITIONALLY_FEASIBLE testing ---
        # mallory gets ADMIN on a lazily-created WKSTN-9998 with low
        # confidence (0.3), creating a structurally valid but low-confidence
        # path for SSE test 10.
        mallory_node = account_node_id("mallory")
        test_host = self.get_or_create_host_node("WKSTN-9998")
        self._graph.add_edge(
            mallory_node, test_host,
            key="GRANTS:ADMIN",
            edge_type="GRANTS",
            access_level=_fact(AccessLevel.ADMIN, 0.3),
        )
