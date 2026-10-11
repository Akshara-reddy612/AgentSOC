"""
perception/environment.py

Environment profile (design step S1, 2026-10-11; see
experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md).

What a deployment knows about its own network: which IPv4 ranges and name
suffixes are internal, how internal hosts are named, and each zone's internet
egress policy.  Before S1 these were hard-coded for the synthetic enterprise
(RFC 1918 = internal; perception/network_model.ZONE_EGRESS_POLICY).  Real
environments differ: in DEDALE the simulated internet and the external zone
use 172.18.0.0/16 and 172.19.0.0/16, which RFC 1918 would call internal, so
the known-bad escalation and the T1071 destination checks would never fire.

Design rules:
  - The profile is TRUSTED configuration (a CMDB / network plan).  It never
    comes from alert text, and it contains no attacker infrastructure.
  - It travels with the Knowledge Store graph as a graph attribute
    (GRAPH_ATTR), so the dry-run copies RSEM and the playbook layer make
    (graph.copy() + KnowledgeStoreGraph.from_graph) keep it.
  - DEFAULT_PROFILE reproduces the pre-S1 rules.  Only malformed dotted quads
    (an octet above 255) are handled differently by is_internal_address: they
    are not addresses, so they are not internal (before S1, e.g. "10.300.1.1"
    counted as internal because only the leading octets were compared).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

import networkx as nx

from perception.network_model import ZONE_EGRESS_POLICY

GRAPH_ATTR = "environment_profile"


def parse_ipv4(address: str) -> ipaddress.IPv4Address | None:
    """Dotted-quad IPv4 address (leading zeros allowed, as before S1), else None."""
    parts = address.strip().split(".")
    if len(parts) != 4 or not all(p.isascii() and p.isdigit() for p in parts):
        return None
    octets = [int(p) for p in parts]
    if any(o > 255 for o in octets):
        return None
    return ipaddress.IPv4Address(".".join(str(o) for o in octets))


@dataclass(frozen=True, eq=False)
class EnvironmentProfile:
    """Trusted description of one environment's network (see module docstring)."""

    name: str
    internal_networks: tuple[str, ...]
    internal_domain_suffixes: tuple[str, ...] = (".corp.local", ".internal")
    internal_hostname_pattern: str = r"^(WKSTN-|SRV-|LT-.*-CORP$)"
    zone_egress_policy: Mapping[str, dict] = field(default_factory=lambda: dict(ZONE_EGRESS_POLICY))
    # Response policy (added 2026-10-11): may containment proposed for a C2 check
    # that rests on telemetry alone (no NCE reasoning, no threat intelligence) be
    # auto-approved?  True keeps the synthetic enterprise's original behaviour.
    auto_contain_unreasoned_c2: bool = True
    # Telemetry coverage (added 2026-10-11, DEDALE Phase 3, decision (a)): the hosts whose
    # logs the store learns from (a log-source inventory).  None = closed world: the store
    # is taken to describe every host completely (synthetic enterprise, original
    # behaviour).  With a list, a missing access path to any other host means "not
    # known", not "impossible": SSE answers CONDITIONALLY_FEASIBLE (-> analyst review).
    observed_hosts: tuple[str, ...] | None = None
    _networks: tuple[ipaddress.IPv4Network, ...] = field(init=False, repr=False)
    _hostname_re: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_networks", tuple(ipaddress.IPv4Network(n) for n in self.internal_networks))
        object.__setattr__(self, "_hostname_re", re.compile(self.internal_hostname_pattern, re.IGNORECASE))
        object.__setattr__(self, "internal_domain_suffixes", tuple(s.lower() for s in self.internal_domain_suffixes))
        if self.observed_hosts is not None:
            object.__setattr__(self, "observed_hosts", tuple(sorted({h.lower() for h in self.observed_hosts})))
        object.__setattr__(self, "zone_egress_policy", MappingProxyType(
            {zone.upper(): dict(policy) for zone, policy in self.zone_egress_policy.items()}))

    @property
    def hostname_regex(self) -> re.Pattern:
        return self._hostname_re

    def ipv4_is_internal(self, address: str) -> bool | None:
        """True / False for a dotted-quad IPv4 address; None if `address` is not one."""
        ip = parse_ipv4(address)
        if ip is None:
            return None
        return any(ip in net for net in self._networks)

    def is_internal_address(self, address: str) -> bool:
        """Internal IPv4 address or internal name suffix; anything else is not internal."""
        a = address.strip().lower()
        if a.endswith(self.internal_domain_suffixes):
            return True
        return bool(self.ipv4_is_internal(a))

    def is_internal_hostname(self, name: str) -> bool:
        """A name in free text that follows the internal host naming or an internal suffix."""
        return bool(self._hostname_re.match(name)) or name.lower().endswith(self.internal_domain_suffixes)

    def observes_host(self, name: str) -> bool | None:
        """Whether the store learns from this host's logs; None if coverage is not modelled (closed world)."""
        if self.observed_hosts is None:
            return None
        n = name.strip().lower()
        for suffix in self.internal_domain_suffixes:
            if n.endswith(suffix):
                n = n[:-len(suffix)]
                break
        return n in self.observed_hosts

    def to_dict(self) -> dict:
        """Plain-JSON form (stored with a persistent Knowledge Store, design step S2)."""
        d = {
            "name": self.name,
            "internal_networks": list(self.internal_networks),
            "internal_domain_suffixes": list(self.internal_domain_suffixes),
            "internal_hostname_pattern": self.internal_hostname_pattern,
            "zone_egress_policy": {zone: dict(policy) for zone, policy in self.zone_egress_policy.items()},
            "auto_contain_unreasoned_c2": self.auto_contain_unreasoned_c2,
        }
        if self.observed_hosts is not None:          # absent when unset: older stores stay readable
            d["observed_hosts"] = list(self.observed_hosts)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "EnvironmentProfile":
        return cls(
            name=d["name"],
            internal_networks=tuple(d["internal_networks"]),
            internal_domain_suffixes=tuple(d["internal_domain_suffixes"]),
            internal_hostname_pattern=d["internal_hostname_pattern"],
            zone_egress_policy=d["zone_egress_policy"],
            auto_contain_unreasoned_c2=d.get("auto_contain_unreasoned_c2", True),
            observed_hosts=tuple(d["observed_hosts"]) if d.get("observed_hosts") is not None else None,
        )


DEFAULT_PROFILE = EnvironmentProfile(
    name="default (synthetic enterprise, RFC 1918 internal)",
    internal_networks=("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"),
)


def profile_of(graph: nx.MultiDiGraph) -> EnvironmentProfile:
    """The environment profile a Knowledge Store graph was built for (default if none)."""
    return graph.graph.get(GRAPH_ATTR, DEFAULT_PROFILE)
