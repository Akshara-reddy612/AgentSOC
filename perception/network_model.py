"""
perception/network_model.py

Synthetic enterprise network model used by the Knowledge Store graph
(added 2026-10-10, Phase 2 step 2.3).

THIS IS SYNTHETIC DATA.  It models the trusted network context a real SOC has
(proxy/firewall egress policy, an allow-list of sanctioned services and a
threat-intelligence list of known-bad destinations) so that SSE can evaluate
T1071 (Application Layer Protocol / C2) hypotheses against something other
than "any outbound edge exists".  It is generated deterministically
(random.Random(71)) and uses only the IPv4 ranges reserved for documentation
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and the reserved
`.example` top-level domain (RFC 2606), so no real organisation's address is
referenced.

Design rule: everything here is TRUSTED context.  It is read only by SSE,
RSEM and the Action/Playbook layer, never by NCE, ERA or prompt construction,
and nothing in an alert's free-text fields can change it.
"""
from __future__ import annotations

import random

SEED = 71
SOURCE_ALLOWLIST = "synthetic_allowlist"
SOURCE_THREAT_INTEL = "synthetic_threat_intel"

# Reputation classes for external destinations.
SANCTIONED = "sanctioned"
KNOWN_BAD = "known_bad"
UNKNOWN = "unknown"
INTERNAL = "internal"

# Per-zone internet egress policy.
#   mode "proxy":     outbound web via the corporate proxy; reputations in
#                     `deny` are blocked, everything else is allowed (and logged).
#   mode "allowlist": only reputations in `allow` may be reached.
#   mode "open":      routed to the internet with no egress filtering (added
#                     2026-10-11 for environments that document none, e.g. DEDALE).
#   mode "none":      no internet route at all.
ZONE_EGRESS_POLICY: dict[str, dict] = {
    "WORKSTATION": {"mode": "proxy", "deny": [KNOWN_BAD]},
    "DMZ": {"mode": "allowlist", "allow": [SANCTIONED]},
    "WEB": {"mode": "none"},
    "DATABASE": {"mode": "none"},
    "MANAGEMENT": {"mode": "none"},
    "UNKNOWN": {"mode": "none"},
}

_SANCTIONED_NAMES = [
    "updates.os-vendor.example", "telemetry.os-vendor.example", "login.idp.example",
    "mail.office-suite.example", "files.office-suite.example", "crm.saas.example",
    "hr.saas.example", "tickets.itsm.example", "cdn.assets.example", "av-updates.edr-vendor.example",
]
_KNOWN_BAD_NAMES = [
    "gate.c2-panel.example", "beacon.dyn-dns.example", "check-in.badcdn.example",
    "update-service.typosquat.example", "invoice-portal.phish.example",
    "drop.exfil-store.example", "stage2.loader.example", "api.botnet.example",
    "sync.rat-relay.example", "cdn.malvert.example",
]


def _build_destinations() -> list[dict]:
    rng = random.Random(SEED)
    sanctioned_ips = sorted(rng.sample(range(10, 250), 10))
    bad_ips_a = sorted(rng.sample(range(10, 250), 5))
    bad_ips_b = sorted(rng.sample(range(10, 250), 5))
    dests: list[dict] = []
    for name in _SANCTIONED_NAMES:
        dests.append({"address": name, "kind": "domain", "reputation": SANCTIONED,
                      "confidence": 0.95, "source": SOURCE_ALLOWLIST})
    for octet in sanctioned_ips:
        dests.append({"address": f"192.0.2.{octet}", "kind": "ip", "reputation": SANCTIONED,
                      "confidence": 0.95, "source": SOURCE_ALLOWLIST})
    for name in _KNOWN_BAD_NAMES:
        dests.append({"address": name, "kind": "domain", "reputation": KNOWN_BAD,
                      "confidence": round(rng.uniform(0.7, 0.95), 2), "source": SOURCE_THREAT_INTEL})
    for octet in bad_ips_a:
        dests.append({"address": f"203.0.113.{octet}", "kind": "ip", "reputation": KNOWN_BAD,
                      "confidence": round(rng.uniform(0.7, 0.95), 2), "source": SOURCE_THREAT_INTEL})
    for octet in bad_ips_b:
        dests.append({"address": f"198.51.100.{octet}", "kind": "ip", "reputation": KNOWN_BAD,
                      "confidence": round(rng.uniform(0.7, 0.95), 2), "source": SOURCE_THREAT_INTEL})
    return dests


# 20 sanctioned + 20 known-bad destinations, fixed by SEED.
SYNTHETIC_DESTINATIONS: list[dict] = _build_destinations()


# Which addresses count as internal is part of the environment profile since
# design step S1 (perception/environment.py; RFC 1918 in the default profile).


def policy_permits(policy: dict, reputation: str) -> bool:
    """Does an egress policy let traffic reach a destination of this reputation?"""
    mode = policy["mode"]
    if mode == "none":
        return False
    if mode == "open":
        return True
    if mode == "proxy":
        return reputation not in policy.get("deny", [])
    if mode == "allowlist":
        return reputation in policy.get("allow", [])
    return False


def egress_permits(zone_id: str, reputation: str) -> bool:
    """policy_permits for the synthetic enterprise's zone policy table (no graph needed)."""
    return policy_permits(ZONE_EGRESS_POLICY.get(zone_id.upper(), {"mode": "none"}), reputation)
