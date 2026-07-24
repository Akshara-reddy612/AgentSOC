"""
perception/knowledge_store.py

In-memory Knowledge Store seeded with sample enterprise facts.

Every lookup returns a KnowledgeFact — never a bare value.  Callers can
inspect confidence and timestamp to assess staleness before trusting the fact.

KnowledgeFact invariants (enforced in __post_init__):
  - confidence must be in [0.0, 1.0]
  - timestamp must be timezone-aware

The store is a collection of KnowledgeFact objects, not raw values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from perception.source_systems import SourceSystem


# ---------------------------------------------------------------------------
# KnowledgeFact
# ---------------------------------------------------------------------------

@dataclass
class KnowledgeFact:
    """
    A versioned, confidence-scored piece of enterprise knowledge.

    Attributes:
        value           — the knowledge value (typed appropriately for its domain)
        version         — monotonically increasing version counter
        confidence      — certainty of the fact, in [0.0, 1.0]
        source          — which system asserted this fact
        timestamp       — when this version was recorded (UTC-aware)
        audit_history   — list of prior KnowledgeFact versions (oldest first)
    """

    value: Any
    version: int
    confidence: float
    source: SourceSystem
    timestamp: datetime
    audit_history: list["KnowledgeFact"] = field(default_factory=list)

    def __post_init__(self) -> None:
        # --- confidence in [0.0, 1.0] ---
        if not isinstance(self.confidence, (int, float)):
            raise TypeError(
                f"confidence must be a float, got {type(self.confidence)!r}"
            )
        if not (0.0 <= float(self.confidence) <= 1.0):
            raise ValueError(
                f"confidence must be in [0.0, 1.0], got {self.confidence!r}"
            )

        # --- source must be a SourceSystem ---
        if not isinstance(self.source, SourceSystem):
            raise TypeError(
                f"source must be a SourceSystem instance, got {type(self.source)!r}"
            )

        # --- timestamp must be timezone-aware ---
        if not isinstance(self.timestamp, datetime):
            raise TypeError(
                f"timestamp must be a datetime, got {type(self.timestamp)!r}"
            )
        if self.timestamp.tzinfo is None:
            raise ValueError(
                "KnowledgeFact.timestamp must be timezone-aware (UTC)"
            )


# ---------------------------------------------------------------------------
# InMemoryKnowledgeStore
# ---------------------------------------------------------------------------

_KS = SourceSystem.KNOWLEDGE_STORE
_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)


def _fact(value: Any, confidence: float = 1.0) -> KnowledgeFact:
    """Convenience builder for seed data."""
    return KnowledgeFact(
        value=value,
        version=1,
        confidence=confidence,
        source=_KS,
        timestamp=_NOW,
    )


class InMemoryKnowledgeStore:
    """
    Simple in-memory knowledge store seeded with sample enterprise data.

    All lookups return a KnowledgeFact (or raise KeyError with a descriptive
    message if the fact is not found), so callers always have access to
    confidence, version, and timestamp — not just the bare value.
    """

    def __init__(self) -> None:
        # user_id -> privilege_tier (e.g. "standard", "admin", "privileged")
        self._user_privilege: dict[str, KnowledgeFact] = {
            "alice": _fact("standard", confidence=1.0),
            "bob": _fact("admin", confidence=0.95),
            "charlie": _fact("standard", confidence=1.0),
            "svc_backup": _fact("privileged", confidence=1.0),
            "mallory": _fact("standard", confidence=0.8),
        }

        # host_id -> {"criticality": str, "zone": str}
        self._asset_info: dict[str, KnowledgeFact] = {
            "workstation-01": _fact({"criticality": "low", "zone": "WORKSTATION"}, 1.0),
            "workstation-02": _fact({"criticality": "low", "zone": "WORKSTATION"}, 1.0),
            "server-dc01": _fact({"criticality": "critical", "zone": "DMZ"}, 1.0),
            "server-db01": _fact({"criticality": "high", "zone": "DATABASE"}, 0.95),
            "server-web01": _fact({"criticality": "medium", "zone": "WEB"}, 1.0),
        }

        # (src_zone, dst_zone) -> reachable (bool)
        self._topology: dict[tuple[str, str], KnowledgeFact] = {
            ("WORKSTATION", "WORKSTATION"): _fact(True, 1.0),
            ("WORKSTATION", "WEB"):         _fact(True, 1.0),
            ("WORKSTATION", "DMZ"):         _fact(False, 1.0),
            ("WORKSTATION", "DATABASE"):    _fact(False, 1.0),
            ("WEB", "DATABASE"):            _fact(True, 1.0),
            ("WEB", "DMZ"):                 _fact(True, 1.0),
            ("DMZ", "DATABASE"):            _fact(False, 1.0),
            ("DATABASE", "WORKSTATION"):    _fact(False, 1.0),
        }

        # (user_id, host_id) -> has_prior_access (bool)
        self._access_baseline: dict[tuple[str, str], KnowledgeFact] = {
            ("alice", "workstation-01"):  _fact(True, 1.0),
            ("alice", "workstation-02"):  _fact(True, 0.9),
            ("bob", "server-dc01"):       _fact(True, 1.0),
            ("bob", "server-db01"):       _fact(True, 1.0),
            ("charlie", "workstation-01"): _fact(True, 1.0),
            ("svc_backup", "server-db01"): _fact(True, 1.0),
        }

    # ------------------------------------------------------------------
    # Public lookups — each returns a KnowledgeFact, never a bare value
    # ------------------------------------------------------------------

    def get_user_privilege_tier(self, user_id: str) -> KnowledgeFact:
        """
        Return the privilege tier KnowledgeFact for `user_id`.

        Raises KeyError if the user is not in the store (unknown identity).
        """
        try:
            return self._user_privilege[user_id.lower()]
        except KeyError:
            raise KeyError(
                f"No privilege tier known for user {user_id!r}. "
                "Treat as untrusted / no-entry."
            )

    def get_asset_info(self, host_id: str) -> KnowledgeFact:
        """
        Return the asset info KnowledgeFact for `host_id`.

        Raises KeyError if the host is not in the store.
        """
        try:
            return self._asset_info[host_id.lower()]
        except KeyError:
            raise KeyError(
                f"No asset info known for host {host_id!r}."
            )

    def get_network_reachability(
        self, src_zone: str, dst_zone: str
    ) -> KnowledgeFact:
        """
        Return whether `src_zone` can reach `dst_zone` according to topology.

        Raises KeyError if the zone pair is not in the topology table.
        """
        key = (src_zone.upper(), dst_zone.upper())
        try:
            return self._topology[key]
        except KeyError:
            # Symmetric lookup
            rev_key = (dst_zone.upper(), src_zone.upper())
            if rev_key in self._topology:
                orig = self._topology[rev_key]
                return KnowledgeFact(
                    value=orig.value,
                    version=orig.version,
                    confidence=orig.confidence,
                    source=orig.source,
                    timestamp=orig.timestamp,
                )
            raise KeyError(
                f"No topology entry for zone pair {key!r}."
            )

    def get_prior_access(self, user_id: str, host_id: str) -> KnowledgeFact:
        """
        Return whether (user_id, host_id) is a known-good access pair.

        Returns a KnowledgeFact with value=False (confidence=1.0) for
        unknown pairs — absence of a record means no established baseline.
        """
        key = (user_id.lower(), host_id.lower())
        return self._access_baseline.get(
            key,
            KnowledgeFact(
                value=False,
                version=1,
                confidence=1.0,
                source=_KS,
                timestamp=_NOW,
            ),
        )

    def get_user_privilege_tier_default(
        self, user_id: str, default: str = "unknown"
    ) -> KnowledgeFact:
        """
        Like get_user_privilege_tier but returns a low-confidence 'unknown'
        KnowledgeFact instead of raising when the user is not found.
        """
        try:
            return self.get_user_privilege_tier(user_id)
        except KeyError:
            return KnowledgeFact(
                value=default,
                version=0,
                confidence=0.0,
                source=_KS,
                timestamp=_NOW,
            )

    def get_asset_info_default(
        self, host_id: str
    ) -> KnowledgeFact:
        """
        Like get_asset_info but returns a safe default for unknown hosts.
        """
        try:
            return self.get_asset_info(host_id)
        except KeyError:
            return KnowledgeFact(
                value={"criticality": "unknown", "zone": "UNKNOWN"},
                version=0,
                confidence=0.0,
                source=_KS,
                timestamp=_NOW,
            )
