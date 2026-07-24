"""
perception/noise_reducer.py

Noise Reduction stage.

Deduplicates and clusters EnrichedIncidents using ONLY structural keys from
ImmutableContext and DerivedContext — never free-text similarity.

Cluster key: (source_user, target_host, event_type, derived_flags_tuple)
  - All key components come from STRUCTURED or DERIVED TrustedFields.
  - Free-text fields (Evidence) are deliberately excluded from the key so
    that injection-style variation in process names or command lines can
    never create false negatives (true duplicates appearing as distinct).

Each cluster retains:
  - occurrence_count   — how many incidents were merged
  - first_seen         — timestamp of the earliest incident
  - last_seen          — timestamp of the most recent incident
  - representative     — the first EnrichedIncident seen (complete, unmodified)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from perception.models import EnrichedIncident, TrustedField


# ---------------------------------------------------------------------------
# Cluster model
# ---------------------------------------------------------------------------

@dataclass
class IncidentCluster:
    """
    A group of structurally-identical EnrichedIncidents.

    Attributes:
        cluster_key         — the tuple used to identify equivalent incidents
        representative      — the first (canonical) EnrichedIncident in the cluster
        occurrence_count    — total number of incidents merged into this cluster
        first_seen          — UTC datetime of the earliest incident
        last_seen           — UTC datetime of the most recent incident
    """
    cluster_key: tuple[Any, ...]
    representative: EnrichedIncident
    occurrence_count: int = 1
    first_seen: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    last_seen: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )


# ---------------------------------------------------------------------------
# Noise Reducer
# ---------------------------------------------------------------------------

def _extract_timestamp(incident: EnrichedIncident) -> datetime:
    """
    Extract the alert timestamp from ImmutableContext or fall back to now.

    Uses ImmutableContext.event_type.provenance_timestamp as a proxy for
    alert time (the actual alert timestamp is on the normalised Alert, but
    EnrichedIncident doesn't carry the raw Alert to keep separation clean).
    We use the provenance_timestamp of the ImmutableContext fields as the
    creation time proxy.
    """
    # Use the provenance_timestamp on the source_user TrustedField — this was
    # set to the current time when the TrustedField was created, which is a
    # reasonable proxy for processing time.  A future phase can carry the
    # original alert timestamp through properly.
    ts = incident.immutable_context.source_user.provenance_timestamp
    if ts is not None and ts.tzinfo is not None:
        return ts
    return datetime.now(tz=timezone.utc)


def _make_cluster_key(incident: EnrichedIncident) -> tuple[Any, ...]:
    """
    Derive the structural cluster key for an incident.

    Components (all from STRUCTURED or DERIVED TrustedFields):
      - source_user value
      - target_host value
      - event_type value
      - no_prior_access (bool)
      - cross_zone_access (bool)
      - high_criticality_target (bool)
      - privilege_escalation_risk (bool)

    Free-text Evidence fields are deliberately excluded.
    """
    ic = incident.immutable_context
    dc = incident.derived_context
    return (
        ic.source_user.value,
        ic.target_host.value,
        ic.event_type.value,
        dc.no_prior_access.value,
        dc.cross_zone_access.value,
        dc.high_criticality_target.value,
        dc.privilege_escalation_risk.value,
    )


class NoiseReducer:
    """
    Stateless noise-reduction utility.

    Call reduce() with a list of EnrichedIncidents; it returns a list of
    IncidentClusters with duplicates merged.

    Thread-safety: reduce() is pure (no mutation of inputs); safe to call
    from multiple threads simultaneously.
    """

    def reduce(
        self, incidents: list[EnrichedIncident]
    ) -> list[IncidentCluster]:
        """
        Cluster incidents by structural key and merge duplicates.

        Args:
            incidents: List of EnrichedIncidents from the contextualizer.

        Returns:
            List of IncidentClusters, one per unique structural key.
            Order: stable insertion order (first seen wins as representative).
        """
        clusters: dict[tuple[Any, ...], IncidentCluster] = {}

        for incident in incidents:
            key = _make_cluster_key(incident)
            ts = _extract_timestamp(incident)

            if key not in clusters:
                clusters[key] = IncidentCluster(
                    cluster_key=key,
                    representative=incident,
                    occurrence_count=1,
                    first_seen=ts,
                    last_seen=ts,
                )
            else:
                cluster = clusters[key]
                cluster.occurrence_count += 1
                if ts < cluster.first_seen:
                    cluster.first_seen = ts
                if ts > cluster.last_seen:
                    cluster.last_seen = ts

        return list(clusters.values())


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_default_reducer = NoiseReducer()


def reduce_noise(incidents: list[EnrichedIncident]) -> list[IncidentCluster]:
    """Convenience wrapper using the default NoiseReducer."""
    return _default_reducer.reduce(incidents)
