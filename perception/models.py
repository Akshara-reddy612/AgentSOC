"""
perception/models.py

Core data model for the Trust-Aware Perception Layer.

Design principles enforced here:
- Trust metadata is immutable once created (frozen dataclasses + __post_init__ validation).
- ImmutableContext, DerivedContext, and Evidence are structurally separate types —
  never merged into a single dict, string, JSON blob, or prompt.
- FREE_TEXT evidence can NEVER flow into DerivedContext computation; the
  `compute_*` functions in derived_context_rules.py enforce this at the
  argument level. The dataclass-level enforcement here is that DerivedContext
  rejects FREE_TEXT fields at construction time.
- Evidence content is never modified or redacted — risk_metadata attaches
  externally in future phases without touching the original `value`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from perception.source_systems import SourceSystem


# ---------------------------------------------------------------------------
# TrustLevel
# ---------------------------------------------------------------------------

class TrustLevel(Enum):
    """
    Five-value trust taxonomy.

    This phase actively uses STRUCTURED, FREE_TEXT, and DERIVED.
    SYSTEM_GENERATED and LLM_GENERATED are reserved for future phases
    (pipeline-generated annotations and LLM reasoning outputs respectively)
    and are included now so downstream code never needs to add enum values.
    """
    STRUCTURED = "STRUCTURED"          # Knowledge-store or schema-validated field
    FREE_TEXT = "FREE_TEXT"            # Attacker-controllable raw text
    DERIVED = "DERIVED"                # Computed deterministically from STRUCTURED only
    SYSTEM_GENERATED = "SYSTEM_GENERATED"  # Future: pipeline metadata
    LLM_GENERATED = "LLM_GENERATED"   # Future: LLM reasoning output


# ---------------------------------------------------------------------------
# TrustedField
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrustedField:
    """
    An immutable wrapper around a single field value, carrying trust metadata.

    Constraints enforced at construction time (via __post_init__):
    - `trust_level` must be a TrustLevel instance (no None default).
    - `source_system` must be a SourceSystem instance (no None default).
    - `evidence_id` must be a valid UUIDv4 string; auto-generated if omitted.
    - `provenance_timestamp` must be timezone-aware (UTC); naive datetimes rejected.

    Because the dataclass is frozen, attribute reassignment after construction
    raises FrozenInstanceError — tests confirm this explicitly.
    """

    value: Any
    trust_level: TrustLevel
    source_system: SourceSystem
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    provenance_timestamp: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    def __post_init__(self) -> None:
        # --- trust_level ---
        if not isinstance(self.trust_level, TrustLevel):
            raise TypeError(
                f"trust_level must be a TrustLevel instance, got {type(self.trust_level)!r}"
            )

        # --- source_system ---
        if not isinstance(self.source_system, SourceSystem):
            raise TypeError(
                f"source_system must be a SourceSystem instance, got {type(self.source_system)!r}"
            )

        # --- evidence_id: must be a valid UUID string ---
        if not isinstance(self.evidence_id, str):
            raise TypeError(
                f"evidence_id must be a str, got {type(self.evidence_id)!r}"
            )
        try:
            parsed = uuid.UUID(self.evidence_id, version=4)
            # uuid.UUID is lenient; verify the canonical form round-trips
            if str(parsed) != self.evidence_id.lower():
                raise ValueError("not canonical UUID form")
        except (ValueError, AttributeError) as exc:
            raise ValueError(
                f"evidence_id must be a valid UUIDv4 string, got {self.evidence_id!r}"
            ) from exc

        # --- provenance_timestamp: must be timezone-aware ---
        if not isinstance(self.provenance_timestamp, datetime):
            raise TypeError(
                f"provenance_timestamp must be a datetime, got {type(self.provenance_timestamp)!r}"
            )
        if self.provenance_timestamp.tzinfo is None:
            raise ValueError(
                "provenance_timestamp must be timezone-aware (UTC); naive datetimes are rejected"
            )


# ---------------------------------------------------------------------------
# ImmutableContext
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ImmutableContext:
    """
    Knowledge-store-sourced facts about the entities involved in an alert.

    ALL fields must carry TrustLevel.STRUCTURED.  Any attempt to store a
    FREE_TEXT field raises ValueError at construction time.

    Fields:
        user_role           — privilege tier / role from the identity store
        asset_criticality   — criticality classification of the target host
        network_zone        — network zone of the target asset
        historical_access   — whether this (user, host) pair has prior access
        source_user         — originating user identifier (structured)
        source_host         — originating host identifier (structured)
        target_host         — target host identifier (structured)
        event_type          — event category (structured)
    """

    user_role: TrustedField
    asset_criticality: TrustedField
    network_zone: TrustedField
    historical_access: TrustedField
    source_user: TrustedField
    source_host: TrustedField
    target_host: TrustedField
    event_type: TrustedField

    def __post_init__(self) -> None:
        _reject_non_structured(self, context_name="ImmutableContext")


# ---------------------------------------------------------------------------
# DerivedContext
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DerivedContext:
    """
    Computed facts derived deterministically from ImmutableContext only.

    ALL fields must carry TrustLevel.DERIVED.  FREE_TEXT fields are
    structurally rejected at construction.  The compute_* functions in
    derived_context_rules.py additionally enforce that they accept ONLY
    ImmutableContext arguments, making the contamination path doubly blocked.

    Fields:
        no_prior_access         — user has no baseline access to the target
        cross_zone_access       — source and target are in different network zones
        high_criticality_target — target asset is classified high/critical
        privilege_escalation_risk — user role is lower than the target requires
    """

    no_prior_access: TrustedField
    cross_zone_access: TrustedField
    high_criticality_target: TrustedField
    privilege_escalation_risk: TrustedField

    def __post_init__(self) -> None:
        _reject_non_derived(self, context_name="DerivedContext")


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """
    Raw free-text fields extracted from the alert, untouched.

    Every field is a TrustedField with TrustLevel.FREE_TEXT.

    `risk_metadata` is intentionally empty in Phase 1.  Future Evidence Risk
    Assessment stages will populate it with suspicion scores, matched patterns,
    embedding similarity, and detector outputs — without ever modifying the
    original `value` of any TrustedField.

    Fields:
        process_name    — process name or command string (attacker-controllable)
        command_line    — full command-line arguments (attacker-controllable)
        registry_key    — registry key path (attacker-controllable on value side)
        parent_process  — parent process name
        file_path       — file path involved in the event
        raw_log_line    — the unparsed log line, if available
        risk_metadata   — populated by future ERA stage; never touch existing keys
    """

    process_name: TrustedField | None = None
    command_line: TrustedField | None = None
    registry_key: TrustedField | None = None
    parent_process: TrustedField | None = None
    file_path: TrustedField | None = None
    raw_log_line: TrustedField | None = None
    risk_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Verify that all supplied TrustedField values are FREE_TEXT."""
        trusted_fields = {
            "process_name": self.process_name,
            "command_line": self.command_line,
            "registry_key": self.registry_key,
            "parent_process": self.parent_process,
            "file_path": self.file_path,
            "raw_log_line": self.raw_log_line,
        }
        for attr_name, tf in trusted_fields.items():
            if tf is None:
                continue
            if not isinstance(tf, TrustedField):
                raise TypeError(
                    f"Evidence.{attr_name} must be a TrustedField, got {type(tf)!r}"
                )
            if tf.trust_level != TrustLevel.FREE_TEXT:
                raise ValueError(
                    f"Evidence.{attr_name} must have TrustLevel.FREE_TEXT, "
                    f"got {tf.trust_level!r}"
                )

    def free_text_field_count(self) -> int:
        """Return count of non-None free-text fields (used in log summaries)."""
        return sum(
            1
            for tf in (
                self.process_name,
                self.command_line,
                self.registry_key,
                self.parent_process,
                self.file_path,
                self.raw_log_line,
            )
            if tf is not None
        )


# ---------------------------------------------------------------------------
# Alert  (post-normalization, pre-contextualization)
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """
    A normalized alert holding TrustedFields before trust-separation.

    Fields are already classified as STRUCTURED or FREE_TEXT by the normalizer.
    The contextualizer will split them into ImmutableContext / Evidence buckets.

    Deliberately not frozen so the pipeline can assemble it incrementally,
    but all trust-classified fields must be TrustedField instances.
    """

    alert_id: str
    source_system: SourceSystem
    event_type: TrustedField
    timestamp: TrustedField
    source_user: TrustedField
    source_host: TrustedField
    target_host: TrustedField
    severity: TrustedField

    # Free-text fields (attacker-controlled)
    process_name: TrustedField | None = None
    command_line: TrustedField | None = None
    registry_key: TrustedField | None = None
    parent_process: TrustedField | None = None
    file_path: TrustedField | None = None
    raw_log_line: TrustedField | None = None

    # Extension point for future phases: additional structured fields
    extra_structured: dict[str, TrustedField] = field(default_factory=dict)
    # Extension point for future phases: additional free-text fields
    extra_free_text: dict[str, TrustedField] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# EnrichedIncident
# ---------------------------------------------------------------------------

@dataclass
class EnrichedIncident:
    """
    The output of Situational Contextualization.

    Composes three completely separate objects — never merged:
        immutable_context   — knowledge-store facts (STRUCTURED)
        derived_context     — computed flags (DERIVED)
        evidence            — raw attacker-controlled fields (FREE_TEXT)

    Extension points (None in Phase 1, populated by future phases):
        era_metadata        — Evidence Risk Assessment outputs
        spc_metadata        — Safe Prompt Construction metadata
        llm_output          — LLM reasoning results
        output_validation   — Output Validation metadata
    """

    alert_id: str
    immutable_context: ImmutableContext
    derived_context: DerivedContext
    evidence: Evidence

    # Future-phase extension points (None until those phases are built)
    era_metadata: dict[str, Any] | None = None       # Phase 2
    spc_metadata: dict[str, Any] | None = None       # Phase 3
    llm_output: dict[str, Any] | None = None         # Phase 4
    output_validation: dict[str, Any] | None = None  # Phase 5


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _reject_non_structured(obj: Any, context_name: str) -> None:
    """
    Verify that every TrustedField attribute on `obj` carries STRUCTURED trust.
    Called from ImmutableContext.__post_init__.
    """
    for attr_name in obj.__dataclass_fields__:
        tf = getattr(obj, attr_name)
        if not isinstance(tf, TrustedField):
            raise TypeError(
                f"{context_name}.{attr_name} must be a TrustedField, got {type(tf)!r}"
            )
        if tf.trust_level != TrustLevel.STRUCTURED:
            raise ValueError(
                f"{context_name}.{attr_name} must have TrustLevel.STRUCTURED, "
                f"got {tf.trust_level!r}. "
                f"ImmutableContext must never hold FREE_TEXT or DERIVED data."
            )


def _reject_non_derived(obj: Any, context_name: str) -> None:
    """
    Verify that every TrustedField attribute on `obj` carries DERIVED trust.
    Called from DerivedContext.__post_init__.
    """
    for attr_name in obj.__dataclass_fields__:
        tf = getattr(obj, attr_name)
        if not isinstance(tf, TrustedField):
            raise TypeError(
                f"{context_name}.{attr_name} must be a TrustedField, got {type(tf)!r}"
            )
        if tf.trust_level != TrustLevel.DERIVED:
            raise ValueError(
                f"{context_name}.{attr_name} must have TrustLevel.DERIVED, "
                f"got {tf.trust_level!r}. "
                f"DerivedContext must never hold FREE_TEXT data."
            )
