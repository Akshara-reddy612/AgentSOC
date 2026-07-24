"""
perception/normalizer.py

Alert Normalization stage.

Maps a raw heterogeneous alert dict (as received from EDR, SIEM, Windows Event
Log, etc.) into the unified Alert schema, classifying every field as
TrustLevel.STRUCTURED or TrustLevel.FREE_TEXT.

Trust-classification rules:
  - Structured identifiers (user IDs, host names, event types, severity,
    timestamps, UUIDs) come from the logging infrastructure and are classified
    as STRUCTURED.
  - Any field whose value can be influenced by an adversary (process name,
    command line, registry key, file path, log line body) is classified as
    FREE_TEXT.
  - Fail-safe default: any field not in the explicit classification table
    defaults to FREE_TEXT.

The normalizer rejects unrecognised source strings via SourceSystem.from_string().
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from perception.models import Alert, TrustedField, TrustLevel
from perception.source_systems import SourceSystem


# ---------------------------------------------------------------------------
# Field classification tables
# ---------------------------------------------------------------------------

# Fields whose values are produced by the logging infrastructure (not the
# monitored process) — treated as STRUCTURED.
_STRUCTURED_FIELD_NAMES: frozenset[str] = frozenset({
    "alert_id",
    "source_system",
    "event_type",
    "timestamp",
    "source_user",
    "source_host",
    "target_host",
    "severity",
    "event_id",
    "session_id",
    "logon_type",
    "process_id",
    "parent_process_id",
    "destination_ip",
    "destination_port",
    "protocol",
})

# Fields that are attacker-controlled free text — classified as FREE_TEXT.
_FREE_TEXT_FIELD_NAMES: frozenset[str] = frozenset({
    "process_name",
    "command_line",
    "registry_key",
    "parent_process",
    "file_path",
    "raw_log_line",
    "description",
    "message",
    "subject",
    "object_name",
    "new_value",
    "old_value",
})


def _classify(field_name: str) -> TrustLevel:
    """
    Return the TrustLevel for a raw alert field.

    Fail-safe: unknown fields default to FREE_TEXT so they can never silently
    contaminate derived context.
    """
    if field_name in _STRUCTURED_FIELD_NAMES:
        return TrustLevel.STRUCTURED
    if field_name in _FREE_TEXT_FIELD_NAMES:
        return TrustLevel.FREE_TEXT
    # Fail-safe default
    return TrustLevel.FREE_TEXT


def _to_trusted_field(
    field_name: str,
    value: Any,
    source_system: SourceSystem,
) -> TrustedField:
    """Wrap a raw value in a TrustedField with the appropriate trust level."""
    return TrustedField(
        value=value,
        trust_level=_classify(field_name),
        source_system=source_system,
    )


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class AlertNormalizer:
    """
    Converts raw alert dicts into validated Alert objects.

    Each call to normalize() returns either a completed Alert or raises
    ValueError / KeyError for structurally unrecoverable inputs (e.g.,
    missing alert_id, unrecognised source_system).  Downstream schema
    validation catches semantic problems (bad timestamps, unknown event types).
    """

    def normalize(self, raw: dict[str, Any]) -> Alert:
        """
        Normalise a raw alert dict into an Alert.

        Required keys: alert_id, source_system.
        All other recognized keys are classified and wrapped; unknown keys
        default to FREE_TEXT.

        Raises:
            ValueError — missing alert_id
            ValueError — unrecognised source_system string (via SourceSystem.from_string)
        """
        if "alert_id" not in raw or raw["alert_id"] is None:
            raise ValueError(
                "Raw alert is missing required field 'alert_id'."
            )

        alert_id: str = str(raw["alert_id"])

        # Parse source system — rejects unknown strings
        raw_source = raw.get("source_system", "")
        if not raw_source:
            raise ValueError(
                f"Raw alert {alert_id!r} is missing required field 'source_system'."
            )
        source_system: SourceSystem = SourceSystem.from_string(str(raw_source))

        def tf(field_name: str) -> TrustedField | None:
            """Return a TrustedField for the named field, or None if absent."""
            if field_name not in raw or raw[field_name] is None:
                return None
            return _to_trusted_field(field_name, raw[field_name], source_system)

        # Required Alert fields — produce a TrustedField even if the value is
        # questionable; schema validation will flag bad values later.
        event_type = tf("event_type") or TrustedField(
            value="unknown",
            trust_level=TrustLevel.STRUCTURED,
            source_system=source_system,
        )
        timestamp_val = raw.get("timestamp")
        if timestamp_val is None:
            timestamp = TrustedField(
                value=None,
                trust_level=TrustLevel.STRUCTURED,
                source_system=source_system,
            )
        else:
            # Attempt ISO-8601 parse for string timestamps
            if isinstance(timestamp_val, str):
                try:
                    parsed_dt = datetime.fromisoformat(timestamp_val)
                    timestamp_val = parsed_dt
                except ValueError:
                    pass  # Leave as-is; schema validation will flag it
            timestamp = TrustedField(
                value=timestamp_val,
                trust_level=TrustLevel.STRUCTURED,
                source_system=source_system,
            )

        source_user = tf("source_user") or TrustedField(
            value="unknown",
            trust_level=TrustLevel.STRUCTURED,
            source_system=source_system,
        )
        source_host = tf("source_host") or TrustedField(
            value="unknown",
            trust_level=TrustLevel.STRUCTURED,
            source_system=source_system,
        )
        target_host = tf("target_host") or TrustedField(
            value="unknown",
            trust_level=TrustLevel.STRUCTURED,
            source_system=source_system,
        )
        severity = tf("severity") or TrustedField(
            value="unknown",
            trust_level=TrustLevel.STRUCTURED,
            source_system=source_system,
        )

        # Extra fields not mapped to named Alert attributes
        extra_structured: dict[str, TrustedField] = {}
        extra_free_text: dict[str, TrustedField] = {}

        skip_keys = {
            "alert_id", "source_system", "event_type", "timestamp",
            "source_user", "source_host", "target_host", "severity",
            "process_name", "command_line", "registry_key",
            "parent_process", "file_path", "raw_log_line",
        }
        for k, v in raw.items():
            if k in skip_keys or v is None:
                continue
            trust = _classify(k)
            field_obj = TrustedField(
                value=v, trust_level=trust, source_system=source_system
            )
            if trust == TrustLevel.STRUCTURED:
                extra_structured[k] = field_obj
            else:
                extra_free_text[k] = field_obj

        return Alert(
            alert_id=alert_id,
            source_system=source_system,
            event_type=event_type,
            timestamp=timestamp,
            source_user=source_user,
            source_host=source_host,
            target_host=target_host,
            severity=severity,
            process_name=tf("process_name"),
            command_line=tf("command_line"),
            registry_key=tf("registry_key"),
            parent_process=tf("parent_process"),
            file_path=tf("file_path"),
            raw_log_line=tf("raw_log_line"),
            extra_structured=extra_structured,
            extra_free_text=extra_free_text,
        )


# Module-level singleton for convenience
_default_normalizer = AlertNormalizer()


def normalize_alert(raw: dict[str, Any]) -> Alert:
    """Convenience wrapper around the default AlertNormalizer."""
    return _default_normalizer.normalize(raw)
