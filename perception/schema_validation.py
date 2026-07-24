"""
perception/schema_validation.py

Schema validation stage — runs immediately after Alert Normalization,
before Contextualization.

Validates a normalised Alert against a strict schema.  On failure returns
a list of structured ValidationError objects (machine-readable error codes),
never silently repairs the alert.

Error codes:
    SCHEMA_001  Missing Required Field
    SCHEMA_002  Invalid Timestamp
    SCHEMA_003  Unsupported Event Type
    SCHEMA_004  Invalid Data Type
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from perception.models import Alert, TrustedField, TrustLevel


# ---------------------------------------------------------------------------
# Error model
# ---------------------------------------------------------------------------

SUPPORTED_EVENT_TYPES = {
    "process_create",
    "registry_write",
    "network_connect",
    "file_create",
    "file_modify",
    "logon",
    "logon_failure",
    "privilege_escalation",
    "lateral_movement",
    "data_exfiltration",
}


@dataclass(frozen=True)
class ValidationError:
    """
    A single structured schema-validation failure.

    Attributes:
        code        — machine-readable error code (e.g. "SCHEMA_001")
        field       — which field triggered the error (may be None for structural errors)
        message     — human-readable description
        raw_value   — the offending value (for diagnostics; may be None)
    """
    code: str
    field: str | None
    message: str
    raw_value: Any = None


@dataclass(frozen=True)
class ValidationResult:
    """
    Outcome of validating a single Alert.

    Attributes:
        is_valid    — True iff the alert passed all checks
        errors      — list of ValidationError (empty when is_valid is True)
        alert_id    — the alert being validated
    """
    is_valid: bool
    errors: tuple[ValidationError, ...]
    alert_id: str


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class AlertSchemaValidator:
    """
    Validates a normalised Alert before it proceeds to Contextualization.

    Checks performed (in order):
      1. Required fields present and are TrustedField instances (SCHEMA_001 / SCHEMA_004)
      2. Timestamp is timezone-aware and parseable (SCHEMA_002)
      3. event_type value is in the supported set (SCHEMA_003)
    """

    # Fields that must be present and non-None
    REQUIRED_FIELDS: tuple[str, ...] = (
        "alert_id",
        "source_system",
        "event_type",
        "timestamp",
        "source_user",
        "source_host",
        "target_host",
        "severity",
    )

    # These must be TrustedField instances
    TRUSTED_FIELD_ATTRS: tuple[str, ...] = (
        "event_type",
        "timestamp",
        "source_user",
        "source_host",
        "target_host",
        "severity",
    )

    def validate(self, alert: Alert) -> ValidationResult:
        """
        Run all schema checks on `alert`.

        Returns a ValidationResult.  Never raises — all errors are collected
        and returned as structured ValidationError objects so the pipeline
        can decide how to handle each code.
        """
        errors: list[ValidationError] = []

        # --- 1. Required fields ---
        for field_name in self.REQUIRED_FIELDS:
            value = getattr(alert, field_name, None)
            if value is None:
                errors.append(ValidationError(
                    code="SCHEMA_001",
                    field=field_name,
                    message=f"Required field '{field_name}' is missing or None.",
                    raw_value=None,
                ))

        # --- 2. TrustedField type check ---
        for field_name in self.TRUSTED_FIELD_ATTRS:
            value = getattr(alert, field_name, None)
            if value is not None and not isinstance(value, TrustedField):
                errors.append(ValidationError(
                    code="SCHEMA_004",
                    field=field_name,
                    message=(
                        f"Field '{field_name}' must be a TrustedField instance, "
                        f"got {type(value).__name__!r}."
                    ),
                    raw_value=value,
                ))

        # --- 3. Timestamp validity (only if timestamp field is present & typed correctly) ---
        ts_field: TrustedField | None = getattr(alert, "timestamp", None)
        if ts_field is not None and isinstance(ts_field, TrustedField):
            ts_value = ts_field.value
            if not isinstance(ts_value, datetime):
                # Try to interpret string timestamps
                if isinstance(ts_value, str):
                    try:
                        parsed = datetime.fromisoformat(ts_value)
                        if parsed.tzinfo is None:
                            errors.append(ValidationError(
                                code="SCHEMA_002",
                                field="timestamp",
                                message="Timestamp string is not timezone-aware (no UTC offset).",
                                raw_value=ts_value,
                            ))
                    except ValueError:
                        errors.append(ValidationError(
                            code="SCHEMA_002",
                            field="timestamp",
                            message=f"Cannot parse timestamp value {ts_value!r} as ISO 8601.",
                            raw_value=ts_value,
                        ))
                else:
                    errors.append(ValidationError(
                        code="SCHEMA_002",
                        field="timestamp",
                        message=(
                            f"Timestamp value must be a datetime or ISO-8601 string, "
                            f"got {type(ts_value).__name__!r}."
                        ),
                        raw_value=ts_value,
                    ))
            elif ts_value.tzinfo is None:
                errors.append(ValidationError(
                    code="SCHEMA_002",
                    field="timestamp",
                    message="Timestamp datetime is naive (no timezone); must be UTC-aware.",
                    raw_value=ts_value,
                ))

        # --- 4. Event type membership ---
        et_field: TrustedField | None = getattr(alert, "event_type", None)
        if et_field is not None and isinstance(et_field, TrustedField):
            et_value = et_field.value
            if not isinstance(et_value, str):
                errors.append(ValidationError(
                    code="SCHEMA_004",
                    field="event_type",
                    message=f"event_type.value must be a string, got {type(et_value).__name__!r}.",
                    raw_value=et_value,
                ))
            elif et_value.lower() not in SUPPORTED_EVENT_TYPES:
                errors.append(ValidationError(
                    code="SCHEMA_003",
                    field="event_type",
                    message=(
                        f"Unsupported event type {et_value!r}. "
                        f"Supported: {sorted(SUPPORTED_EVENT_TYPES)}"
                    ),
                    raw_value=et_value,
                ))

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=tuple(errors),
            alert_id=getattr(alert, "alert_id", "<unknown>"),
        )


# Module-level singleton for convenience
_default_validator = AlertSchemaValidator()


def validate_alert(alert: Alert) -> ValidationResult:
    """Convenience wrapper around the default AlertSchemaValidator."""
    return _default_validator.validate(alert)
