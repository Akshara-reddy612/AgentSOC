"""
perception/contextualizer.py

Situational Contextualization stage.

Produces an EnrichedIncident from a validated Alert by:
  1. Looking up ImmutableContext facts from the KnowledgeStore.
  2. Computing DerivedContext flags by calling the pure rule functions
     (with ONLY ImmutableContext — never Evidence).
  3. Collecting Evidence from the alert's free-text fields, untouched.

The three resulting objects (ImmutableContext, DerivedContext, Evidence) are
composed into an EnrichedIncident as three completely separate attributes —
never merged, concatenated, or passed together to any function that accepts
all three.
"""

from __future__ import annotations

from perception.derived_context_rules import build_derived_context
from perception.knowledge_store import InMemoryKnowledgeStore
from perception.models import (
    Alert,
    DerivedContext,
    EnrichedIncident,
    Evidence,
    ImmutableContext,
    TrustedField,
    TrustLevel,
)
from perception.source_systems import SourceSystem

_KS_SYS = SourceSystem.KNOWLEDGE_STORE


def _structured_field(value: object) -> TrustedField:
    """Wrap a knowledge-store value as a STRUCTURED TrustedField."""
    return TrustedField(
        value=value,
        trust_level=TrustLevel.STRUCTURED,
        source_system=_KS_SYS,
    )


class Contextualizer:
    """
    Transforms a validated Alert into an EnrichedIncident.

    Depends on InMemoryKnowledgeStore for enterprise facts.  In Phase 1 the
    store is always in-memory; later phases can inject a different store via
    the constructor without breaking this interface.
    """

    def __init__(self, store: InMemoryKnowledgeStore | None = None) -> None:
        self._store = store or InMemoryKnowledgeStore()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def contextualize(self, alert: Alert) -> EnrichedIncident:
        """
        Build an EnrichedIncident from a validated Alert.

        Args:
            alert: A fully validated Alert (i.e. ValidationResult.is_valid is True).

        Returns:
            EnrichedIncident composed of ImmutableContext, DerivedContext, Evidence.
        """
        immutable_ctx = self._build_immutable_context(alert)
        derived_ctx = build_derived_context(immutable_ctx)
        evidence = self._build_evidence(alert)

        return EnrichedIncident(
            alert_id=alert.alert_id,
            immutable_context=immutable_ctx,
            derived_context=derived_ctx,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # Private builders
    # ------------------------------------------------------------------

    def _build_immutable_context(self, alert: Alert) -> ImmutableContext:
        """
        Look up knowledge-store facts and build an ImmutableContext.

        Uses _default variants so unknown users/hosts get confidence=0.0
        rather than raising (the pipeline can still proceed; low-confidence
        facts inform downstream risk scoring in later phases).
        """
        source_user_id: str = str(alert.source_user.value)
        target_host_id: str = str(alert.target_host.value)
        source_host_id: str = str(alert.source_host.value)

        # --- User privilege tier ---
        privilege_fact = self._store.get_user_privilege_tier_default(source_user_id)
        user_role = _structured_field(privilege_fact.value)

        # --- Asset criticality (target host) ---
        asset_fact = self._store.get_asset_info_default(target_host_id)
        asset_criticality = _structured_field(asset_fact.value)

        # --- Network zones (both source and target, combined for rule use) ---
        src_asset_fact = self._store.get_asset_info_default(source_host_id)
        src_asset_info = src_asset_fact.value if isinstance(src_asset_fact.value, dict) else {}
        dst_asset_info = asset_fact.value if isinstance(asset_fact.value, dict) else {}
        zone_combined = {
            "src_zone": src_asset_info.get("zone", "UNKNOWN"),
            "dst_zone": dst_asset_info.get("zone", "UNKNOWN"),
        }
        network_zone = _structured_field(zone_combined)

        # --- Historical access baseline ---
        access_fact = self._store.get_prior_access(source_user_id, target_host_id)
        historical_access = _structured_field(access_fact.value)

        # --- Pass-through structured identifiers from the alert ---
        source_user_field = _structured_field(alert.source_user.value)
        source_host_field = _structured_field(alert.source_host.value)
        target_host_field = _structured_field(alert.target_host.value)
        event_type_field = _structured_field(alert.event_type.value)

        return ImmutableContext(
            user_role=user_role,
            asset_criticality=asset_criticality,
            network_zone=network_zone,
            historical_access=historical_access,
            source_user=source_user_field,
            source_host=source_host_field,
            target_host=target_host_field,
            event_type=event_type_field,
        )

    def _build_evidence(self, alert: Alert) -> Evidence:
        """
        Collect free-text fields from the alert into an Evidence object.

        Fields are passed through completely unchanged — no redaction, no
        modification, no annotation.  The risk_metadata dict is empty; a
        future Evidence Risk Assessment stage will populate it.
        """
        def _free_text(tf: TrustedField | None) -> TrustedField | None:
            """
            Accept a TrustedField from the normalizer and ensure it carries
            FREE_TEXT trust.  The normalizer already classified these correctly;
            this is a defence-in-depth assertion.
            """
            if tf is None:
                return None
            if tf.trust_level != TrustLevel.FREE_TEXT:
                # Normalizer mis-classified this field — wrap it correctly
                return TrustedField(
                    value=tf.value,
                    trust_level=TrustLevel.FREE_TEXT,
                    source_system=tf.source_system,
                )
            return tf

        return Evidence(
            process_name=_free_text(alert.process_name),
            command_line=_free_text(alert.command_line),
            registry_key=_free_text(alert.registry_key),
            parent_process=_free_text(alert.parent_process),
            file_path=_free_text(alert.file_path),
            raw_log_line=_free_text(alert.raw_log_line),
            risk_metadata={},  # Phase 2 (ERA) will populate this
        )


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_default_contextualizer = Contextualizer()


def contextualize_alert(alert: Alert) -> EnrichedIncident:
    """Convenience wrapper using the default Contextualizer."""
    return _default_contextualizer.contextualize(alert)
