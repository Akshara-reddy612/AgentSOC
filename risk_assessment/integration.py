"""
risk_assessment/integration.py

Integration adapter: the ONLY module in Phase 2 allowed to import both
risk_assessment internals and perception.models.

Responsibility
--------------
This module bridges Phase 2's risk assessment output (RiskAssessmentBundle)
with Phase 1's domain objects (Evidence, EnrichedIncident).  It performs the
actual ``evidence.risk_metadata = result.to_dict()`` assignments and updates
``EnrichedIncident.era_metadata`` with the full bundle serialization.

Design contract (non-negotiable)
----------------------------------
1. ``risk_metadata`` on each Evidence TrustedField-carrying attribute is
   populated EXCLUSIVELY by calling ``RiskAssessmentResult.to_dict()`` on the
   corresponding result from the bundle.  It is never assembled independently.
   This is the SINGLE source of truth guarantee from Session 1's design rules.

2. The orchestrator (orchestrator.py) is pure — it never mutates Evidence.
   Only THIS module mutates Evidence.risk_metadata and EnrichedIncident.era_metadata.

3. The original ``value`` of any TrustedField is NEVER modified.

Usage
-----
    from risk_assessment.orchestrator import assess
    from risk_assessment.integration import attach_risk_metadata

    bundle = assess(incident.evidence)
    attach_risk_metadata(bundle, incident)
    # After this call:
    #   incident.evidence.risk_metadata["field_results"]["command_line"] == ...
    #   incident.era_metadata == bundle.to_dict()
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from risk_assessment.results import RiskAssessmentBundle

if TYPE_CHECKING:
    from perception.models import EnrichedIncident

# Evidence field names that may appear in a bundle's field_results.
# Must match the attribute names on perception.models.Evidence.
_EVIDENCE_FIELD_NAMES: frozenset[str] = frozenset({
    "process_name",
    "command_line",
    "registry_key",
    "parent_process",
    "file_path",
    "raw_log_line",
})


def attach_risk_metadata(
    bundle: RiskAssessmentBundle,
    incident: "EnrichedIncident",
) -> None:
    """
    Populate ``Evidence.risk_metadata`` and ``EnrichedIncident.era_metadata``
    from a RiskAssessmentBundle.

    This is the ONLY function in the codebase that writes to
    ``Evidence.risk_metadata``.  It derives the dict content exclusively from
    ``RiskAssessmentResult.to_dict()`` — never assembling it independently.

    Parameters
    ----------
    bundle : RiskAssessmentBundle
        The authoritative assessment produced by ``orchestrator.assess()``.
    incident : EnrichedIncident
        The incident whose evidence will be annotated.  The original
        ``TrustedField.value`` attributes are never touched; only
        ``Evidence.risk_metadata`` (a plain dict) is updated.

    Side Effects
    ------------
    - Sets ``incident.evidence.risk_metadata`` to a structured dict with keys:
        ``field_results``   : dict keyed by field name → per-field risk dict
        ``incident_result`` : incident-level risk dict (or None)
    - Sets ``incident.era_metadata`` to ``bundle.to_dict()`` — the full
      serialized bundle, for downstream use by SPC and logging.

    Notes
    -----
    Evidence.risk_metadata is replaced wholesale on each call, not merged.
    This ensures no stale data from a previous assessment persists.  If you
    need to preserve prior metadata, snapshot it before calling this function.
    """
    # Build the structured risk_metadata dict.
    # ALL content is derived via .to_dict() — never assembled independently.
    field_risk_dicts: dict[str, Any] = {}
    for field_name, field_result in bundle.field_results.items():
        if field_name in _EVIDENCE_FIELD_NAMES:
            # .to_dict() is the single definition of the dict shape (results.py)
            field_risk_dicts[field_name] = field_result.to_dict()

    incident_risk_dict: Any = (
        bundle.incident_result.to_dict()
        if bundle.incident_result is not None
        else None
    )

    from types import MappingProxyType

    def _make_immutable_dict(d: dict[str, Any]) -> MappingProxyType:
        return MappingProxyType({
            k: _make_immutable_dict(v) if isinstance(v, dict) else v
            for k, v in d.items()
        })

    # Assign to Evidence.risk_metadata — Evidence is now frozen.
    risk_metadata_dict = {
        "field_results": field_risk_dicts,
        "incident_result": incident_risk_dict,
    }
    object.__setattr__(
        incident.evidence,
        "risk_metadata",
        _make_immutable_dict(risk_metadata_dict)
    )

    # Also populate the EnrichedIncident-level era_metadata extension point.
    # This is the full serialized bundle for use by downstream phases.
    incident.era_metadata = bundle.to_dict()
