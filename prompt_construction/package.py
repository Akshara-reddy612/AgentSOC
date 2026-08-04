"""
prompt_construction/package.py

PromptPackage — the structured intermediate representation for safe prompt
construction.

Design
------
PromptPackage separates trusted context from untrusted evidence at the data
layer, before any serialization occurs.  Serializers (serializers.py) consume
a PromptPackage and produce a string — they never receive raw Evidence objects.

This decoupling means:
- Adding a new serializer (JSON, Markdown, etc.) requires no changes to this
  module or to the safe prompt builder.
- The truncation logic lives in exactly one place (safe_prompt_builder.py),
  and the PromptPackage records what was truncated and why.
- The provenance metadata (builder_version, schema_version, generated_at) is
  captured at build time, not at serialization time.

Provenance metadata constants
------------------------------
BUILDER_VERSION and SCHEMA_VERSION are module-level constants defined here
and referenced in the ``metadata`` dict that every PromptPackage carries.
They are NOT passed as arguments to any function — they are read from the
module to ensure there is exactly one definition.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Module-level provenance constants
# Single definition; referenced by safe_prompt_builder.py at build time.
# ---------------------------------------------------------------------------

BUILDER_VERSION: str = "phase2"
SCHEMA_VERSION: str = "1.0"


from types import MappingProxyType

def _make_immutable_dict(d: dict[str, Any]) -> MappingProxyType:
    return MappingProxyType({
        k: _make_immutable_dict(v) if isinstance(v, dict) else v
        for k, v in d.items()
    })

@dataclass(frozen=True)
class PromptPackage:
    """
    Structured intermediate representation of a safe prompt.

    Attributes
    ----------
    trusted_context : dict
        Facts derived from ImmutableContext and DerivedContext only.
        All values carry TrustLevel.STRUCTURED or DERIVED — never FREE_TEXT.
        Serializers may render this block without additional escaping (though
        defensive escaping is always applied).

    untrusted_evidence : dict
        Evidence fields from the alert, including their risk_metadata.
        These values are attacker-controllable and MUST be:
        - Truncated to MAX_PROMPT_FIELD_LENGTH per field.
        - Escaped for the target serialization format (e.g. XML entity escaping).
        - Structurally isolated from trusted_context in the serialized output.

    instructions : str
        A fixed system-authored string framing the evidence as data to be
        analyzed, not instructions to follow.  Written by the pipeline, not
        derived from any alert field.

    metadata : dict
        Provenance and truncation information.  Required keys (set by
        safe_prompt_builder.py):
            builder_version : str  — from BUILDER_VERSION constant
            schema_version  : str  — from SCHEMA_VERSION constant
            generated_at    : str  — UTC ISO-8601 timestamp (build time)
        Optional per-field truncation keys (added when a field is truncated):
            truncated_fields : dict[field_name, TruncationInfo]
                TruncationInfo = {
                    "was_truncated": True,
                    "original_length": int,
                    "included_length": int,
                }
        Optional overall truncation key:
            total_was_truncated : bool
            total_original_length : int
            total_included_length : int
    """

    trusted_context: dict[str, Any]
    untrusted_evidence: dict[str, Any]
    instructions: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "trusted_context", _make_immutable_dict(self.trusted_context))
        object.__setattr__(self, "untrusted_evidence", _make_immutable_dict(self.untrusted_evidence))
        object.__setattr__(self, "metadata", _make_immutable_dict(self.metadata))
