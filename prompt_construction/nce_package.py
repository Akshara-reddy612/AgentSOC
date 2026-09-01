"""
prompt_construction/nce_package.py

NCEPromptPackage — the structured intermediate representation for NCE prompt
construction.

Design
------
Mirrors PromptPackage's separation of "build" from "serialize" so that
alternate output formats (JSON, Markdown, etc.) can be added later without
touching the builder logic.

CRITICAL DESIGN INVARIANT:
    NCEPromptPackage has NO trusted_context field — not empty, not optional,
    structurally absent.  NCE receives evidence-only input by design: it must
    NEVER see Knowledge Store context, ImmutableContext, or DerivedContext.
    This makes the boundary structurally obvious to anyone reading the code —
    if a future contributor tries to add trusted context to NCE's prompt,
    they must first add a field to this dataclass, making the design violation
    visible in code review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class NCEPromptPackage:
    """
    Structured intermediate representation of an NCE prompt.

    Attributes
    ----------
    incident_id : str
        Unique identifier for the incident being analyzed.

    evidence : dict[str, str]
        field_name → raw untrusted value (unescaped — escaping happens at
        serialization time, exactly like PromptPackage does for the verdict
        flow).  Values are the plain strings from NCEInput.evidence_fields,
        possibly truncated to MAX_PROMPT_FIELD_LENGTH.

    instructions : str
        A fixed system-authored string framing the evidence as data to be
        analyzed and specifying NCE's hypothesis-generation task.  Written
        by the pipeline, never derived from any evidence field.

    metadata : dict[str, Any]
        Provenance and truncation information:
            nce_builder_version : str  — from NCE_BUILDER_VERSION constant
            nce_schema_version  : str  — from NCE_SCHEMA_VERSION constant
            generated_at        : str  — UTC ISO-8601 timestamp (build time)
            incident_id         : str  — echoed for traceability
        Optional per-field truncation keys (added when a field is truncated):
            truncated_fields : dict[field_name, TruncationInfo]
                TruncationInfo = {
                    "was_truncated": True,
                    "original_length": int,
                    "included_length": int,
                }

    NOTE: There is intentionally NO trusted_context field.  See module
    docstring for the design rationale.
    """

    incident_id: str
    evidence: dict[str, str]
    instructions: str
    metadata: dict[str, Any] = field(default_factory=dict)
