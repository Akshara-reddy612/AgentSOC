"""
risk_assessment/registry.py

Detector registry for Evidence Risk Assessment (ERA).

Single source of truth for which detectors are active.  The orchestrator
imports these two lists; nothing else in the codebase constructs detector
instances independently.

Two separate lists — by design
-------------------------------
FIELD_DETECTORS and INCIDENT_DETECTORS are deliberately NOT merged into one
list.  Their input shapes are fundamentally different:

  FieldDetector.detect(normalized_text, decoded_candidates)  →  single field
  IncidentDetector.detect(all_fields)                        →  whole incident

Conflating them would require detectors to accept arguments they don't need,
obscure the type contract, and make it harder to add new detectors to only one
category.  The orchestrator dispatches to each list separately, at separate
points in its processing loop.

Singleton instances
-------------------
Each detector is instantiated exactly once here and reused across all calls.
The SemanticDetector already caches its model at module level; creating multiple
instances would be wasteful even though the model is only loaded once.
"""

from __future__ import annotations

from risk_assessment.detectors.approval_claim_detector import (
    ApprovalClaimDetector,
)
from risk_assessment.detectors.base import FieldDetector, IncidentDetector
from risk_assessment.detectors.regex_detector import RegexDetector
from risk_assessment.detectors.semantic_detector import SemanticDetector
from risk_assessment.detectors.split_field_detector import SplitFieldDetector

# ---------------------------------------------------------------------------
# Active field detectors (run per evidence field, in registration order)
# ---------------------------------------------------------------------------

FIELD_DETECTORS: list[FieldDetector] = [
    RegexDetector(),
    SemanticDetector(),
    ApprovalClaimDetector(),
]

# ---------------------------------------------------------------------------
# Active incident detectors (run across all fields together, in order)
# ---------------------------------------------------------------------------

INCIDENT_DETECTORS: list[IncidentDetector] = [
    SplitFieldDetector(),
]
