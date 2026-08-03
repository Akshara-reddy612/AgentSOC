"""
risk_assessment/__init__.py

Evidence Risk Assessment (ERA) package — Phase 2.

Session 1 builds:
  - config        : central tunable constants
  - exemplars     : known injection phrases
  - results       : shared result types (NormalizationResult, DetectorResult, etc.)
  - normalization : normalization pipeline (unicode, homoglyph, whitespace, base64)
  - detectors/base: FieldDetector and IncidentDetector abstract interfaces
  - detectors/regex_detector   : literal/pattern-based FieldDetector
  - detectors/semantic_detector: embedding-based FieldDetector (all-MiniLM-L6-v2)

Session 2 will add:
  - detectors/split_field_detector : IncidentDetector (cross-field injection)
  - detectors/registry             : detector registry
  - orchestrator                   : combines detector results into RiskAssessmentBundle
  - integration                    : adapts results → Evidence.risk_metadata
  - prompt_construction/           : safe prompt assembly
"""
