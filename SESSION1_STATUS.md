# Phase 2 Session 1 — Status Handoff

**Committed:** 2026-08-03  
**Tests:** 38 new passing (38 Session 1) + 51 Phase 1 = 89 total passing  
**New packages:** `sentence-transformers==5.6.1`, `confusables==1.2.0`

---

## What is built (Session 1)

| File | Purpose |
|------|---------|
| `risk_assessment/__init__.py` | Package init with session-boundary doc |
| `risk_assessment/config.py` | All tunable constants (weights, thresholds, limits), validated at import |
| `risk_assessment/exemplars.py` | 60+ known injection phrases in 7 categories, single source of truth |
| `risk_assessment/results.py` | `NormalizationResult`, `DetectorResult`, `RiskAssessmentResult` (with `.to_dict()`), `RiskAssessmentBundle` |
| `risk_assessment/normalization.py` | 4-step pipeline: NFKC → homoglyph → whitespace → base64 decode |
| `risk_assessment/detectors/base.py` | `FieldDetector` and `IncidentDetector` abstract interfaces |
| `risk_assessment/detectors/regex_detector.py` | `RegexDetector(FieldDetector)` — pattern-based, punctuation-tolerant |
| `risk_assessment/detectors/semantic_detector.py` | `SemanticDetector(FieldDetector)` — all-MiniLM-L6-v2 embeddings, singleton |
| `tests/test_risk_assessment_session1.py` | 38 tests covering all 7 spec categories |

## Key design decisions (do not re-litigate in Session 2)

- `REGEX_WEIGHT=0.25, SEMANTIC_WEIGHT=0.40, SPLIT_FIELD_WEIGHT=0.35` (user-chosen)
- Risk thresholds: LOW < 0.20, MEDIUM 0.20–0.50, HIGH ≥ 0.50 (user-chosen: strict)
- Homoglyph library: `confusables` PyPI (user-chosen)
- Semantic model: `all-MiniLM-L6-v2` cached at `~/.cache/huggingface/hub/` (~80MB)
- `RiskAssessmentResult.to_dict()` is the canonical dict shape for `Evidence.risk_metadata`
- `IncidentDetector` interface defined now; no concrete implementation yet

---

## What Session 2 must build (do NOT add now)

- `risk_assessment/detectors/split_field_detector.py` — `SplitFieldDetector(IncidentDetector)`
- `risk_assessment/detectors/registry.py` — detector registry
- `risk_assessment/orchestrator.py` — combines field + incident results into `RiskAssessmentBundle`
- `risk_assessment/integration.py` — adapts bundle → `Evidence.risk_metadata` via `.to_dict()`
- `risk_assessment/prompt_construction/` — safe prompt assembly using `MAX_PROMPT_FIELD_LENGTH`
- `tests/test_risk_assessment_session2.py`
- `demo_phase2.py`
- Sample adversarial data files

## Handoff notes for Session 2

1. `SINGLE_DETECTOR_CEILING_THRESHOLD = 0.90` is in config; the orchestrator
   must implement the ceiling logic: if any single detector's score exceeds this
   value, the overall risk level must be HIGH regardless of the weighted average.
2. `RiskAssessmentResult.risk_level` is derived at construction time from
   `_derive_risk_level(overall_score)` in `results.py` — the orchestrator
   does NOT need to compute this; it just sets `overall_score` correctly.
3. The semantic model singleton is in `semantic_detector._MODEL`; the orchestrator
   does NOT need to manage model lifecycle.
4. `SplitFieldDetector` receives `dict[str, NormalizationResult]` (all fields)
   — the orchestrator is responsible for calling normalization on each field
   before dispatching to detectors.
