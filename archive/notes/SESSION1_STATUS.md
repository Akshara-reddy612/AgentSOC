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

- `REGEX_WEIGHT=0.25, SEMANTIC_WEIGHT=0.40, SPLIT_FIELD_WEIGHT=0.35` (user-chosen — **provisional**, see below)
- Risk thresholds: LOW < 0.20, MEDIUM 0.20–0.50, HIGH ≥ 0.50 (user-chosen: strict — **provisional**, see below)
- Homoglyph library: `confusables==1.2.0` PyPI — **settled design choice**, not a numeric tunable (see below)
- Semantic model: `all-MiniLM-L6-v2` cached at `~/.cache/huggingface/hub/` (~80MB)
- `RiskAssessmentResult.to_dict()` is the canonical dict shape for `Evidence.risk_metadata`
- `IncidentDetector` interface defined now; no concrete implementation yet

---

## Provisional decisions — revisit before production

The three decisions below were made during the Session 1 elicitation as reasonable
starting points. They are **not empirically benchmarked values**. Do not treat them
as settled or correct — treat them as defaults that must survive contact with real
data before being trusted.

### 1. Detector weights (`REGEX_WEIGHT`, `SEMANTIC_WEIGHT`, `SPLIT_FIELD_WEIGHT`)

**Current values:** `0.25 / 0.40 / 0.35`  
**Status: Provisional numeric choices — not benchmarked.**

These weights were chosen on first principles (semantic catches paraphrases, so weight
it higher; split-field is structurally distinct, so weight it above regex). No labeled
dataset was used to derive or validate them.

`SPLIT_FIELD_WEIGHT` is **doubly provisional**: its detector (`SplitFieldDetector`)
does not exist until Session 2, so this weight has never been exercised against any
real or adversarial data at all. It is a placeholder that says "this category of
attack deserves about 35% of the final score" — a belief, not a measurement.

**What justifies changing them:** Run the full three-detector ensemble against labeled
GUIDE dataset samples (or a dedicated red-team adversarial set) once `SplitFieldDetector`
exists. Tune weights jointly using precision/recall on that held-out set. Do not
tune them individually — the weights only make sense as a simplex (they must sum to 1.0).

### 2. Risk level thresholds (`LOW_RISK_THRESHOLD`, `HIGH_RISK_THRESHOLD`)

**Current values:** LOW < 0.20, MEDIUM 0.20–0.50, HIGH ≥ 0.50  
**Status: Provisional — chosen strict by policy preference, not by empirical tuning.**

The reasoning at elicitation time was: "false negatives (missed injection) cost more
than false positives (analyst reviews a benign alert)", so thresholds were set
aggressively. This is a defensible starting position but it was not derived from
any measurement of false-positive rates on real benign traffic or false-negative
rates on real adversarial samples.

Setting HIGH at ≥ 0.50 means any overall score above the midpoint triggers escalation.
This will likely produce too many MEDIUM/HIGH labels on clean data until the weights
are calibrated. The two concerns (weight tuning and threshold tuning) are coupled —
**do not retune thresholds until weights are stabilized first**.

**What justifies changing them:** After weight tuning (see §1 above), measure
false-positive rate on a representative benign-alert corpus. If analyst alert
fatigue is unacceptably high, raise `HIGH_RISK_THRESHOLD` (e.g. to 0.65–0.70).
Do not lower `LOW_RISK_THRESHOLD` without evidence that the current value is
producing too many escalations on genuinely clean traffic.

### 3. Homoglyph library (`confusables==1.2.0`)

**Current value:** `confusables` PyPI library, version pinned at `1.2.0`  
**Status: Settled design/dependency choice — not a numeric tunable, not pending retuning.**

This is categorically different from the two decisions above: it is a library
selection, not a number to optimize. The choice (over a hand-crafted table) was
made because the Unicode Confusables standard (UTR #39) is the authoritative
mapping and `confusables` implements it correctly without requiring us to maintain
our own table.

The version is pinned at `1.2.0` in `requirements.txt` — this ensures reproducible
normalization behavior across environments. Upstream library updates may silently
expand or revise the confusables data, which would change normalization output for
existing evidence strings. **Do not bump the pinned version without reviewing the
upstream changelog for data changes** (not just API changes).

**What justifies changing it:** Only two reasons warrant switching away from
`confusables`: (a) the library is abandoned/broken, or (b) a security audit
identifies a meaningful class of homoglyph attacks that the Unicode standard
does not cover and a more comprehensive source exists. Routine upstream version
bumps are fine after changelog review.

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
