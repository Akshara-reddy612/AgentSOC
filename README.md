# Trust-Aware Perception Layer for Agentic SOC Pipelines

**Phase 1 — Research prototype for mitigating Data-to-Prompt Log Contamination attacks**

---

## Overview

AgentSOC-style pipelines feed raw security alerts into an LLM-based reasoning module.  The Perception Layer normalises heterogeneous alert data before it reaches that module.  The core vulnerability: if the Perception Layer never classifies which fields are *attacker-controlled free text* vs *trusted structured data*, an attacker can embed natural-language directives inside fields like process names or registry keys and later hijack the downstream LLM.

This prototype implements the Perception Layer with an explicit **trust-separation** architecture that makes that contamination path structurally impossible.

---

## Pipeline Diagram

```
Raw Alerts  (JSON dicts from EDR, SIEM, Windows Event Log, …)
      │
      ▼
┌─────────────────────┐
│  Alert Normalization│  Maps raw fields → unified Alert schema.
│  (normalizer.py)    │  Classifies every field as STRUCTURED or FREE_TEXT.
│                     │  Fail-safe: unknown fields → FREE_TEXT.
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Schema Validation  │  Validates the Alert before contextualization.
│  (schema_validation │  Returns machine-readable error codes on failure:
│   .py)              │    SCHEMA_001 Missing Required Field
│                     │    SCHEMA_002 Invalid Timestamp
│                     │    SCHEMA_003 Unsupported Event Type
│                     │    SCHEMA_004 Invalid Data Type
│                     │  Never silently repairs malformed alerts.
└──────────┬──────────┘
           │  (invalid alerts are rejected here — do not proceed)
           ▼
┌─────────────────────┐
│  Situational        │  Produces EnrichedIncident with THREE SEPARATE objects.
│  Contextualization  │  (internally: KnowledgeStore lookups → ImmutableContext,
│  (contextualizer.py)│   then compute_* rules → DerivedContext,
│                     │   then free-text extraction → Evidence)
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Noise Reduction    │  Deduplicates/clusters by structural keys only:
│  (noise_reducer.py) │    (source_user, target_host, event_type, derived flags)
│                     │  FREE_TEXT fields NEVER used in cluster key.
│                     │  Each cluster retains: occurrence_count, first_seen,
│                     │  last_seen, representative EnrichedIncident.
└──────────┬──────────┘
           │
           ▼
  Enriched Incident Clusters  →  downstream reasoning (Phase 2+, not built)
```

*Note: If Knowledge Store lookup needs to be separately timed in a future phase, it would require its own `StageLogger` block added to `contextualizer.py`.*

---

## Trust-Separation Principle

### Why attacker-controlled evidence must never influence derived context

In a standard SOC pipeline an attacker who controls the value of a log field (process name, command line, registry key) effectively controls a string that will eventually be embedded in an LLM prompt.  If the pipeline ever uses that string to *compute* a security flag (e.g. "this looks like privilege escalation because the process name contains 'psexec'"), the attacker can craft a value that flips that flag.

This prototype enforces a hard structural boundary:

| Concept | Trust level | Can influence DerivedContext? |
|---------|-------------|-------------------------------|
| `ImmutableContext` | `STRUCTURED` | **Yes — it's the only input** |
| `DerivedContext` | `DERIVED` | N/A (output) |
| `Evidence` | `FREE_TEXT` | **No — TypeError at runtime** |

Enforcement layers (defence-in-depth):

1. **Type annotation** — `compute_*` functions are annotated `(context: ImmutableContext)`.
2. **Runtime `isinstance()` guard** — passing `Evidence` raises `TypeError` immediately; it is *not* a silent no-op.
3. **Dataclass-level rejection** — `ImmutableContext.__post_init__` rejects any `TrustedField` that does not carry `TrustLevel.STRUCTURED`; `DerivedContext.__post_init__` rejects anything not `DERIVED`.
4. **Immutability** — `TrustedField` is a frozen dataclass; trust metadata cannot be changed after construction.
5. **Log redaction** — pipeline log summaries contain only field counts by trust level, never raw free-text values.

---

## Project Structure

```
perception/
    models.py               TrustLevel, TrustedField, ImmutableContext,
                            DerivedContext, Evidence, Alert, EnrichedIncident
    source_systems.py       SourceSystem enum (strongly typed, rejects unknown strings)
    knowledge_store.py      KnowledgeFact, InMemoryKnowledgeStore
    schema_validation.py    AlertSchemaValidator, ValidationResult, error codes
    normalizer.py           AlertNormalizer (STRUCTURED/FREE_TEXT classification)
    derived_context_rules.py  compute_* pure functions + build_derived_context
    contextualizer.py       Contextualizer → EnrichedIncident
    noise_reducer.py        NoiseReducer → IncidentCluster
    pipeline_logging.py     StageLogger, PipelineLogEntry, redacted summaries
    pipeline.py             PerceptionPipeline orchestrator
tests/
    test_perception.py      51 unit tests covering all 11 specified test cases
sample_data/
    sample_alerts.json      4 sample alerts (benign, injection, malformed, duplicate)
demo.py                     End-to-end demonstration
requirements.txt            pytest, pytest-cov (stdlib only for production code)
```

---

## Quick Start

```bash
# 1. Create and activate the virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows PowerShell
# source .venv/bin/activate     # Linux/macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the test suite
python -m pytest tests/ -v

# 4. Run the demo
python demo.py
```

---

## Running Tests

```
pytest tests/ -v
```

Expected: **51 passed**.

Test cases cover all 11 specified scenarios:

| # | What is tested |
|---|----------------|
| 1 | `TrustedField` is frozen — attribute assignment raises `FrozenInstanceError` |
| 2 | `TrustedField` rejects non-UUID `evidence_id` and naive `provenance_timestamp` |
| 3 | `SourceSystem.from_string()` rejects unrecognised strings |
| 4 | `ImmutableContext`/`DerivedContext` reject FREE_TEXT-labelled fields |
| 5 | Each `compute_*` function raises `TypeError` when passed `Evidence` |
| 6 | Malformed alert rejected by Schema Validation with correct `SCHEMA_0xx` code |
| 7 | Injection string in free-text field does not affect `DerivedContext` flags |
| 8 | Noise reduction merges true duplicates; `occurrence_count`/`first_seen`/`last_seen` correct |
| 9 | Determinism: same `ImmutableContext` → identical output every call |
| 10 | `KnowledgeFact` rejects `confidence` outside `[0.0, 1.0]` |
| 11 | Pipeline log for injection-containing alert contains no raw free-text values |

---

## Not Built Yet / Future Phases

The data model was explicitly designed to accept these additions without breaking changes (extension slots are already present as `None` fields on `EnrichedIncident`):

| Phase | Component | Status |
|-------|-----------|--------|
| 2 | Evidence Risk Assessment (ERA) — suspicion scoring, pattern matching, embedding similarity, detector outputs; populates `Evidence.risk_metadata` without touching `value` | **Not built** |
| 3 | Safe Prompt Construction — assembles a structured prompt from `ImmutableContext` + `DerivedContext` only; Evidence content admitted only via ERA-scored summaries | **Not built** |
| 4 | LLM Reasoning Integration — agentic reasoning module over the safe prompt | **Not built** |
| 5 | Output Validation — validates LLM outputs before action-layer execution; latency evaluation using `PipelineLogEntry` data already collected | **Not built** |
| — | Action Layer | **Not built** |
| — | Evaluation harness | **Not built** |

---

## Design Decisions

- **No external dependencies** in production code — only stdlib (`dataclasses`, `uuid`, `datetime`, `enum`, `logging`, `json`, `collections`).  `pytest` is the only dependency.
- **UUIDv4** chosen for `evidence_id` (standard, toolchain-supported, sufficient entropy).
- **In-memory knowledge store** for Phase 1.  The `Contextualizer` accepts any store via its constructor; SQLite or a real identity store can be injected without touching pipeline code.
- **Fail-safe FREE_TEXT default** in the normalizer — unknown fields can never accidentally be classified as STRUCTURED and flow into derived context.
- **Frozen dataclasses** for `TrustedField`, `ImmutableContext`, `DerivedContext` — Python's `FrozenInstanceError` on reassignment, plus `__post_init__` validation on construction.
