# Paper checklist: live runs (proposed 2026-11-22, for approval)

The reviewer checklist items that need live LLM calls and that can run on the free Gemini quota. Everything is
coded, tested and queued in `tools/live_queue.sh`; nothing has run.

| Job | Checklist item | What it measures | Calls |
|:--|:--|:--|--:|
| `telemetry` | A6, fair baselines | The undefended agent given the pipeline's trusted context (target, destination and its reputation, role, criticality, zones, prior access, derived flags; `agent/prompt_defences.trusted_context`). It answers whether the 29.6% vs 0.9% gap is only about what each side knows. | 300 |
| `none`, temperature 0.7, repeats 1-3 | B1, run-to-run variance | The plain undefended prompt three times at temperature 0.7, giving the hijack rate as mean ± sd across repeats. This sits beside the recorded default-sampling run. | 900 |
| **Total** | | Same 150 GUIDE dev pairs (first 300 alerts) as T2.2, so every result is paired. | **1,200** + retries (about 1,500 attempts) |

- **Model:** gemini-3.1-flash-lite, the same as every recorded run.
- **Quota:** at about 60-150 calls per key-project per day, the 25+ keys in `.env` cover this after the daily reset (about 08:00 UTC, 13:30 IST).
- **Scoring:** `experiments/tier2_score.py`, which writes `experiments/tier2_scores.json`; then `experiments/build_results.py`, whose RESULTS.md Tier 2 section has the rows ready.

## Not included (needs a separate decision)

- **Frontier model (B1):** paid API.
- **StruQ (A3):** needs a fine-tuned model.
- **Escalation flooding, the ablation matrix, low-and-slow poisoning, window rotation (A3, A8, A11):** offline replays, with no API calls.
- **MemStream (A7):** new code.
