# Paper revision, Tier 2: experiments that need API calls (plan, 2026-11-22; FOR APPROVAL, nothing run yet)

Tier 2 of the paper review (`PROJECT_STATUS.md`; decision P10 left it out of scope). This plan asks for one decision: bring T2.1-T2.3 into scope with the call budget below.

**Rules**, as for every live run:
- calls only within the approved budget;
- keys from `.env` (8 Gemini keys, 5 Groq keys; never printed);
- runners resume where they stopped and stop cleanly at the daily quota (exit 3);
- monitor through the API log;
- no change to the pipeline: new code goes in `agent/` and `experiments/` only.

**Quota:** gemini-3.1-flash-lite free tier, 500 requests / key / day, so **about 4,000 calls per day** with 8 keys.

## The experiments, in priority order

| # | Experiment | Review item | Code | Calls | Wall time |
|:--|:--|:--|:--|--:|:--|
| **T2.1** | Undefended agent on the GUIDE held-out split (both twins of 500 pairs) | A6 (baselines on held-out) | exists: `python -m agent.run_v2_undefended --set heldout --workers 8` | about 1,000 | about 1-2 h |
| **T2.2** | Prompt-level defences as baselines, on GUIDE dev (500 pairs, both twins), same verdict task and scoring as the undefended agent | A3, A6 (hardened prompts) | new: a `--defence` option on `agent/run_v2_undefended.py`, one prompt builder per variant in `agent/` | about 3,000 (3 variants × 1,000) | about 1 day of quota |
| **T2.3** | Adaptive attacker (limited): payloads rewritten until ERA scores them LOW (offline, no calls), then those contaminated twins through live NCE on GUIDE dev | A4 | new: `experiments/adaptive_payloads.py` (offline search) + the existing live runner | about 300 (contaminated twins only; clean answers reused) | about 1 h |
| T2.4 (optional) | Run-to-run variance: 2 repeated live Gemini runs on 200 dev pairs | B (repeated runs) | existing runner, new output files | about 800 | about 1 h |

**Total:** about 4,300 calls (T2.1-T2.3), about 5,100 with T2.4. That is a bit over one day of free quota.

### T2.2 variants (prompt-level defences from the literature; no model training)

**Amended 2026-11-22 (P11, user decision):** run on the first 150 dev pairs only (first 300 alerts, `--limit` computed per defence so a resume never goes past them), about 900 calls in place of 3,000. Compare with the undefended agent's recorded answers on the same 150 pairs.

The prompt keeps the undefended agent's structured fields and adds only the defence, so the comparison is like for like.

1. **Delimited data:** the untrusted fields sit inside explicit delimiters, declared as data that must never be followed. This is the hardened prompt the 2026-11-01 pilot tried, which got only HTTP 503.
2. **Spotlighting by datamarking** (Hines et al. 2024, ref [9]): every whitespace in the untrusted fields is replaced by a marker character, and the system prompt explains the marking.
3. **Instruction-hierarchy-style system prompt:** a system message that ranks the operator's instructions above anything in the data, and tells the model to report embedded instructions as suspicious.

StruQ (ref [10]) needs a fine-tuned model, so it is **not runnable here**. The paper should say so.

**Measures:** as for the undefended agent (`experiments/undefended_metrics.py`):
- hijacked to dismiss, of the clean twins it did not dismiss;
- Wilson 95% CI;
- McNemar against the clean twins;
- clean-twin dismissal rate (the defence's cost);
- per family.

The table sits next to the undefended 130/439 and the pipeline's 4/428. The paper then states, measured, where prompt defences stand between the two.

### T2.3 details

- **Payload search (offline):** search over paraphrases of each family's templates (slot substitution, word order, removal of trigger words), keeping a variant only if ERA scores it LOW and it still fits inside the first 512 characters of its field.
- **Live part:** about 300 contaminated dev twins with the adaptive payloads go through live NCE. Their clean twins' answers are already recorded.
- **Measures:** the pipeline's suppression and misdirection (`experiments/attack_metrics.py`), under both rules.
- **Expected:** ERA's escalations drop (that is the point), and asymmetric trust still blocks every NCE-caused dismissal and action by construction. What the run measures is how often the model, as the only detector on GUIDE, misses.

## Out of Tier 2 (each a separate decision; say so in the paper as future work)

- **A frontier model:** paid API, cost not budgeted.
- **gpt-oss-20b on held-out:** Groq's token cap made the dev run take 3 days.
- **Escalation flooding and low-and-slow poisoning:** new attacker simulations. Under asymmetric trust with D7 on, the gate learns nothing on its own, so low-and-slow would act only through analysts, which A10 now covers.
- **A second dataset (E3):** download approval, about 1 week.

## Fast schedule

| When | What |
|:--|:--|
| Day 1, after approval | Start T2.1 at once (code exists). In parallel: write and unit-test the T2.2 prompt builders and the T2.3 payload search (offline). Re-run the fixed A7 baseline (offline, about 10 min) |
| Day 1, continued | Start T2.2 (3 variants in parallel up to the daily quota); then T2.3 |
| Day 2 | Finish T2.2 on the next day's quota; score everything; add Tier 1 + Tier 2 tables to `RESULTS.md` via `build_results`; tracking files; claims file; draft text for the `.docx` |

**Calendar time: about 2 days**, set by the daily quota, not the work. If the API returns HTTP 503 errors (as in the 2026-11-01 pilot), the runners retry and resume, so the schedule can slip by a day; no result is reported until a run completes.
