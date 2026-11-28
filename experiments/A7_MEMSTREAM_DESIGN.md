# A7: MemStream as a learned-memory baseline on DEDALE (design, 2026-11-28; revised the same day after checks)

Review item A7: "an empty store is a straw man". The frozen allowlist and the rarity threshold (K = 2, 5, 10;
`tier1_scores.json`) are the simple baselines. Neither is a *learned* memory. MemStream (Bhatia et al., WWW 2022,
already cited) is a streaming anomaly detector with a memory that updates itself and has its own guard
against poisoning. That makes it the natural published counterpart to the gated store.

## Questions

1. Without fixing a threshold, how does MemStream's trade-off between attack coverage and benign alerts
   compare with the keyed store's operating point?
2. At the same review workload, does it raise as many of the 72 attack cases?
3. Its memory updates without an analyst. Do the A8 plants (harmless runs of the attacker's tools) get into
   that memory, and does the later attack then go quiet?
4. Can MemStream *cut* the keyed store's workload? An alert would need both a novel key and a MemStream anomaly.

## The algorithm, as checked against the reference code and paper (2026-11-28)

Sources: `code/memstream-knn.py` and `code/memstream.py` in github.com/Stream-AD/MemStream (Apache-2.0), and
arXiv 2106.03837v2. I write our own implementation from these; nothing is downloaded or installed.

- **Autoencoder:** encoder `Linear(d, 2d)` + Tanh, decoder `Linear(2d, d)`. Denoising noise `0.001 * randn`,
  MSE loss. Adam with lr 1e-2, 5000 full-batch epochs on the N initial points. The encoder is never retrained.
- **Normalisation:** mean / std of the raw records held in memory, recomputed whenever the memory changes
  (incremental sums here). Features whose std is 0 are set to 0.
- **Score:** L1 distance to the memory, over the K = 3 nearest, discounted by γ (default 0, which is the
  nearest-neighbour distance). Each record is scored before any update.
- **Update:** if score ≤ β, the record's encoding replaces the oldest memory slot (FIFO). This is the
  poisoning guard.
- **Defaults:** N = 2048 and β = 0.1, as in the code and as reported for NSL-KDD / UNSW. The paper's per-dataset
  table and its β grid were read only through a summary, so they are not cited from it. Re-check Table 8 in the
  PDF before quoting.

## Input (the same universe the keyed store sees)

- **Events:** only those some detector keys: 3,459,514 in training and 3,142,395 in the test period (counted
  2026-11-28, of 13.5 M host events). They are file writes 1.31 M, pipes 1.25 M, process starts 0.46 M,
  PowerShell 66 k, logons 45 k and LSASS reads 15 k (test figures).
- **Features (invariant I1):**
  - host, event type and detector, image, parent image, user, logon type, source address, pipe (digits blanked),
    written file extension, and the PowerShell fingerprint (never the text);
  - feature-hashed to d = 128, plus hour of day (sin / cos);
  - no command line or script text.
  - d = 128 rather than 256 keeps one pass to about 30 min on CPU.
- **Stream:** time order. Memory initialised from the first N training records, as the reference code does;
  the rest of the training weeks then stream through with updates. Variant: initial memory and autoencoder
  from a uniform sample of N training records, a stronger baseline, run at the best β only.

## Changes made during implementation (2026-11-28, before any result)

- **Stream start.** MemStream streams from 24 h before the test period, or before the first plant. Every day
  brings far more than N = 2048 accepted updates, and the FIFO memory evicts everything older, so its state at the
  start of the test period does not depend on the earlier weeks. This roughly halves the cost (about 3.4 M records
  per pass).
- **Feature width.** Hashed width is d = 64 (DIM 66): 0.4-0.8 ms per record, against 2.3 ms at d = 130.
- **Pure MemStream runs the store in `static` mode, not `frozen`.** Triage closes an alert whose key the store
  learned as routine as LOW_PRIORITY (`triage_gate.py`), so a `frozen` store would silently add the keyed store's
  memory to the baseline. `frozen` + MemStream *is* stage 4, the combination.
- **β grid** {0.3, 1, 3, 10, 30, 100}, not the reference grid (≤ 10). A pilot of 50,000 records against the
  initial memory scored 2-114, median 53. On this scale the reference grid admits only a few percent of records.
- **Both initialisations over the whole grid** (12 passes). The reference code's first N records are the first
  minutes of the training weeks and nearly identical (autoencoder loss 5e-5), so the uniform sample is the fairer
  baseline.
- **Code:** `experiments/memstream.py`, `memstream_eval.py` (score, curve), `memstream_loop.py` (the replay hook:
  `--memstream-scores TAG --memstream-tau X`) and `a7_runs.py`. Tests: `tests/test_memstream.py` (7).

- **Event-level results, recorded 2026-11-28, before any loop replay:**
  - **First-N init:** near chance at every β (b3: 235/473 attack events at a 50% alert rate). With the reference
    initialisation the memory spans a few minutes, so the hour feature's spread is near zero and scores track time
    of day. This is reported as a property of the reference initialisation on this data, not as MemStream's ceiling.
  - **Sampled init:** at the keyed store's benign rate (102.4 benign events/day) the best β (0.3, 1) alerts 9 of 473
    labelled attack events, against the keyed store's 400. β that admit more records do worse.
- **Stage 3 (plants) dropped:** at matched workload MemStream raises almost no attack event without an attacker, so
  plants have nothing left to hide, and two more scoring passes (~50 min each) would not change the conclusion.
  Stages 2 and 4 run with `b1_sample`.

## Stages

1. **Event level, no replay:**
   - one scoring pass per β in {1e-4, 1e-3, 1e-2, 0.1, 1, 10}, run in parallel, plus the sampled-init variant;
   - for each, the curve of labelled attack events alerted against benign alerted events per day as τ varies;
   - the keyed store's frozen and gated points go on the same axes;
   - β is the one best *for MemStream* on the labels. This is optimistic for the baseline, and the text says so.
2. **Through the loop (best β):**
   - an experiment-side `SocLoop` subclass in which MemStream decides novelty;
   - the store runs in `frozen` mode, so triage has exactly the frozen baseline's context;
   - no pipeline module changes;
   - τ is set (i) so that reviews/day match the gated store's 65.2 (bisection, at most 5 replays), and (ii) by
     MemStream-style calibration, the 99.9th percentile of training scores.
3. **Plants:** `test` and `slow` plants merged into MemStream's stream, so they are scored in-stream as the
   replay merges them. Count the plant encodings admitted to memory, then the attack events and cases raised.
4. **Combination:** a keyed novel alert is kept only if MemStream also scores its event above τ, at two τ
   values. This measures workload saved against attack cases lost.

## Measures

- reviews/day, attack cases raised (of 72), labelled attack events alerted, precision and event-level FPR (as A9);
- plant records admitted to memory.

## Predictions (written before any run)

- Its curve lies below the keyed store's point. At the gated store's workload it raises fewer attack cases,
  because rare benign events on 30 clients score as high as the attack does when there are no per-host keys.
- Plants are novel, score above β and stay out of memory. So conditioning without an analyst fails here too;
  the contrast is in cost and coverage.
- The combination cuts some workload but loses attack cases. The keyed store's novelty is what carries the attack.

## Outputs, tests, cost

- `experiments/memstream.py` (the model), `experiments/memstream_eval.py` (stages) ->
  `experiments/dedale_results/a7_memstream_scores.json`, and a RESULTS.md section.
- Score files go to `<data>/runs/a7_memstream/`, not into the repository.
- **Tests:**
  - the update rule (score ≤ β replaces the oldest slot, above β does not);
  - normalisation follows the memory;
  - K / γ scoring against a hand computation;
  - determinism under a seed;
  - no `cmd` / `script` text in the features.
- **Cost:** no API calls, downloads or installs. About 7 scoring passes of about 30 min each, in parallel, plus
  about 10 replays of about 2 min.
