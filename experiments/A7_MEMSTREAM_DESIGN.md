# A7: MemStream as a learned-memory baseline on DEDALE (design, 2026-11-28; FOR APPROVAL, nothing run)

Review item A7: "an empty store is a straw man". The frozen allowlist and the rarity threshold (K = 2, 5, 10;
`tier1_scores.json`) are the simple baselines. Neither is a *learned* memory. MemStream (Bhatia et al., WWW 2022,
already cited) is a streaming anomaly detector with a memory that updates itself and has its own guard
against poisoning. That makes it the natural published counterpart to the gated store.

## Questions

1. At the same review workload, does MemStream raise as many of the 72 attack cases and 400 labelled events
   as the keyed store?
2. Its memory updates without an analyst. Does the A8 conditioning attack (harmless runs of the attacker's tools)
   get into that memory, and does the later attack then go quiet?

## Method (experiment code only; no pipeline module changes)

- **Implementation:** `experiments/memstream.py`, written from the paper (no download; torch is installed):
  - a denoising autoencoder (encoder `Linear(d, 2d)` + tanh, as in the paper), trained on the clean training
    weeks;
  - a FIFO memory of N encodings, initialised from training;
  - score = discounted mean L1 distance to the K nearest memory entries;
  - an event whose score is below β replaces the oldest memory entry. This is MemStream's poisoning guard.
  - Fixed seed.
- **Features (invariant I1):**
  - the structured fields the detectors key on: host, image, parent image, user, logon type, source address,
    pipe, written file extension, target image, the PowerShell fingerprint (never the text), and the event type;
  - feature-hashed to d = 256, plus hour of day (sin / cos);
  - no command line or script text.
- **Alerts:** an event with a score above τ becomes a host alert. The replay gets `--novelty memstream
  --memstream-scores <file>`:
  - scores are computed once into a file under `<data>/runs/` (MemStream is self-contained and needs no
    store feedback);
  - the alert then goes through the same case builder, triage gate and scorer;
  - detector-key learning is off in this mode, because MemStream is the memory.
- **τ, two ways:**
  - (i) matched workload: τ set so that test-period reviews/day equal the gated store's 65.2;
  - (ii) MemStream's own rule: the 99.9th percentile of training scores.
- **Hyperparameters:** paper defaults (N = 256 here, K = 3, γ = 0); β swept over 3 values (the paper's main knob).

## Conditions (offline replays, NCE off, no analyst; about 2 min each, as `dedale_host_gated`)

| # | Condition | Replays |
|--:|:--|--:|
| 1 | clean, β × {low, mid, high}, τ by (i) and (ii) | 6 |
| 2 | A8 test-period plants (`--plant test`), best β from row 1, τ (i) | 1 |
| 3 | A8 slow plants (`--plant slow`), same | 1 |

**Measures:** reviews/day, attack cases raised (of 72), labelled events alerted (of 400), precision and
event-level FPR (as A9). Plants: memory entries taken from plant events, and attack cases raised after them.

## Predictions (written before any run)

- At matched workload MemStream raises fewer attack cases than the keyed store. Rare benign events score as
  high as attacks when there are no per-host keys.
- Plants are novel, so they score above β and do not enter memory. Conditioning without an analyst fails
  against MemStream as it does against the gated store. The contrast is in Q1 (cost and coverage), not Q2.

## Outputs, tests, cost

- `experiments/memstream_eval.py` -> `experiments/dedale_results/a7_memstream_scores.json`, and a RESULTS.md
  section built by `build_results.py`.
- Tests: the memory update rule (below β replaces the oldest entry, above β does not), determinism under a
  seed, and that no `cmd` / `script` text reaches the features.
- No API calls, downloads or installs. CPU only. The event count, and so the scoring time, is measured
  before the runs and reported.
