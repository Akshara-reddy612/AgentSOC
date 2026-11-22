# A10: the persuaded analyst (design, 2026-11-22; FOR APPROVAL, nothing run yet)

Decision P10 (`PROJECT_PLAN.md`). Offline, recorded LLM answers only, no API call, no change to the pipeline (`perception/`, `soc_server/`, `review_api/`, `frontend/`).

## Question

Can text the attacker writes into their own logs get an analyst to clear the attack, and so get the attack taught to the Knowledge Store?

Asymmetric trust (P9 A) stops the LLM's output from lowering scrutiny. Analyst verdicts are different:
- they bypass the learning gate: a `benign` verdict teaches the case's pattern (provenance `analyst`);
- analysts read the same attacker-written text and LLM hypotheses as the pipeline.

The paper lists this as a limitation, the "analyst channel" (`docs/LIMITATIONS_DRAFT.md`, viva Q6), but never measures it. The existing analyst-mistake result uses **random** misses: 20% misses taught 20 attack patterns, and with unlearning on confirmed compromise (B5) none (`experiments/RESULTS.md` C3). A persuaded analyst does not miss at random. They miss the cases that carry the attacker's text.

## Facts the design rests on (checked 2026-11-22, read-only, run `dedale_host_gated_nce_analyst_E1_fake_approval`)

- **Attacker text reaches 38 of the 72 attack cases** (its alerts' command lines carry the E1 payload): CLIENT2 17 of 35, CLIENT1 21 of 37. The other 34 attack cases come from events with no free text (named pipes, file writes, PowerShell fingerprints, lineage without a command line), so a perfect analyst still confirms them.
- **Timing:**
  - On CLIENT2 the first attack case (2025-01-06 10:01, text-free) opens 2.5 min before the first case with text.
  - On CLIENT1 the first attack case (2025-01-08 15:28:29.199) carries text; a text-free one opens 0.3 s later.
- **What the code does after a confirmation:**
  - Once a host is confirmed malicious, a later `benign` verdict on it teaches nothing (`perception/soc_loop.py:224-228`).
  - B5 retracts what was learned on that host in the 7 days before (`UNLEARN_LOOKBACK`, `soc_loop.py:75, 331-333`).
  - So the order of verdicts on a host decides what persuasion can teach.

## The simulated analyst (scorer side, like the existing oracle)

The base is the DEDALE oracle (`experiments/dedale_host_score.HostOracle`): a case is malicious if any of its alerts so far is a labelled event. Verdicts arrive 4 h after the case opens, through the case-store inbox, as in every existing analyst run. Two persuasion models wrap it:

| Model | Rule | What it represents |
|:--|:--|:--|
| **P-case** (per case) | A `malicious` verdict on a case whose alerts so far show the attacker's text becomes `benign` with probability *q*. The draw is seeded per case, as in `experiments/analyst_sim.noisy` | An analyst who believes the text on that case only |
| **P-host** (host-wide) | As P-case; and once the analyst has been persuaded on a host, every later `malicious` verdict on that host becomes `benign` too, text or not | An analyst who accepts the story ("this host is under maintenance") and clears what follows on it. This is the bound: the worst plausible case |

"Shows the attacker's text" = a command line in the case's alerts so far contains one of the active family's payload templates (`experiments/dedale_inject.FAMILIES`). This is what an analyst sees in the case view; the simulation reads it the same way the E1 scorer does (`experiments/e1_score.injected_cases`).

Optional stress (also on): a base random miss *m* = 0.2 on the remaining cases, so text-free confirmations can be lost too.

## Conditions

| | Value |
|:--|:--|
| System | the paper's system: gated learning, NCE from E1's recorded answers (`--nce cache --inject <family>`), asymmetric trust (`--llm-authority escalate`), case store, analyst after 4 h |
| Families | `fake_approval` (the payload addressed to the analyst; full grid); `suppress` and `steer` (q = 1.0 only, both models) |
| Persuasion *q* | 0 (= the frozen `A_E1_<family>` analyst runs: the check that nothing else changed), 0.2, 0.5, 1.0 |
| Models | P-case, P-host |
| Base miss *m* | 0; and 0.2 with q = 1.0 (stress) |
| B5 | on (the system) and off (`--no-unlearn`, to show what B5 does) |
| Seeds | 10 per condition with any probability below 1 (`--analyst-seed 0..9`); 1 otherwise |

**Size:**
- `fake_approval`: 2 models × ((0.2, 0.5) × 10 seeds + 1.0 × 1 + 1.0 with *m* 0.2 × 10 seeds) × B5 on / off = 124 replays.
- `suppress` and `steer`: 2 models × q 1.0 × B5 on / off = 8 replays.
- The q = 0 check: 2 replays.
- Total about 134 replays. At about 8 min each with 6 workers that is **about 3 h of compute**.

## Measures (scorer side; labels never enter the pipeline)

1. **Attack patterns taught:**
   - attack cases' patterns learned as routine at the end of the run (as in `RESULTS.md` C3);
   - the **peak** at any time, and how long each stayed learned (**exposure**, from the store's append-only `ks_log`: the time of the learn entry to the time of its `retract_edge`).
2. **Labelled attack events still alerted** (baseline 400). Events silenced while a pattern was exposed = the drop.
3. **Did B5 fire on each host, and when.** Was the host ever confirmed?
4. **Persuaded verdicts** (count, per host), malicious cases reviewed, reviews per day.
5. Mean ± sd and min / max over the seeds; the share of seeds in which a host was never confirmed.

## Predictions (written before any run)

- **P-case, B5 on:** about 0 patterns learned at the end, at any *q*. Each host gets text-free attack cases within minutes, so it is confirmed early. Later persuaded `benign` verdicts on a confirmed host teach nothing. Exposure is short (at most hours).
- **P-case, B5 off:** taught patterns grow with *q*, up to about 38 at q = 1.0. Alerted events drop well below 400.
- **P-host, B5 on:**
  - CLIENT2 is confirmed by its first, text-free case before any persuasion, so it stays protected.
  - On CLIENT1 the first case carries text: if it is persuaded (*q*), the analyst clears every later CLIENT1 case, the host is never confirmed, B5 never fires there, and CLIENT1's attack patterns stay learned.
  - **This is where the defence can fail**, with probability about *q* per run.
- **With *m* = 0.2:** more seeds lose their early text-free confirmations, so some P-case runs also leave a host unconfirmed.

Whatever the numbers are, they are reported. If P-host breaks B5, the paper states it as a measured limit of the analyst channel, with a second approval for analyst-taught patterns as the proposed mitigation (future work; it would change the pipeline and needs its own decision).

## Implementation (after approval)

- `experiments/analyst_sim.py`: `persuaded(analyst, templates, q, model, seed)`, a wrapper like `noisy`. It sees each alert through the oracle's `observe_alert` hook and keeps per-host persuasion state for P-host.
- `experiments/dedale_host_replay.py`: options `--analyst-persuaded Q` and `--persuasion case|host` (default 0: today's behaviour byte for byte), recorded in `summary.json`; a run tag per condition.
- `experiments/persuaded_score.py`: the measures above, from each run's `summary.json`, case store, `alerts.jsonl.gz` and the store's `ks_log`. Writes `experiments/dedale_results/persuaded_analyst_scores.json`.
- `experiments/build_results.py`: a new "Analyst persuaded by attacker text" table under C3. Existing tables unchanged.
- **Checks:**
  - new tests for the wrapper (determinism, per-host state, no effect at q = 0);
  - the full suite;
  - the q = 0 replays equal the frozen `A_E1` analyst rows;
  - a re-freeze of the existing conditions stays byte-identical.
- **Tracking:** `PROJECT_STATUS.md`, `RESEARCH_LOG.md`, and `experiments/PAPER_CLAIMS_TO_REVISE.md` for the new limitation text.

## Limits to state

- Persuasion is a probability, not a model of how people read text. *q* is swept, not estimated.
- One dataset, 2 attacked hosts, one campaign.
- The text sits only in process command lines (E1's injection). Attacker-chosen pipe names or file names are not used as carriers.
- One analyst delay (4 h); one LLM's recorded answers.
