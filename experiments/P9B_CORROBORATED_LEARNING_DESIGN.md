# P9 B: corroborated learning against the precursor attack (design, 2026-11-28; revised the same day after checks)

Decision P9 B: the precursor attack on the learning gate, and corroborated learning. P8 changes 4 (stricter
learning), 6 (second approval for `benign` on critical hosts) and 7 (unlearning that follows a pattern's
decisions) fold into it.

## The weakness being addressed (A8, RESEARCH_LOG 2026-11-22)

An attacker runs its tools harmlessly first. The host keys carry no command-line text, so a harmless run has
the attack's key. The analyst truthfully closes those cases as benign, and `KnowledgeUpdater.analyst_closed_benign`
learns the keys:

| Condition | Attack cases (of 72) | Attack events (of 400) |
|:--|--:|--:|
| test-period plants, analyst 4 h, B5 on | 21 | 212 |
| test-period plants, analyst 4 h, B5 off | 2 | 34 |
| training-week plants | 2 | 34 |
| slow plants, D7 off (`a8_gate_scores.json`) | 0 raised of 46 | |

B5 retracts only on the host it confirms, and CLIENT1 is never confirmed.

## Pre-check (read-only, 2026-11-28; script in the agent's scratch folder, to be committed as `experiments/p9b_precheck.py`)

The *pattern* of a key is the key without its host: parent -> child image, image + pipe, image + file type,
image reading LSASS, account + logon type + source, script fingerprint.

| What | Count | Seen in training on at least one other host |
|:--|--:|--:|
| plantable attack keys (CLIENT1, CLIENT2) | 42 | **5** (all on CLIENT2 at 01-08 15:07, the Python tool chain, seen on 29 hosts) |
| keys an honest analyst teaches on clean traffic (`F_d4`) | 311 | **75** (SPAWNED 73/293, WRITES_FILE_TYPE 2/12, USES_PIPE 0/6) |
| training keys | 6,484 | 5,987 (497 single-host: SPAWNED 280, LOGON 149, USES_PIPE 60) |

- The counts are bimodal: 236 of the 311 have 0 other hosts, 4 have 1, none have 2, and 71 have ≥ 3. A sweep
  over M therefore adds nothing; M = 1 is used.
- Only 2 of the attack's 40 patterns occur on both attacked hosts, so an attacker on two hosts has little
  chance to corroborate its own plants.
- Counting benign verdicts on other hosts too (R1b, approximated from `F_d4`'s taught keys) keeps 160 of 311
  learnable at M = 2, against 71 under R1 at that M.

## Rules (options of the updater / loop; the default keeps today's behaviour, so every frozen run stays byte-identical)

Each rule applies to **all** learning after training: analyst verdicts, and gate learning from closed cases
(`closed_benign`, the D7-off path). Otherwise the gate path stays open.

- **R1, fleet corroboration from training.** A key is learned after training only if its pattern was seen in
  training on at least one other host. Otherwise the case closes as `benign_once`: its hold is lifted, nothing
  is learned, and the key alerts again.
- **R1b, fleet corroboration with independent verdicts.**
  - R1, or the pattern has benign verdicts on at least M = 2 other hosts that are not under suspicion (no open
    escalation, watch or confirmation);
  - the verdict tally is kept even when nothing is learned, so the first hosts are not deadlocked;
  - the M = 2 means an attacker on two hosts cannot corroborate its own plants. One on three or more can: a
    stated limit.
- **R4, training corroboration (separate condition).** A training key is learned only if its pattern occurs on
  at least two hosts in training. It answers the training-week plants. It changes the frozen baseline (497
  keys, 8%), so it is reported as its own condition and never as the default.
- **R6, pattern-following unlearning (P8 change 7).** When B5 confirms a host, the same patterns learned after
  training on other hosts are retracted too. This is narrower than `unlearn_scope="all"` (+11 reviews/day).
  Predicted weak here, since only 2 of 40 patterns are shared.

**Dropped after the checks:**
- **R2 (second verdict 24 h later) and R3 (7-day lifetime):** an attacker who repeats its plants defeats both by
  construction, and the recorded slow schedule already repeats over days.
- **R5 (two analysts on critical hosts):** vacuous on DEDALE host logs. Host events come only from the 30
  tier-0 Windows clients, so no critical host ever gets a host verdict. With truthful verdicts a second analyst
  would also agree. It remains future work for analyst mistakes (P9 C).

The rules touch only the learning path (`knowledge_updater.py`, `soc_loop.py`). Triage is unchanged, so
`POLICY_VERSION` is not bumped. If a rule is promoted to the default, it is bumped and the decision cache
invalidated. `perception/normalizer.py` is not touched.

## Conditions (offline replays, NCE off, about 2-3 min each, 7 workers)

| Set | Runs | Replays |
|:--|:--|--:|
| Cost, clean traffic | analyst 4 h at 0% misses (deterministic: 1 replay) and at 20% misses (6 seeds), each under R1, R1b and R4. Baselines reuse the recorded `F_d4` and `F_m20` seeds | 21 |
| Attack | `test`, `slow`, `foothold` and `train` plants with the analyst, each under R1, R1b, R4 and R6 | 16 |
| Gate path | `slow` plants with D7 off (as `a8_gate`) under R1 and R1b | 2 |

That is about 39 replays, under an hour.

## Measures

- reviews/day (cost), and `benign_once` closures/day (the analyst's repeat work);
- attack cases raised of 72, and attack events;
- attack keys learned, including under 20% analyst misses: R1 should also stop missed attack cases from
  becoming routine, a second benefit.

## Predictions (written before any run)

- **R1:** test-period plants back to about 72 attack cases. The 5 teachable keys are on CLIENT2, which B5
  confirms. Analyst-miss poisoning falls in step with it. The cost is a clear rise in reviews/day, since 236 of
  the 311 clean keys stay unlearned.
- **R1b:** most of R1's protection at well under half its extra cost.
- **R4:** the only rule that helps against `train` plants, at the cost of raising the frozen baseline's workload.
- **R6:** little change.

## Outputs and tests

- `experiments/p9b_precheck.py`, `experiments/p9b_runs.py`, `experiments/p9b_score.py` ->
  `experiments/dedale_results/p9b_scores.json`, and a RESULTS.md section.
- **Tests:**
  - R1 refuses a single-host pattern and allows a fleet one;
  - R1b's tally ignores suspected hosts and needs M distinct hosts;
  - R4's filter;
  - R6 retracts only the same pattern;
  - the gate path obeys the rule;
  - the default is unchanged (a frozen replay compared byte for byte).
