# P9 B: corroborated learning against the precursor attack (design, 2026-11-28; FOR APPROVAL, nothing run)

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

B5 retracts only on the host it confirms, and CLIENT1 is never confirmed. Cross-host unlearning
(`unlearn_scope="all"`) restores 58 of 72, but only for test-period plants.

## Rules (each an option of the updater / loop; the default keeps today's behaviour, so every frozen run stays byte-identical)

- **R1 fleet corroboration:** an analyst `benign` teaches a detector key only if the key's host-free part
  (for example parent -> child image) was seen on at least M other hosts. M = 1 by default. Otherwise the case
  closes as `benign_once`: the hold is lifted and nothing is learned. The attacker's tools are new on every host,
  so they cannot be taught.
- **R2 second verdict:** an analyst-taught key stays probationary until a second benign verdict on a different
  case at least 24 h later. Until then it still alerts, and the alert can be closed with one click.
- **R3 lifetime:** analyst-taught keys expire after T days (T = 7) unless the key is seen again on another host.
- **R4 training corroboration (option, off by default):** R1's test applied to training-week learning, for the
  training-plant case. This changes the frozen baseline, so it is reported as a separate condition.
- **R5 critical hosts (P8 change 6):** on the profile's critical hosts a `benign` verdict needs two analysts
  before it teaches.

The rules touch only the learning path (`knowledge_updater.py`, `soc_loop.py`). Triage is unchanged, so
`POLICY_VERSION` is not bumped. If R1 is promoted to the default, `POLICY_VERSION` is bumped and the decision
cache invalidated. `perception/normalizer.py` is not touched.

## Conditions (offline replays, NCE off, about 2 min each)

| Set | Plants | Rules | Replays |
|:--|:--|:--|--:|
| Cost on clean traffic | none, analyst 4 h, 6 seeds at 0% and 20% misses | baseline, R1, R2, R3, R1+R3 | 5 × 12 = 60 |
| Attack | `test`, `slow`, `foothold`, `train` | baseline, R1, R2, R3, R1+R3, R4 | 24 |

Seed runs reuse the A11 harness. Total about 84 replays, about 3 h with 6 workers.

## Measures

- reviews/day (cost);
- attack cases raised of 72 and attack events of 400;
- attack keys learned;
- benign cases that never become routine, as `benign_once` closures/day (the analyst's repeat work).

## Predictions (written before any run)

- R1 brings test-period plants back to about 72 / 400, at a cost of a few reviews/day: single-host benign
  software keeps alerting.
- R2 only delays the attacker, who plants twice. It is weaker than R1 against `slow`.
- R3 limits how long a plant lasts, but the attack inside the 7 days still succeeds.
- Only R4 helps against training-week plants, and it raises the frozen baseline's workload.

## Outputs and tests

- `experiments/p9b_runs.py`, `experiments/p9b_score.py` -> `experiments/dedale_results/p9b_scores.json`, and a
  RESULTS.md section.
- Unit tests per rule: the gate on M, the probation clock, expiry, the two-analyst requirement, and that the
  default is unchanged (a frozen replay compared byte for byte).
