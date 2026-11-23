# A8: low-and-slow poisoning (design, 2026-11-22)

Reviewer checklist A8; paper limitation (4) "poisoning during training and low-and-slow poisoning across the gate's
delay were not tested". Offline replays of DEDALE host logs, NCE off, no API call. Experiment code only
(`experiments/dedale_plant.py`, `--plant` in `experiments/dedale_host_replay.py`); no pipeline module changes.

## Attacker

The attacker knows which tools its attack will run. Before each step it runs the same tools harmlessly, so that
every detector key the attack will raise has already been seen on harmless activity. The host detector keys carry
no command-line text, which is what makes this possible:

| Detector | Key | Plantable harmlessly? |
|:--|:--|:--|
| lineage | (host, parent image, child image) | yes: the same programs with harmless arguments |
| exec_file_write | (host, image, file extension) | yes: the same program writes a harmless file of that type |
| pipe | (host, image, pipe name with digits blanked) | yes |
| powershell | (host, fingerprint of the script text) | **no**: only the attack script has its fingerprint |

The attack's labelled class-1 events in the test weeks use 46 distinct keys (CLIENT2 32, CLIENT1 14); 42 are
plantable. A planted event is a copy of the attack event that first uses the key, with harmless text, an earlier
time and a record id no label carries. The simulated analyst therefore sees nothing malicious in it, which is true
of a harmless run: this is the worst case for the defender (a perfectly fooled analyst).

## When

- **test**: in the test period, as early as the data allows: one plant per host every 10 minutes from 2025-01-06
  00:10 (all done by 04:40). CLIENT2's attack starts at 10:01 the same day, CLIENT1's on 2025-01-08. Every plant is
  inside B5's 7-day lookback, because the whole campaign lasts 5 days.
- **train**: 8 days before each key's first use (past the lookback), which falls inside the training weeks: an
  attacker present while the store is trained. Training learning is trusted by design and B5 never retracts it.

## Conditions (7 replays) and baselines

| Run | Plants | Analyst | B5 | Baseline |
|:--|:--|:--|:--|:--|
| A8_test_gated | test | none | - | F_gated |
| A8_test_d4 | test | oracle, 4 h | on | F_d4 |
| A8_test_d4_nob5 | test | oracle, 4 h | off | F_d4_nob5 |
| A8_test_all_d4 | test, PowerShell too (upper bound) | oracle, 4 h | on | F_d4 |
| A8_train_frozen | train | none (frozen) | - | F_frozen |
| A8_train_d4 | train | oracle, 4 h | on | F_d4 |
| A8_train_all_d4 | train, PowerShell too (upper bound) | oracle, 4 h | on | F_d4 |

## Measures

Attack cases raised, labelled attack events alerted, attack patterns learned as routine, reviews per day, time to
detect each attack step, and the planting cost: how many planted events alerted and how their cases ended (a
reviewed plant is the attacker's tooling shown to an analyst).

## Expected, before running

- Without an analyst, nothing is learned in the test period (every new key goes to review; D7), so test-period
  planting changes nothing but adds reviews.
- With the analyst, planted keys are learned at the benign verdict. If any attack case on the host still surfaces and
  is confirmed, B5 retracts everything learned there in the last 7 days, including the plants.
- Training-week plants are learned as training and are never retracted: the attack is hidden except where it uses
  unplantable keys. This is a limit of every baseline-learning detector, and the result quantifies it.

Whatever the result, it is reported as a result or a limitation; the pipeline is not changed before submission
(user, 2026-11-22).

## Corrections (2026-11-23)

The PowerShell key hashes only the first 160 normalised characters, so it can be planted by a harmless script with the same prefix. The plants need a foothold before the recorded intrusion, outside the threat model. The gate's delay path is not exercised, so this is conditioning through the analyst, not low-and-slow poisoning. See RESEARCH_LOG.md.
