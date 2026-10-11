# Analyst review loop — evaluation on DEDALE (2026-10-11)

**Question:** with real analysts in the loop, what do their speed and their mistakes do to the workload, to detection and to what the Knowledge Store learns?

- Design: `experiments/ANALYST_REVIEW_LOOP_DESIGN.md`.
- Earlier phases: `DEDALE_PHASE2_RESULTS.md` (host logs) and `DEDALE_PHASE1_RESULTS.md` (network alerts).
- Ground truth is exact (labelled host events) and is read only by the simulated analyst and the scorers.
- No API calls: NCE was off, so the analyst's effect is not mixed with the LLM's.

## Setup

- **The analyst** is the DEDALE oracle (the verdict follows the labels).
  - It works through the real review path: its verdicts and approvals go into the case store's inbox, and the loop applies them. With a case store this is byte-identical to the earlier direct path.
  - **Delay:** 1 h, 4 h (the earlier default), 24 h, 72 h.
  - **Mistakes** (`experiments/analyst_sim.py`): a reproducible share of malicious verdicts given as benign ("misses"), or of benign verdicts given as malicious ("false alarms"). The draw is per case and seeded.
- **Runs:**
  - host logs: gated learning, all 6 detectors;
  - network alerts (Suricata): gated learning.
  - `--analyst oracle --case-store --analyst-delay H --analyst-miss P --analyst-false-alarm Q`.
  - Scores: `dedale_results/review_eval_host.json`, `review_eval_network.json`.

## Results

### Analyst delay

| Delay | Host cases | Host reviews / day | Network reviews / day | Attacker server contained after (network) |
|:--|--:|--:|--:|--:|
| 1 h | 417 | 29.8 | 20.6 | 60 min |
| 4 h | 432 | 30.9 | 20.9 | 240 min |
| 24 h | 491 | 35.1 | 21.5 | 24 h |
| 72 h | 696 | **49.7** | 22.6 | 72 h |

- **Detection does not depend on the delay.** All 72 malicious host cases reached an analyst, the attack steps surfaced at the same times (+1.2 min, +28.5 min, +30 min, +21 h), and no attack pattern was learned as routine.
- **On host logs, a slow team costs reviews.** A benign pattern is learned only once its verdict arrives; until then it opens new cases. 72 h instead of 4 h means +61% reviews (49.7 vs 30.9 per day).
- **On the network, the delay is the containment time.** The attacker's server is blocked only when the verdict comes.

### Analyst mistakes (host logs, 4 h delay)

| Analyst | Malicious verdicts given as benign | Attack cases whose pattern was learned as routine | Labelled attack events alerted | Exfiltration-window cases surfaced |
|:--|--:|--:|--:|--:|
| always right | 0 | 0 | 400 | 4 |
| misses 5% | 4 | 8 | 397 | 4 |
| misses 20% | 11 | 20 | **256 (−36%)** | **1** |
| false alarms 5% | 0 (20 benign given as malicious) | 0 | 400 | 4 |

- **A missed attack teaches the attacker's pattern as routine.**
  - A `benign` verdict is learned at once, and the learning gate does not apply to analyst verdicts (by design).
  - With 20% misses, 11 wrong verdicts silenced over a third of the later attack events: the attacker's tools reran unseen.
  - This is the main poisoning risk of analyst feedback, and it is larger than anything the gated automatic learning showed.
- **False alarms cost little on host logs** (+0.5 reviews / day; flagged benign hosts escalate some activity). **On the network they cause collateral blocks:** at 5% false alarms (12 wrong malicious verdicts), the approved blocks would have hit benign traffic 8 times.

## What this means

1. **Reviewing fast matters twice over:** for containment (network) and for the review load (host). The queue order (`dedale_queue_eval.py`) helps the first.
2. **Analyst feedback needs its own guard.** The design already offers `benign_once` (close without learning) and shows a learning preview, but nothing corrects a wrong `benign` later. Possible guards (open decision, see below):
   - **(a) Retroactive unlearning:** when a host is confirmed malicious, revoke the patterns learned on that host in a window before (provenance analyst / closed_benign), so they alert again, and reopen their cases.
   - **(b) Benign on a risky host needs a second look:** if the host has other open or confirmed cases, `benign` (learn) needs a second analyst, or defaults to `benign_once`.
3. **False alarms matter where actions execute:** four-eyes on critical hosts (B4) covers part of it. Blocking benign destinations on a single wrong verdict is the remaining risk.

## Decision B5 (a): unlearn on confirmed compromise (implemented 2026-10-11)

- **Decision:** option (a), user-approved; option (b) was a second analyst for `benign` on busy hosts.
- **Change:** when an analyst confirms a host compromised (`malicious` verdict):
  - the patterns learned on that host after training (provenance closed_benign / analyst / ungated) in the 7 days before are **retracted**: they alert again;
  - while the host stays confirmed (its 7-day watch), a `benign` verdict on it is **not learned**.
- Retraction is a logged Knowledge Store operation (`retract_edge`), so every earlier state can still be rebuilt. `SocLoop(unlearn_on_confirm=True)` is the default.
- **Replays** (host, 4 h, oracle through the inbox; `dedale_results/b5_eval_{host,network}.json`):

| Analyst | Attack cases' patterns learned as routine (off -> on) | Labelled attack events alerted | Reviews / day |
|:--|--:|--:|--:|
| always right | 0 -> 0 | 400 -> 400 | 30.9 -> **34.1** |
| misses 5% | 8 -> **0** | 397 -> **400** | 30.6 -> 34.1 |
| misses 20% | 20 -> **0** | 256 -> **400** | 30.1 -> 34.1 |
| false alarms 5% | 0 -> 0 | 400 -> 400 | 31.4 -> **44.6** |

- **Missed attacks no longer teach the store.**
  - With B5, the miss runs end in the same state as the perfect analyst: all 72 malicious cases reviewed, 400 / 400 labelled events alerted.
  - Each attacked host got at least one correct malicious verdict early. That retracted earlier learning, and the wrong benign verdicts after it learned nothing.
  - B5 cannot help a host on which every malicious case is missed.
- **Costs:**
  - **Perfect analyst:** +10% reviews (benign activity on the two compromised hosts keeps alerting).
  - **False alarms:** they now cost much more (+42% reviews at 5%), because a false confirmation stops learning on a healthy host for 7 days and retracts its recent patterns.
  - **Network:** no change (20.9 reviews / day, attacker contained after 240 min).
- **Open:**
  - The 7-day window and watch are a first choice.
  - A way to withdraw a wrong `malicious` verdict (which would restore the host's learning) does not exist yet.

## Caveats

- The analyst is a simulation: mistakes are random per case. Real mistakes cluster on hard cases, which are exactly the stealthy ones.
- One dataset, only 2 attacked hosts, NCE off.
- The network results rest on 3 malicious verdicts.
