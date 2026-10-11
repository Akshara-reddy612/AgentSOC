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

## Caveats

- The analyst is a simulation: mistakes are random per case. Real mistakes cluster on hard cases, which are exactly the stealthy ones.
- One dataset, only 2 attacked hosts, NCE off.
- The network results rest on 3 malicious verdicts.
