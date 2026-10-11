# DEDALE Phase 1 results — learning Knowledge Store on real IDS alerts

*Revision 2 (2026-10-11). Applies the three decisions taken after the first run:*
- *a response policy: no automatic containment on telemetry alone;*
- *a simulated-analyst condition;*
- *exact network ground truth from DEDALE's labelled Zeek flows.*

*The first run's numbers are kept under "Before the policy change".*

**What was tested:** whether a Knowledge Store that learns from a benign period makes AgentSOC usable on a real alert stream, and what it costs in analyst time and LLM calls. Input: DEDALE's Suricata alerts, offline. NCE (the LLM) was switched off, so **no API calls**. Design: `experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md`. Data facts: `experiments/DEDALE_DATA_NOTES.md`.

## Setup

- **Stream:** all 1,465,627 Suricata alerts (4 weeks, 2 routers) in time order.
- **Training weeks:** 2024-12-23 .. 2025-01-05, the weeks DEDALE documents as benign. The loop only learns here (shadow mode).
- **Test weeks:** 2025-01-06 .. 2025-01-19. The attack runs 01-06 .. 01-13.
- **Per alert:** addresses -> hosts through the store, then the outcome monitor, then the case builder (same signature + source + destination = one case; closes after 1 h idle or 24 h).
- **Per new case:** the triage gate — escalation rules, then the learned pattern (`LOW_PRIORITY`), then the decision cache, then the defended pipeline.
- **Learning modes:**
  - **static** (C0): nothing learned;
  - **frozen** (C1): training weeks only;
  - **gated** (C2): keeps learning behind the gate;
  - **ungated** (C3): keeps learning, no gate.
- **Variants:**
  - **"no_actionable"** (open decision D7): unreasoned novel cases end `NO_ACTIONABLE` instead of `REVIEW`;
  - **gated + analyst** (D1): a simulated analyst gives each review case a verdict 4 h after it is raised. Benign -> the pattern is learned. Malicious -> the proposed containment is approved, the destination becomes known-bad, and the host is flagged. This analyst is an oracle reading ground truth, so it is a separate condition, not part of the system.
- **Response policy for DEDALE** (`auto_contain_unreasoned_c2=False` in the profile): a C2 check that rests on telemetry alone — a connection to an unknown destination, with no NCE reasoning and no threat intelligence — proposes containment but does not execute it. The synthetic corpus-v2 environment keeps its original policy (0 changes to all earlier results).
- **Volume:** 7,273 training + **7,732 test cases** in every run, ~30-60 s per replay.
- **Reproduce:**
  - `python -m experiments.dedale_replay --mode <mode> [--unreasoned no_actionable] [--analyst oracle] --overwrite`
  - `python -m experiments.dedale_zeek_labels` (once)
  - `python -m experiments.dedale_score`
  - Scores: `experiments/dedale_results/phase1_scores.json`.

## Headline (test weeks, 14 days)

| Run | LOW_PRIORITY | REVIEW | Reviews/day (week 1 -> week 2) | Attack-related cases hidden* | Attacker server contained |
|:--|--:|--:|:--|:--|:--|
| static (C0) | 0% | 7,732 | 552.3 (547 -> 557) | 0 / 7 | no (left to analyst) |
| frozen (C1) | 95.3% | 366 | 26.1 (20.7 -> 31.6) | 0 / 7 | no (left to analyst) |
| gated (C2) | 95.3% | 366 | 26.1 (20.7 -> 31.6) | 0 / 7 | no (left to analyst) |
| ungated (C3) | 96.3% | 289 | 20.6 (17.0 -> 24.3) | 4 / 7 | no |
| gated, D7 "no_actionable" | 95.6% | 111 (+ 231 NO_ACTIONABLE) | 7.9 (4.9 -> 11.0) | 6 / 7 | no |
| **gated + analyst** | **96.2%** | **293** | **20.9 (17.4 -> 24.4)** | **4 / 7**** | **after 4 h** (the analyst delay) |

\* "Hidden" = ended LOW_PRIORITY or NO_ACTIONABLE. Ground truth: 1 confirmed case + 6 heuristic "probable" cases; 4 of the 6 are probably benign (see Limitations).
\*\* In the analyst run these 4 are exactly the probably-benign heuristic cases. The analyst marked the 3 real attack cases malicious (3 of its 293 verdicts; 290 benign).

No run auto-approves any containment any more (0 automatic blocks).

## What this shows

1. **Learning the benign weeks cuts the analyst load ~21×: ~552 to ~26 reviews per day.** 95% of test-week cases match one of the 753 patterns learned in the training weeks and need no pipeline run or LLM call.
2. **Analyst feedback makes continued learning pay off safely.**
   - Gated learning with analyst verdicts brings the load to 20.9/day. That matches ungated learning (20.6/day), but without its failure mode: **ungated learning stored the attacker's dropper download as a routine pattern; the analyst run marked it malicious.**
   - Without feedback, gated = frozen: nothing can vouch for new patterns while NCE is off.
3. **No automatic containment without reasoning — the trade-off.** Before the policy change, 35 auto-blocks were 1 attacker server + 34 benign destinations (31 of them STUN servers). Those watches also caused about a third of all reviews. Now:
   - nothing is blocked automatically;
   - the dropper download goes to an analyst immediately (`REVIEW` at 10:01:14);
   - containment waits for the analyst (4 h in the simulation).

   With NCE on (Phase 3), a reasoned C2 hypothesis may still be contained automatically.
4. **Lateral movement reached an analyst** in every "review" run: the two SMB alerts from client 2 to the domain controller around 15:00 on 01-08.
5. **D7 "review" matters.** Under "no_actionable", both lateral-movement alerts and the three known false positives end NO_ACTIONABLE, i.e. silently dropped.
6. **LLM budget:** ~21-26 cases per day reach review, the ones NCE would reason about. With 2,500 Gemini calls per day available, live reasoning on this stream fits easily.

## Exact network ground truth (Zeek labels, router 1)

- **What the labels contain:** DEDALE's labelled Zeek flows for router 1 (company <-> internet / DMZ; 84 files, all four weeks) hold **84 attack-labelled flows**:
  - command and control: 58 (TLS on port 443 from clients 1 and 2 to 172.19.2.1 and 172.19.0.2);
  - initial access: 4;
  - exfiltration: 2;
  - attack-related: 20 (e.g. the phishing mail to the DMZ mail server).
- **What Suricata saw:** only 2 Suricata alerts hit a labelled attack flow — the two router copies of the dropper download, i.e. exactly the "confirmed" case. **83 of the 84 labelled attack flows raised no Suricata alert**, including the whole C2 channel and the exfiltration.
- **Is "first contact" a usable detector?** No, not on its own. In the test weeks router 1 shows **4,400-9,300 outbound (source, destination) pairs per weekday that were never seen in the training weeks** (100-150 on weekends). All 5 attack pairs are among them, but they are ~0.05% of the first contacts. Using flow telemetry would need more signal, e.g. connections by bare IP without a DNS lookup, as with these C2 servers. Future work.

## Before the policy change (first run, same day)

Auto-approving containment for telemetry-only C2 checks:

| Run | Reviews/day | Auto-blocks |
|:--|--:|:--|
| static | 549.6 | 38 |
| frozen / gated | 29.4 | 35 (1 attacker, 34 benign) |
| ungated | 24.0 | 34 |
| "no_actionable" | 11.1 | 35 |

- The dropper server was blocked within the same minute as the download.
- Simulated collateral of the benign blocks: 1,065 alerts (6,291 in static).
- 141 of 411 gated reviews were escalations on those blocked benign destinations.

## Limitations (read before quoting numbers)

- **Ground truth for internal traffic is heuristic.** The router 1 labels are exact but cover only company <-> internet / DMZ traffic. The "probable" tier covers internal traffic (compromised host + new pattern + labelled host event within 5 min). Its two SMB alerts at lateral-movement time are plausible; its four "TikTok domain" DNS cases from client 1 are probably benign.
- **One attack scenario, one sensor, and the sensor is nearly blind** to this attack (1 of 84 labelled attack flows alerted). The detection findings are case studies, not rates.
- **Profile assumptions change outcomes:** egress, internal reachability, client numbering, criticality tiers.
- **The simulated analyst is perfect up to the ground truth's own errors**, always answers after exactly 4 h, and never makes mistakes.
- **NCE was off.** Responses are dry runs. "Would have been blocked" is simulated.
- **The decision cache works in every mode,** so C0 vs C1 isolates learned knowledge.

## Next

- **Phase 2:** host logs (winlogbeat, downloaded and verified). Includes design decision D6: extend NCE's technique vocabulary and SSE's constraints to the techniques host logs show, plus a defined review path for techniques without a structural precondition.
- **Phase 3:** live NCE on the ~20-26 review cases per day (needs API budget approval).
