# DEDALE Phase 1 results — learning Knowledge Store on real IDS alerts (2026-10-11)

**What was tested:** whether a Knowledge Store that learns from a benign period makes AgentSOC usable on a real alert stream, and what it costs in analyst time and LLM calls. It runs on DEDALE's Suricata alerts, offline: NCE (the LLM) was switched off, so **no API calls**. Design: `experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md`. Data facts: `experiments/DEDALE_DATA_NOTES.md`.

## Setup

- **Stream:** all 1,465,627 Suricata alerts (4 weeks, 2 routers), replayed in time order.
- **Training weeks:** 2024-12-23 .. 2025-01-05, the weeks DEDALE documents as benign. The loop only learns here (shadow mode: no triage, no actions).
- **Test weeks:** 2025-01-06 .. 2025-01-19. The attack runs 01-06 .. 01-13.
- **Per alert:** addresses -> hosts through the store's inventory, then the outcome monitor, then the case builder (same signature + source + destination = one case; closes after 1 h idle or 24 h).
- **Per new case:** the triage gate — escalation rules, then the learned pattern (`LOW_PRIORITY`), then the decision cache, then the defended pipeline.
- **Learning modes:**
  - **static** (C0): nothing learned;
  - **frozen** (C1): learned in the training weeks only;
  - **gated** (C2): keeps learning behind the gate;
  - **ungated** (C3): keeps learning, no gate.
- **Policy variant:** the "no_actionable" variant of open decision D7, where unreasoned novel cases end `NO_ACTIONABLE` instead of `REVIEW`.
- **Volume:** 7,273 training cases + **7,732 test cases** in every run. About 30 s per replay.
- **Reproduce:**
  - `python -m experiments.dedale_replay --mode <mode> [--unreasoned no_actionable] --overwrite`
  - `python -m experiments.dedale_score`
  - Scores: `experiments/dedale_results/phase1_scores.json`. Stores and per-case records: `agentsoc_data/ks/`, `agentsoc_data/runs/` (outside the repo).

## Headline (test weeks, 14 days)

| Run | LOW_PRIORITY | REVIEW | AUTO_APPROVED | Reviews / day (max) | Attack-related cases surfaced* |
|:--|--:|--:|--:|--:|:--|
| static (C0) | 0 | 7,694 | 38 | 549.6 (822) | all 7 |
| frozen (C1) | 7,286 (94.2%) | 411 | 35 | 29.4 (84) | all 7 |
| gated (C2) | 7,286 (94.2%) | 411 | 35 | 29.4 (84) | all 7 |
| ungated (C3) | 7,362 (95.2%) | 336 | 34 | 24.0 (81) | 3 of 7 |
| gated, D7 = "no_actionable" | 7,305 | 156 (+236 NO_ACTIONABLE) | 35 | 11.1 (35) | 1 of 7 |

\* Ground truth has two tiers (see Limitations): 1 confirmed case and 6 heuristic "probable" cases. 4 of the 6 are probably benign. The hidden ones in C3 and in the "no_actionable" run are discussed below.

## What this shows

1. **Learning the benign weeks cuts the analyst load about 19×: ~550 to ~29 reviews per day.**
   - The store learned 753 alert patterns and 822 communications in the training weeks.
   - 94% of test-week cases then match a learned pattern and are handled at low priority, with no pipeline run and no LLM call.
   - Weekday reviews drop from 687-822 to 15-84; weekends are 0-2.
2. **The attack's first step was contained at once.**
   - Client 2 downloaded the dropper from the attacker's server (172.19.1.1) at 10:01:14 on 01-06, about a minute after the phishing infection.
   - The case was new, so the pipeline checked it as possible C2 and auto-approved `BLOCK_DESTINATION` on the attacker's server, in every run.
   - The outcome monitor then watched that server; nothing contacted it again. The one "would have been blocked" count is the second router's copy of the same download.
3. **The lateral-movement step reached an analyst.** Two new alerts from client 2 to the domain controller over SMB went to REVIEW in the static, frozen and gated runs:
   - "Possible Call with No Offset TCP Shellcode" at 14:58 on 01-08;
   - "SMB Executable File Transfer" at 15:05, which matches the labelled `svcmon.exe` activity.
4. **Suricata is blind to most of the attack.** Collection on the internal server (SSH) and exfiltration to the C2 server produced no alerts. This is a property of the sensor, not the pipeline. Measuring detection properly needs the host logs (Phase 2).
5. **The learning gate matters.**
   - **Ungated learning stored the attacker's dropper download (client 2 -> 172.19.1.1) as a routine pattern.** A repeat would have been handled at low priority, except that the block's watch would still have escalated it within 7 days.
   - The gated runs learned nothing involving attacker infrastructure.
6. **The D7 default ("review") matters.** Under "no_actionable", both lateral-movement alerts ended NO_ACTIONABLE, i.e. silently dropped, because nothing reasoned about them. The three known false positives also vanished unseen. Under "review" all of them reach an analyst.
7. **Gated = frozen in this phase, as expected.**
   - Without NCE or an analyst, nothing can vouch for a new pattern; an unexamined REVIEW case is not benign, so the gate does not learn it.
   - The gate still learned 265 additional communications from routine cases. It dropped 4,703 routine updates because a case sharing an endpoint had been escalated.
   - Continued learning needs a reasoning source: NCE (Phase 3) or analyst feedback (the simulated-analyst condition, open decision D1).
8. **LLM budget:** with learning, ~29 cases per day reach review — the ones NCE would reason about. Current Gemini capacity is 2,500 calls per day, so live reasoning on this stream fits easily. Without learning it would be ~550 per day.

## False positives and side effects

- **Benign auto-blocks.** The frozen and gated runs auto-approved 34 blocks of benign external destinations. 31 of them are STUN binding requests (WebRTC) from four clients (CLIENT9, 12, 13, 30) to STUN servers first contacted in the test weeks.
  - Simulated collateral: 1,065 later alerts to those destinations would have been blocked.
  - The watches then escalated 141 new cases on those blocked destinations: about a third of all reviews come from the system's own false blocks.
  - Without learning (static) there are 38 blocks and 6,291 collateral alerts (2.21.225.158, Microsoft device metadata, alone 4,904).
- **Known false positives** (the three attack-window alerts the timeline rules out): REVIEW in every "review" run, never auto-acted on.
- **DNS resolver: not blocked** (this corrects an earlier prediction in the notes). The outbound DNS comes from the DNS forwarders (company router 2, DMZ mail server). Their criticality in the inventory sends the proposed block to review: 278 resolver cases in the static run. This rests on a criticality assumption.

**Review load by cause (frozen / gated, 411 reviews):**

| Cause | Reviews |
|:--|--:|
| Novel pattern, not reasoned about (NCE off) | 214 |
| Activity on an auto-blocked target (watch) | 141 |
| Repeat decisions from the decision cache | 41 |
| Guardrail review (critical host) | 15 |

## Limitations (read before quoting numbers)

- **Ground truth for these alerts is thin.**
  - Only 1 case is confirmed (it has an attacker address).
  - The 6 "probable" cases are a heuristic join, not labels: a new pattern on a compromised host, with a labelled malicious host event within 5 minutes. The two SMB alerts at lateral-movement time are plausible. The four "TikTok domain" DNS cases from client 1 are probably benign browsing that happened to fall near the malware's frequent labelled events.
  - Exact network labels (Zeek `conn.log`) are not downloaded, so no precision / recall is claimed.
- **One attack scenario, one sensor.** Suricata barely sees this attack, so the detection results are a handful of cases, not a rate.
- **Assumptions in the environment profile change outcomes:** egress "open", internal reachability, client numbering, criticality tiers. The DNS-resolver result above depends on criticality.
- **NCE was off.** Nothing reasoned about novel cases; the pipeline could only check C2 for outbound alerts. With NCE off, internal and inbound cases can only be reviewed or dropped.
- **Responses are dry runs.** "Would have been blocked" is simulated.
- **The decision cache works in every mode, including static.** C0 vs C1 isolates learned knowledge, not operational memory.

## Next steps (decisions for the team)

1. **Benign auto-blocks:** decide whether `BLOCK_DESTINATION` on a never-seen destination may be auto-approved, or should go to review the first time (e.g. for traffic types like STUN). This is a policy decision, not a bug.
2. **Analyst feedback:** a simulated-analyst condition (D1) that closes REVIEW cases using the labels, so gated learning can accept benign new patterns.
3. **Phase 2 (host logs):** winlogbeat is downloaded and verified (27.1 GB). Decision D6 first: NCE and SSE know only 7 techniques, so most of this attack (phishing, PowerShell, persistence, PrintNightmare, SSH, exfiltration) cannot be named yet.
4. **Exact network ground truth:** Zeek `conn.log` labels for router 1 (4.40 GB, needs download approval).
5. **Phase 3:** live NCE on the ~29 cases per day that reach review (needs API budget approval).
