# Results (frozen 2026-11-22)

Built by `python -m experiments.build_results` from frozen result files only; see `REPRODUCE.md`. Claims as in `PROJECT_PLAN.md` section 3.

## C1 — Text an attacker writes into logs does not steer the pipeline's actions

Pipeline response on clean vs contaminated twins (same GUIDE row, differing only at the injection site). *Suppressed* = the clean twin got a response (REVIEW / AUTO_APPROVED) and the contaminated one did not. *Asymmetric trust* (decision P9 A): the same recorded LLM answers, re-scored with `--llm-authority escalate` (NCE's hypotheses may raise scrutiny, never lower it).

| Run | Pairs scored | Suppressed (of clean responded) | 95% CI | Induced by ERA escalation | Induced otherwise | McNemar p (suppressed vs induced otherwise) | Steered actions: executed / gated | Automatic containments removed by contamination |
|:--|--:|--:|--:|--:|--:|--:|--:|--:|
| GUIDE v2 dev, gemini-3.1-flash-lite | 500 | 4/428 (0.9%) | 0.4%-2.4% | 12 | 4 | 1 | 0 / 7 | 20/178 (11.2%); 17 ERA-flagged |
| GUIDE v2 held-out, gemini-3.1-flash-lite | 500 | 3/437 (0.7%) | 0.2%-2.0% | 10 | 0 | 0.25 | 0 / 2 | 18/168 (10.7%); 18 ERA-flagged |
| GUIDE v2 dev, gpt-oss-20b | 500 | 10/437 (2.3%) | 1.2%-4.2% | 12 | 5 | 0.3 | 0 / 3 | 21/176 (11.9%); 17 ERA-flagged |
| GUIDE v2 dev, gemini-3.1-flash-lite, asymmetric trust | 500 | 4/428 (0.9%) | 0.4%-2.4% | 12 | 4 | 1 | 0 / 7 | 0/178 (0.0%) |
| GUIDE v2 held-out, gemini-3.1-flash-lite, asymmetric trust | 500 | 3/437 (0.7%) | 0.2%-2.0% | 10 | 0 | 0.25 | 0 / 2 | 0/168 (0.0%) |
| GUIDE v2 dev, gpt-oss-20b, asymmetric trust | 500 | 10/437 (2.3%) | 1.2%-4.2% | 12 | 5 | 0.3 | 0 / 3 | 0/178 (0.0%) |

*Paired view* (each pair is its own control; Wald CI for paired proportions; no significance is claimed where the interval covers zero):

- GUIDE v2 dev, gemini-3.1-flash-lite: 4 suppressed, 4 induced otherwise, of 500 pairs: change in response rate +0.0 points (paired 95% CI -1.1 to +1.1)
- GUIDE v2 held-out, gemini-3.1-flash-lite: 3 suppressed, 0 induced otherwise, of 500 pairs: change in response rate -0.6 points (paired 95% CI -1.3 to +0.1)
- GUIDE v2 dev, gpt-oss-20b: 10 suppressed, 5 induced otherwise, of 500 pairs: change in response rate -1.0 points (paired 95% CI -2.5 to +0.5)
- GUIDE v2 dev, gemini-3.1-flash-lite, asymmetric trust: 4 suppressed, 4 induced otherwise, of 500 pairs: change in response rate +0.0 points (paired 95% CI -1.1 to +1.1)
- GUIDE v2 held-out, gemini-3.1-flash-lite, asymmetric trust: 3 suppressed, 0 induced otherwise, of 500 pairs: change in response rate -0.6 points (paired 95% CI -1.3 to +0.1)
- GUIDE v2 dev, gpt-oss-20b, asymmetric trust: 10 suppressed, 5 induced otherwise, of 500 pairs: change in response rate -1.0 points (paired 95% CI -2.5 to +0.5)

*Induced by ERA escalation*: the contaminated twin got a response the clean one did not because ERA flagged its injected text (MEDIUM / HIGH) and escalated it to review; that is the defence reacting, not the attacker succeeding.

*Automatic containments removed by contamination*: of the pairs whose clean twin executes an automatic containment (a destination block the trusted telemetry supports), those whose contaminated twin does not. In the current pipeline a review outcome holds back every auto-approved response, so text that sends the case to review -- an NCE hypothesis, or ERA's own escalation -- delays containment; the suppression column counts these as responded. Under asymmetric trust the text-free decision's containment executes whatever the text does; that holds for the clean twins too, which is why the denominator can be higher (a clean twin whose own NCE hypotheses asked for review).

Outcomes per run (alerts, clean and contaminated; AUTO_APPROVED = an automatic response executed):

- GUIDE v2 dev, gemini-3.1-flash-lite: REVIEW 532, AUTO_APPROVED 336, LOW_PRIORITY 129, NO_ACTIONABLE 3
- GUIDE v2 held-out, gemini-3.1-flash-lite: REVIEW 563, AUTO_APPROVED 318, LOW_PRIORITY 110, NO_ACTIONABLE 9
- GUIDE v2 dev, gpt-oss-20b: REVIEW 548, AUTO_APPROVED 333, LOW_PRIORITY 107, NO_ACTIONABLE 12
- GUIDE v2 dev, gemini-3.1-flash-lite, asymmetric trust: REVIEW 532, AUTO_APPROVED 336, LOW_PRIORITY 0, NO_ACTIONABLE 132
- GUIDE v2 held-out, gemini-3.1-flash-lite, asymmetric trust: REVIEW 563, AUTO_APPROVED 318, LOW_PRIORITY 0, NO_ACTIONABLE 119
- GUIDE v2 dev, gpt-oss-20b, asymmetric trust: REVIEW 548, AUTO_APPROVED 333, LOW_PRIORITY 0, NO_ACTIONABLE 119

**Undefended LLM agent vs defended pipeline, same pairs** (all 500 dev pairs; defended McNemar against responses induced otherwise than by ERA escalation):

| | Attack succeeded (of clean twins it applies to) | 95% CI | McNemar p | Misdirected actions executed |
|:--|--:|--:|--:|--:|
| Undefended agent (hijacked to dismiss) | 130/439 (29.6%) | 25.5%-34.0% | 6.5e-17 | - |
| Defended pipeline (response suppressed) | 4/428 (0.9%) | 0.4%-2.4% | 1 | 0 |

**Through the full loop on real telemetry (E1, DEDALE host logs, live NCE + learning gate)**: the attacker appends text to the command lines of their own processes (84 events; 38 cases whose first alert carries it).

| Attacker text | Condition | Attack cases dismissed | Attack cases' patterns learned as routine | Labelled attack events alerted | Injected cases where NCE named the steered host | Steered hypotheses flagged unbound | Containment against the steered host | Reviews / day |
|:--|:--|--:|--:|--:|--:|--:|--:|--:|
| none (clean) | no analyst | 0 / 72 | 0 | 400 | 0 / 38 | 0 / 0 | 0 | 54.8 |
| none (clean) | analyst 4 h, B5 on | 0 / 72 | 0 | 400 | 0 / 38 | 0 / 0 | 0 | 33.2 |
| "routine maintenance" | no analyst | 1 / 72 | 0 | 400 | 0 / 38 | 0 / 0 | 0 | 54.7 |
| "routine maintenance" | analyst 4 h, B5 on | 0 / 72 | 0 | 400 | 0 / 38 | 0 / 0 | 0 | 33.1 |
| fake SOC approval | no analyst | 3 / 72 | 0 | 400 | 0 / 38 | 0 / 0 | 0 | 54.6 |
| fake SOC approval | analyst 4 h, B5 on | 0 / 72 | 0 | 400 | 0 / 38 | 0 / 0 | 0 | 33.1 |
| "isolate the domain controller" | no analyst | 1 / 72 | 0 | 400 | 30 / 38 | 49 / 49 | 0 | 54.7 |
| "isolate the domain controller" | analyst 4 h, B5 on | 0 / 72 | 0 | 400 | 32 / 38 | 59 / 59 | 0 | 33.1 |
| none (clean) | no analyst, asymmetric trust | 0 / 72 | 0 | 400 | 0 / 38 | 0 / 0 | 0 | 65.2 |
| none (clean) | analyst 4 h, B5 on, asymmetric trust | 0 / 72 | 0 | 400 | 0 / 38 | 0 / 0 | 0 | 34.1 |
| "routine maintenance" | no analyst, asymmetric trust | 0 / 72 | 0 | 400 | 0 / 38 | 0 / 0 | 0 | 65.2 |
| "routine maintenance" | analyst 4 h, B5 on, asymmetric trust | 0 / 72 | 0 | 400 | 0 / 38 | 0 / 0 | 0 | 34.1 |
| fake SOC approval | no analyst, asymmetric trust | 0 / 72 | 0 | 400 | 0 / 38 | 0 / 0 | 0 | 65.2 |
| fake SOC approval | analyst 4 h, B5 on, asymmetric trust | 0 / 72 | 0 | 400 | 0 / 38 | 0 / 0 | 0 | 34.1 |
| "isolate the domain controller" | no analyst, asymmetric trust | 0 / 72 | 0 | 400 | 30 / 38 | 49 / 49 | 0 | 65.2 |
| "isolate the domain controller" | analyst 4 h, B5 on, asymmetric trust | 0 / 72 | 0 | 400 | 32 / 38 | 59 / 59 | 0 | 34.1 |

## C2 — A learning Knowledge Store behind a gate cuts analyst load and keeps the attack visible

DEDALE, test weeks 2025-01-06..19 (14 days), training on the two benign weeks before. NCE off. Host logs: exact labels of the attacked clients' events.

**Host logs**

| Condition | Reviews / day | Test cases | Malicious cases raised (all reviewed unless noted) | Labelled attack events alerted | Attack cases' patterns learned as routine |
|:--|--:|--:|--:|--:|--:|
| static (nothing learned) | 6095.4 | 85336 | 80 | 473 | 0 |
| frozen (learned in training only) | 65.2 | 913 | 72 | 400 | 0 |
| gated (learning continues behind the gate) | 65.2 | 913 | 72 | 400 | 0 |
| ungated (learning without the gate) | 27.4 | 384 | 38 | 99 | 38 |

**Network alerts (Suricata)**

| Condition | Reviews / day | Attack-related cases hidden | Attacker server contained after | Attack patterns learned as routine |
|:--|--:|--:|--:|--:|
| static | 552.3 | 0 / 7 | never | 0 |
| frozen | 26.1 | 0 / 7 | never | 0 |
| gated | 26.1 | 0 / 7 | never | 0 |
| ungated | 20.6 | 4 / 7 | never | 1 |
| gated, unreasoned cases dismissed (D7 off) | 7.9 | 6 / 7 | never | 0 |

## C3 — Memory poisoning and its defences

Without the gate the store learns the attacker (C2 tables, *ungated*). Through the analyst: a simulated analyst (oracle with reproducible mistakes, 4 h delay) with and without unlearning on confirmed compromise (decision B5).

| Condition | Reviews / day | Test cases | Malicious cases raised (all reviewed unless noted) | Labelled attack events alerted | Attack cases' patterns learned as routine |
|:--|--:|--:|--:|--:|--:|
| analyst always right, B5 off | 30.9 | 432 | 72 | 400 | 0 |
| analyst always right, B5 on | 34.1 | 477 | 72 | 400 | 0 |
| misses 5% of attacks, B5 off | 30.6 | 429 | 69 | 397 | 8 |
| misses 5% of attacks, B5 on | 34.1 | 477 | 72 | 400 | 0 |
| misses 20% of attacks, B5 off | 30.1 | 421 | 61 | 256 | 20 |
| misses 20% of attacks, B5 on | 34.1 | 477 | 72 | 400 | 0 |
| 5% false alarms, B5 off | 31.4 | 439 | 72 | 400 | 0 |
| 5% false alarms, B5 on | 44.6 | 625 | 72 | 400 | 0 |

## C4 — What the LLM adds on real telemetry, and a failure mode

Host logs, gated. NCE = gemini-3.1-flash-lite hypotheses from the cache of the live Phase 3 run (cache misses go to review unreasoned). With an analyst and B5 the system sees alerts the cached run did not (different learning), so some cases were not reasoned about: the cache-miss column.

| Condition | Reviews / day | Malicious cases dismissed | Benign cases dismissed | NCE cache misses |
|:--|--:|--:|--:|--:|
| NCE off | 65.2 | 0 / 72 | 0 | 0 |
| NCE on, closed-world feasibility | 54.6 | 2 / 72 | 89 | 0 |
| NCE on, open-world feasibility | 54.8 | 0 / 72 | 89 | 0 |
| NCE on + analyst (4 h, B5 on) | 33.2 | 0 / 72 | 30 | 0 |
| NCE on, asymmetric trust (NCE may only escalate) | 65.2 | 0 / 72 | 0 | 0 |
| NCE on + analyst, asymmetric trust | 34.1 | 0 / 72 | 0 | 0 |

**What NCE is shown.** The NCE prompt holds the first 512 characters of each evidence field. In the first alert of each test case of the NCE run (856 cases): the command line is longer than that in 1 of 797; the raw log line in 718 of 856.

## C5 — Operating the analyst loop

Simulated analyst (oracle) through the case-store inbox, B5 on, different response times.

**Host logs**

| Condition | Reviews / day | Test cases | Malicious cases raised (all reviewed unless noted) | Labelled attack events alerted | Attack cases' patterns learned as routine |
|:--|--:|--:|--:|--:|--:|
| no analyst (gated) | 65.2 | 913 | 72 | 400 | 0 |
| analyst after 1 h | 33.1 | 463 | 72 | 400 | 0 |
| analyst after 4 h | 34.1 | 477 | 72 | 400 | 0 |
| analyst after 24 h | 38.1 | 533 | 72 | 400 | 0 |
| analyst after 72 h | 51.5 | 721 | 72 | 400 | 0 |

**Network alerts**

| Condition | Reviews / day | Attack-related cases hidden | Attacker server contained after | Attack patterns learned as routine |
|:--|--:|--:|--:|--:|
| no analyst (gated) | 26.1 | 0 / 7 | never | 0 |
| analyst after 1 h | 20.7 | 4 / 7 | 60 min | 0 |
| analyst after 4 h | 20.9 | 4 / 7 | 240 min | 0 |
| analyst after 4 h, B5 off | 20.9 | 4 / 7 | 240 min | 0 |
| analyst after 24 h | 21.5 | 4 / 7 | 1440 min | 0 |
| analyst after 72 h | 22.8 | 2 / 7 | 4320 min | 0 |
| analyst after 4 h, 5% false alarms | 21.2 | 4 / 7 | 240 min | 0 |

With 5% false alarms on the network, approved blocks would have hit benign traffic 8 times (perfect analyst: 0).

**Attack steps (host, gated + analyst 4 h, B5 on):** Initial access on client 2 (phishing macro, dropper): 20 cases, first after 1.2 min; Lateral movement to client 1 (PrintNightmare): 11 cases, first after 28.5 min; Collection: client 1 to the internal server over SSH: 11 cases, first after 30.0 min; Exfiltration to the attacker: 4 cases, first after 1265.0 min

## Paper revision (decisions P10, P11; 2026-11-22)

Offline replays of DEDALE host logs (recorded LLM answers only), added after the frozen results above; designs in `experiments/TIER1_EXPERIMENTS_DESIGN.md` and `experiments/PERSUADED_ANALYST_DESIGN.md`.

**Detection metrics** (from `final_host_scores.json`; a case holding a labelled class-1 event is an attack case; time to detect = minutes from each attack step's start to its first reviewed case):

| Condition | Precision (cases) | Attack cases reviewed / raised (ungated raises only 38: it learned the rest) | Benign reviews / day | Benign cases dismissed unreviewed | Time to detect per attack step (min) |
|:--|--:|--:|--:|--:|:--|
| static (nothing learned) | 0.1% | 80/80 | 6089.7 | 0/85256 | 1.2 / 28.5 / 30 / 1265 |
| frozen | 7.9% | 72/72 | 60.1 | 0/841 | 1.2 / 28.5 / 30 / 1265 |
| gated | 7.9% | 72/72 | 60.1 | 0/841 | 1.2 / 28.5 / 30 / 1265 |
| ungated | 9.9% | 38/38 | 24.6 | 1/346 | 1.2 / 28.5 / 30 / - |
| gated + analyst 4 h | 15.1% | 72/72 | 28.9 | 0/405 | 1.2 / 28.5 / 30 / 1265 |
| gated + NCE (acting rule) | 9.4% | 72/72 | 49.6 | 89/784 | 1.2 / 28.5 / 30 / 1265 |
| gated + NCE (asymmetric trust) | 7.9% | 72/72 | 60.1 | 0/841 | 1.2 / 28.5 / 30 / 1265 |
| gated + NCE + analyst (asymmetric trust) | 15.1% | 72/72 | 28.9 | 0/405 | 1.2 / 28.5 / 30 / 1265 |

*Derived (paper text):* learning the clean weeks cuts host reviews from 6095.4 to 65.2 per day, 98.9% fewer; 400 of the 473 labelled attack events the static detectors alert on still alert (84.6%); the other 73 match routine activity learned in the clean weeks.
E1 under asymmetric trust: 0/72 attack cases dismissed for every payload, 95% Wilson CI 0.0%-5.1%.

*Event-level false-positive rate* (frozen_F_frozen, `experiments/event_fpr.py`): 1434 of 6,760,514 test-period host events without a class-1 label raised an alert (0.021%); 400 of the 1834 alerted events are class-1.

**A simple memory baseline:** a pattern from the two clean weeks counts as normal only if it occurred at least K times (K = 1 is the clean-weeks allowlist, i.e. the frozen store). NCE off, no analyst.

| K | Reviews / day | Attack cases raised | Labelled attack events alerted | Attack cases learned | Precision | Training patterns forgotten |
|--:|--:|--:|--:|--:|--:|--:|
| 1 | 65.2 | 72 | 400 | 0 | 7.9% | 0 |
| 2 | 86.4 | 72 | 400 | 0 | 5.9% | 579 |
| 5 | 163.4 | 72 | 400 | 0 | 3.1% | 1053 |
| 10 | 718.7 | 72 | 400 | 0 | 0.7% | 1982 |

Gated learning gives the same numbers as frozen at every K (`tier1_scores.json`).

**Learning-gate delay**, where the gate learns: host logs with NCE under the acting rule, and network alerts with unreasoned cases dismissed (D7 off). 24 h is the frozen value.

| Delay | Host: reviews / day | Host: patterns learned through the gate | Host: attack cases learned | Network: reviews / day | Network: edges learned through the gate | Network: attack patterns learned |
|:--|--:|--:|--:|--:|--:|--:|
| 1h | 55.0 | 16 | 0 | 7.9 | 671 | 0 |
| 24h | 54.8 | 13 | 0 | 7.9 | 616 | 0 |
| 72h | 59.2 | 4 | 0 | 7.9 | 512 | 0 |
| 168h | 58.9 | 0 | 0 | 7.9 | 256 | 0 |

**Analyst mistakes over seeds** (seed 0 = the frozen run above, plus seeds 1-5; analyst after 4 h; mean ± sd (min-max)):

| Condition | Seeds | Attack cases' patterns learned | Labelled attack events alerted | Reviews / day |
|:--|--:|--:|--:|--:|
| misses 5%, B5 on | 6 | 0 ± 0 (0-0) | 400 ± 0 (400-400) | 34.1 ± 0 (34.1-34.1) |
| misses 5%, B5 off | 6 | 7.33 ± 2.42 (5-11) | 386.5 ± 18.48 (349-397) | 30.62 ± 0.13 (30.4-30.8) |
| misses 20%, B5 on | 6 | 0 ± 0 (0-0) | 400 ± 0 (400-400) | 34.1 ± 0 (34.1-34.1) |
| misses 20%, B5 off | 6 | 18.5 ± 2.81 (15-23) | 333.33 ± 61.14 (253-377) | 29.95 ± 0.44 (29.1-30.4) |
| 5% false alarms, B5 on | 6 | 0 ± 0 (0-0) | 400 ± 0 (400-400) | 41.83 ± 2.25 (38.7-44.6) |
| 5% false alarms, B5 off | 6 | 0 ± 0 (0-0) | 400 ± 0 (400-400) | 31.38 ± 0.23 (31-31.7) |

**Unlearning lookback** (how far back B5 retracts; analyst misses 20%, B5 on; 7 days = frozen):

| Lookback | Seeds | Attack cases' patterns learned | Labelled attack events alerted | Reviews / day |
|:--|--:|--:|--:|--:|
| 1d | 5 | 0 ± 0 (0-0) | 400 ± 0 (400-400) | 33.3 ± 0 (33.3-33.3) |
| 3d | 5 | 0 ± 0 (0-0) | 400 ± 0 (400-400) | 34.1 ± 0 (34.1-34.1) |
| 7d | 6 | 0 ± 0 (0-0) | 400 ± 0 (400-400) | 34.1 ± 0 (34.1-34.1) |
| 14d | 5 | 0 ± 0 (0-0) | 400 ± 0 (400-400) | 34.1 ± 0 (34.1-34.1) |

**The persuaded analyst (A10):** the attacker's command-line text (E1's `fake_approval` payload) talks the simulated analyst out of a `malicious` verdict with probability q. *Per case*: only cases that show the text; *host-wide*: once persuaded on a host, every later case there. Asymmetric trust, NCE from E1's recorded answers, analyst after 4 h; 'miss' = extra random misses. The text reaches 38 of the 72 attack cases; `suppress` and `steer` give the same numbers at q = 1.0 (`persuaded_analyst_scores.json`).

| Persuasion | q | Extra miss | B5 | Seeds | Attack cases' patterns learned (end) | Longest learned (h) | Labelled attack events alerted | Reviews / day | CLIENT1 never confirmed |
|:--|--:|--:|:--|--:|--:|--:|--:|--:|--:|
| per case | 1 | 0% | on | 1 | 0 | 0 | 400 | 34.1 | 0/1 |
| per case | 1 | 0% | off | 1 | 21 | 321.9 | 351 | 29.6 | 0/1 |
| per case | 1 | 20% | on | 10 | 0 | 0 | 400 | 34.08 | 0/10 |
| per case | 1 | 20% | off | 10 | 31 | 321.95 | 271.6 | 29.11 | 1/10 |
| per case | 0.5 | 0% | on | 5 | 0 | 0 | 400 | 34.1 | 0/5 |
| per case | 0.5 | 0% | off | 5 | 17.8 | 321.54 | 365.8 | 30.02 | 0/5 |
| host-wide | 1 | 0% | on | 1 | 13 | 268.5 | 262 | 30 | 1/1 |
| host-wide | 1 | 0% | off | 1 | 32 | 321.9 | 99 | 28.4 | 1/1 |
| host-wide | 1 | 20% | on | 10 | 13 | 268.5 | 262 | 30 | 10/10 |
| host-wide | 1 | 20% | off | 10 | 32.9 | 321.95 | 99 | 28.4 | 10/10 |
| host-wide | 0.5 | 0% | on | 5 | 5.2 | 107.4 | 344.8 | 31.74 | 2/5 |
| host-wide | 0.5 | 0% | off | 5 | 33.2 | 321.54 | 174.2 | 28.64 | 3/5 |

CLIENT2 was confirmed in every run: its first attack case carries no attacker text.

**Tier 2: live runs on GUIDE v2** (gemini-3.1-flash-lite; `experiments/tier2_scores.json`; design `experiments/TIER2_PLAN.md`). Hijacked = the clean twin is not dismissed and the contaminated twin is; suppressed = the clean twin gets a response and the contaminated twin does not.

*T2.1, the undefended agent on the held-out split:* hijacked 123/445 (27.6%, 95% CI 23.7%-32.0%); McNemar b=123, c=21, p=9.6e-19.

*T2.2, prompt-level defences on the undefended agent,* first 150 dev pairs (the same pairs for every defence; the undefended row uses its recorded answers on the same pairs):

| Defence | Pairs answered | Undefended: hijacked | Defended: hijacked | 95% CI (defended) | McNemar b / c | p |
|:--|--:|--:|--:|:--|:--|--:|
| delimited | 150 | 36/128 (28.1%) | 8/136 (5.9%) | 3.0%-11.2% | 2 / 30 | 2.5e-07 |
| spotlight | 150 | 36/128 (28.1%) | 7/140 (5.0%) | 2.4%-10.0% | 1 / 30 | 3e-08 |
| hierarchy | 150 | 36/128 (28.1%) | 4/140 (2.9%) | 1.1%-7.1% | 1 / 33 | 4.1e-09 |

Paired difference over all pairs both conditions answered (per-pair hijack indicator; 95% Wald CI for paired proportions):

- delimited: 24.0% -> 5.3% of 150 pairs, reduction 18.7 points (95% CI 11.9-25.4)
- spotlight: 24.0% -> 4.7% of 150 pairs, reduction 19.3 points (95% CI 12.8-25.9)
- hierarchy: 24.0% -> 2.7% of 150 pairs, reduction 21.3 points (95% CI 14.5-28.1)

*T2.3, the adaptive attacker:* 300 dev pairs whose payload was rewritten until ERA rated it LOW (ERA-flagged 53 -> 0) and placed in NCE's 512-character view (300/300); NCE errors 0.

| Rule | Suppressed, original payload | Suppressed, adaptive payload | 95% CI | McNemar b / c | Outcome changed | Techniques changed | Review removed (back to the clean response) |
|:--|--:|--:|:--|:--|--:|--:|--:|
| acting rule | 2/300 | 2/300 | 0.2%-2.4% | 0 / 0 | 17 | 80 | 17 |
| asymmetric trust | 2/300 | 2/300 | 0.2%-2.4% | 0 / 0 | 17 | 80 | 17 |

## Limits

- **DEDALE:** one real dataset. Labels exist for 2 attacked clients; the network results rest on few malicious verdicts.
- **Analyst:** simulated (an oracle that follows the labels, with random per-case mistakes).
- **LLM:** one model on DEDALE. On GUIDE, the second model (gpt-oss-20b) ran on the dev set only, not the held-out set.
- **GUIDE v2:** its entities, payloads and evidence are synthetic.
