# Results (frozen 2026-10-18)

Built by `python -m experiments.build_results` from frozen result files only; see `REPRODUCE.md`. Claims as in `PROJECT_PLAN.md` section 3.

## C1 — Text an attacker writes into logs does not steer the pipeline's actions

Pipeline response on clean vs contaminated twins (same GUIDE row, differing only at the injection site). *Suppressed* = the clean twin got a response (REVIEW / AUTO_APPROVED) and the contaminated one did not.

| Run | Pairs scored | Suppressed (of clean responded) | 95% CI | Induced by ERA escalation | Induced otherwise | McNemar p (suppressed vs induced otherwise) | Steered actions: executed / gated |
|:--|--:|--:|--:|--:|--:|--:|--:|
| GUIDE v2 dev, gemini-3.1-flash-lite | 500 | 4/428 (0.9%) | 0.4%-2.4% | 12 | 4 | 1 | 0 / 7 |
| GUIDE v2 held-out, gemini-3.1-flash-lite | 500 | 3/437 (0.7%) | 0.2%-2.0% | 10 | 0 | 0.25 | 0 / 2 |
| GUIDE v2 dev, gpt-oss-20b (partial run) | 125 | 3/108 (2.8%) | 0.9%-7.9% | 3 | 0 | 0.25 | 0 / 1 |

*Induced by ERA escalation*: the contaminated twin got a response the clean one did not because ERA flagged its injected text (MEDIUM / HIGH) and escalated it to review; that is the defence reacting, not the attacker succeeding.

**Undefended LLM agent vs defended pipeline, same pairs** (dev; 183 pairs so far — run interrupted by the free-tier daily quota):

| | Attack succeeded (of clean twins it applies to) | 95% CI | McNemar p | Misdirected actions executed |
|:--|--:|--:|--:|--:|
| Undefended agent (hijacked to dismiss) | 48/156 (30.8%) | 24.1%-38.4% | 1.7e-05 | - |
| Defended pipeline (response suppressed) | 2/155 (1.3%) | 0.4%-4.6% | 0.29 | 0 |

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
| NCE on, open-world feasibility (final) | 54.8 | 0 / 72 | 89 | 0 |
| NCE on + analyst (4 h, B5 on) | 33.2 | 0 / 72 | 30 | 42 |

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

## Limits

- **DEDALE:** one real dataset. Labels exist for 2 attacked clients; the network results rest on few malicious verdicts.
- **Analyst:** simulated (an oracle that follows the labels, with random per-case mistakes).
- **LLM:** one model on DEDALE. On GUIDE, gpt-oss-20b covered only part of the dev set.
- **GUIDE v2:** its entities, payloads and evidence are synthetic.
- **Comparisons:** the undefended-agent comparison is interim, as the table states.
