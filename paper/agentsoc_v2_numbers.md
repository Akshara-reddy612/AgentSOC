# Numbers in `paper/agentsoc_v2.tex` and where each comes from

Every number in the paper, by where it appears, with its source: a section of `experiments/RESULTS.md`
(C1-C5, Limits) or a page of the base paper (Roy and Singh, AgentSOC, ICAIC 2026, arXiv:2604.20134v1). RESULTS.md
has no C6 section: the paper's C6 (asymmetric trust) uses the rows marked "asymmetric trust" in C1 and C4.
A script check (2026-11-01, final text) found each of the paper's 280 numeric tokens either in RESULTS.md (271) or
in the "other sources" list below (9).

## Abstract

| Number | Says | Source |
|:--|:--|:--|
| 500 | GUIDE v2 pairs (development) | C1, first table, "Pairs scored" |
| 130/439 | undefended agent hijacked | C1, "Undefended LLM agent vs defended pipeline" |
| 4/428 | pipeline's response suppressed | C1, first table, GUIDE v2 dev, gemini-3.1-flash-lite |
| 14 | DEDALE test days | C2, header ("14 days") |
| 6095.4 -> 65.2 | host reviews per day, nothing learned -> benign weeks learned | C2, host table, static and frozen |
| 400 | labelled attack events still alerting | C2, host table, frozen |
| 0/72 | attack cases dismissed in E1 on DEDALE, every text, asymmetric trust | C1, E1 table, asymmetric-trust rows |

## Introduction and Section II

| Number | Says | Source |
|:--|:--|:--|
| 14 | test days | C2, header |
| 5,000 | events in the base paper's LANL sample | base paper p. 4, Sec. IV-A |
| 50 | nodes in the base paper's synthetic topology | base paper p. 4, Sec. IV-A |
| 506 ms, 480 ms | base paper's walk-through, end to end and in the LLM | base paper p. 5, Table VI |

## Table I (comparison)

| Number | Says | Source |
|:--|:--|:--|
| 1 to 72 hours | analyst response delays measured | C5, host table |
| 5,000; 50; 506 ms | base paper's data and timing | base paper p. 4, Sec. IV-A; p. 5, Table VI |
| 500 and 500 | GUIDE v2 development and held-out pairs | C1, first table |
| 14 | test days | C2, header |

## Sections III and IV (system, setup), Fig. 1

| Number | Says | Source |
|:--|:--|:--|
| 512 | characters of each free-text field shown to the LLM (text and Fig. 1) | C4, "What NCE is shown" |
| 500 and 500 | development and held-out pairs | C1, first table |
| 95% | Wilson interval level | C1, first table ("95% CI") |
| 2 | attacked Windows clients with labels | Limits ("Labels exist for 2 attacked clients") |
| 14 | test days | C2, header |
| 84; 38 | E1 events carrying the text; cases whose first alert carries it | C1, E1 paragraph |

## Section V-A, C1, and Table II

| Number | Says | Source |
|:--|:--|:--|
| 4/428 (0.9%, 0.4%-2.4%) | suppressed, dev, Gemini | C1, first table |
| 3/437 (0.7%, 0.2%-2.0%) | suppressed, held-out, Gemini | C1, first table |
| 10/437 (2.3%, 1.2%-4.2%) | suppressed, dev, gpt-oss-20b | C1, first table |
| p = 1, 0.25, 0.3 | McNemar, suppressed vs induced otherwise | C1, first table |
| 12, 10, 12 | flips induced by ERA escalation | C1, first table |
| 7, 2, 3 | steered actions gated (0 executed) | C1, first table, "executed / gated" |
| 130/439 (29.6%, 25.5%-34.0%, p = 6.5e-17) | undefended agent hijacked | C1, undefended vs defended table |
| 1, 3, 1 of 72 | E1 attack cases dismissed, acting rule, no analyst | C1, E1 table |
| 0 | E1 dismissed with an analyst; patterns learned | C1, E1 table |
| 400 | labelled attack events alerted in every E1 run | C1, E1 table |
| 30 of 38; 32 of 38 | NCE named the steered host (no analyst; analyst) | C1, E1 table |
| 49 of 49; 59 of 59 | steered hypotheses flagged unbound | C1, E1 table |
| 20/178, 18/168, 21/176 -> 0/178, 0/168, 0/178 | containments removed (Table II) | C1, first table, last column |
| 54.8 -> 65.2; 33.2 -> 34.1 | E1 clean reviews per day, acting rule -> asymmetric trust (Table II) | C1, E1 table |
| 4 h | the analyst's delay in E1 | C1, E1 table ("analyst 4 h") |

## Sections V-B to V-E (C2-C5), Table III, Fig. 2

| Number | Says | Source |
|:--|:--|:--|
| 6095.4; 85336; 80; 473 | nothing learned: reviews/day, test cases, malicious raised, events alerted | C2, host table, static |
| 65.2; 913; 72; 400 | benign weeks learned (frozen = gated) | C2, host table |
| 27.4; 38; 38; 99 | without the gate: reviews/day, patterns learned, malicious raised, events alerted | C2, host table, ungated |
| 552.3; 26.1; 20.6; 1 | network: static, learned, ungated reviews/day; patterns learned ungated | C2, network table |
| 5%: 8 learned, 397 alerted | analyst misses 5%, no unlearning | C3 |
| 20%: 20 learned, 61 raised, 256 alerted; 30.1/day | analyst misses 20%, no unlearning | C3 |
| 0 learned, 72 raised, 400 alerted; 34.1/day | with unlearning, both mistake rates | C3 |
| 34.1 vs 30.9; 44.6 vs 31.4 | cost of unlearning: perfect analyst; 5% false alarms | C3 |
| 65.2 -> 54.6; 2/72; 89 | NCE, closed world: reviews/day; malicious and benign dismissed | C4 |
| 54.8; 0/72; 89 | NCE, open world | C4 |
| 33.2; 30 | NCE with an analyst: reviews/day; benign dismissed | C4 |
| 34.1 | the same analyst without NCE | C3 (analyst always right, B5 on) |
| 65.2; 34.1; 0/72; 0 | NCE under asymmetric trust, without and with the analyst (Table III) | C4, asymmetric-trust rows |
| 1 of 797; 718 of 856 | command lines and raw log lines longer than 512 characters | C4, "What NCE is shown" |
| 33.1, 34.1, 38.1, 51.5 at 1, 4, 24, 72 h; 65.2 | host reviews/day by analyst delay; no analyst (text and Fig. 2) | C5, host table |
| 72; 400 | malicious raised and events alerted at every delay (text, Fig. 2 caption) | C5, host table |
| 60, 240, 1440, 4320 min; never | network containment after | C5, network table |
| client 2: 1.2 min (20 cases); client 1: 28.5 (11); 30.0 (11); 1265.0 min (4) | attack steps, 4-hour analyst | C5, "Attack steps" |
| 5%; 8 | network false-alarm rate; blocks that would have hit benign traffic | C5, last paragraph |

## Section V-F (C6, asymmetric trust)

| Number | Says | Source |
|:--|:--|:--|
| 4/428, 3/437, 10/437 | suppression unchanged | C1, asymmetric-trust rows |
| 20 of 178 (11.2%), 18 of 168 (10.7%), 21 of 176 (11.9%); 17, 18, 17 | containments removed; of them ERA-flagged | C1, first table |
| 0 of 178, 168, 178 | containments removed under asymmetric trust | C1, asymmetric-trust rows |
| 532; 336 | outcome totals on the development pairs (REVIEW, AUTO_APPROVED) | C1, "Outcomes per run" |
| 0/72; 400; 65.2; 34.1 | E1 under asymmetric trust | C1, E1 table, asymmetric-trust rows |
| 65.2 vs 54.8; 34.1 vs 33.2 | cost without and with an analyst | C1, E1 table; C4 |

## Section VI (discussion, limitations) and Section VII

| Number | Says | Source |
|:--|:--|:--|
| 130 of 439 (29.6%); 30 of 38 | undefended agent hijacked; steered host named | C1 |
| 4 of 428 | GUIDE suppression where the model is the detector | C1 |
| 0/72 | E1 on DEDALE under asymmetric trust | C1, asymmetric-trust rows |
| 2 | attacked Windows clients | Limits |
| 512; 1 of 797; 718 of 856 | what the model is shown | C4 |
| 73 of 473 | attack events silent after learning | derived from C2: static 473 minus frozen 400 |
| 503 | HTTP status of the overload errors | the current paper's Limitations bullet, used word for word as instructed |
| 6095.4 -> 65.2; 400; 38; 0/72 | conclusion | C2; C2; C1 |

## Other sources (not in RESULTS.md)

| Number | Source |
|:--|:--|
| 5,000 | base paper p. 4, Sec. IV-A |
| 50 | base paper p. 4, Sec. IV-A |
| 506 | base paper p. 5, Table VI |
| 480 | base paper p. 5, Table VI |
| 73 | derived: RESULTS.md C2, 473 - 400 |
| 503 | the current paper's Limitations bullet (required wording); RESEARCH_LOG.md 2026-11-01 |
