# DEDALE Phase 3 results — live NCE on host alerts (2026-10-11)

**Question:** when the LLM (NCE) reasons about the host alerts the Knowledge Store raises, does it lower the analyst's workload without losing the attack?

- Same data, detectors, store and scorer as Phase 2 (`experiments/DEDALE_PHASE2_RESULTS.md`). The only change is NCE turned on, live, for cases that reach the pipeline.
- Ground truth is **exact** (DEDALE's labelled host events). The replay never reads labels.

## Setup

- **Model:** gemini-3.1-flash-lite with the full technique vocabulary (design decision D6). Hypotheses are checked by SSE (structural feasibility), entity binding, RSEM, the guardrails and the outcome rule, as in the rest of the project.
- **Run:** learning mode `gated`, no analyst. `python -m experiments.dedale_host_replay --mode gated --nce live --max-calls 700 --overwrite`, then `python -m experiments.dedale_host_score --runs gated gated_nce gated_analyst --out phase3_scores.json`.
- **API use:** 416 live calls in total (117 from the pilot up to 2025-01-09, reused through the cache, plus 299 new), **0 errors**. The approved budget was about 450–900. Calls and results are cached per alert (`<data root>/runs/nce_cache_host.jsonl`), so replaying the same alerts with changed downstream code costs no new calls.
- **Runtime:** 14.4 min.

## Results

| | gated (NCE off, Phase 2) | **gated + NCE** | gated + analyst (Phase 2) |
|:--|--:|--:|--:|
| Test-week cases | 913 | **856** | 432 |
| Reviews / day (mean) | 65.2 | **54.6** | 30.9 |
| Week 1 / week 2 | 42.3 / 88.1 | **34.3 / 75.0** | 25.0 / 36.7 |
| Benign cases dismissed (NO_ACTIONABLE) | 0 | **89** | 0 |
| Malicious cases dismissed | 0 | **2 of 72** | 0 |
| Labelled class-1 events alerted | 400 | 400 | 400 |
| Attack keys learned as routine | 0 | 0 | 0 |

- **NCE removes 16% of the reviews.** Every one of these removals is a NO_ACTIONABLE decision: every hypothesis NCE proposed failed the feasibility check. Dismissed benign cases are mostly Microsoft Mail sync (`svchost.exe -> HxTsr.exe`, 67 cases) and OneDrive (`FileCoAuth.exe`, 16). 57 of the 89 were decided through the decision cache. 13 lineage keys were then learned through the gate (provenance `closed_benign`).
- **It also dismissed 2 malicious cases.** Both are the start of the collection step (2025-01-10 11:42, CLIENT1):
  - `cmd.exe -> scp.exe`, command line `scp -rp root@172.16.0.2:/root/customer_data.xlsx ./my_docs`.
  - The same `scp.exe`'s named pipe.

  NCE proposed T1039, T1078 and T1021.002. SSE rejected all three for the same reason: the store has no access edges for the internal Linux server, because DEDALE has no Windows logs from it. So "the store has no record of access" was read as "impossible". The step is still surfaced by 9 other cases, first at +30.0 min, the same as without NCE. Neither key was learned as routine.
- **NCE does not separate benign from malicious.** Among REVIEW cases, a hypothesis is FEASIBLE in 18 of 70 malicious and 60 of 695 benign cases. The rest are CONDITIONALLY_FEASIBLE: unconstrained techniques such as T1059 (scripting) and T1547 (autostart), or hosts it cannot resolve. Most common techniques on malicious cases: T1059 (59), T1547 (52), T1204 (23), T1078 (21). Nothing was auto-approved.
- **Where NCE points is a signal, not its verdict.** Of the 416 NCE results, 405 name only the alerting client itself as the target. The 11 that name another target are **10 labelled malicious events plus 1 unlabelled PowerShell record next to a labelled one**, and none is on a benign case:
  - the attacker addresses 172.19.1.1 and 172.19.0.2 (7 alerts, CLIENT2 initial access and CLIENT1 lateral movement);
  - the internal server 172.16.0.2 (the 2 scp alerts);
  - a `Z:` drive (1);
  - "unknown" (the scp pipe).

  These targets are exactly the entities the store has no telemetry for, so SSE rejects them.
- **Attack steps:**

  | Step | First surfaced (gated) | First surfaced (gated + NCE) | Cases (gated / + NCE) |
  |:--|--:|--:|--:|
  | Initial access, client 2 | +1.2 min | +1.2 min | 20 / 20 |
  | Lateral movement, client 1 | +28.5 min | +28.5 min | 11 / 11 |
  | Collection window | +30.0 min | +30.0 min | 11 / 9 |
  | Exfiltration window | +21 h | +21 h | 4 / 4 |

## What this means

1. **On real host telemetry, dismissal on structural infeasibility is not a safe filter by itself.** It dismisses about 11% of benign cases and about 3% of malicious ones (89 of 784 and 2 of 72). The malicious dismissals happen exactly where the store's knowledge has a gap, here a host with no telemetry.
2. **The analyst's verdicts cut reviews much more than NCE does:** 30.9 per day against 54.6, with no malicious case dismissed. Phase 2's analyst is an oracle, so that figure is an upper bound.
3. **Measured NCE value is small and comes with a cost.** For this model and this store, NCE adds labels to cases (technique, binding) rather than decisions.

## Caveats

- One model, one learning mode, one dataset, and the only labelled hosts are 2 clients.
- The decision cache reuses a dismissal for later cases on the same endpoints, so one wrong dismissal can repeat (here: 57 of the 89 benign dismissals came from the cache; the malicious ones were not repeated).
- The NCE input includes command lines (attacker-influenced free text); DEDALE's attack contains no prompt injection, so this run does not test contamination.

## Decision (a): open world for hosts without telemetry (implemented 2026-10-11)

- **Decision:** option (a), user-approved. The alternatives were (b) never dismiss a host alert on infeasibility alone, and (c) keep as is.
- **Change:** the environment profile now lists the hosts the store learns from (`EnvironmentProfile.observed_hosts`; for DEDALE, the 30 Windows clients). If SSE finds no access path to a host outside that list, it returns CONDITIONALLY_FEASIBLE ("access cannot be ruled out"), not INFEASIBLE, and the case goes to review. An address is resolved to the inventory host that owns it. Profiles without the list (the synthetic enterprise) are unchanged.
- **Replay:** `--mode gated --nce live --max-calls 50 --tag openworld`. **0 new API calls** (all 416 from the cache), 1.8 min.

| | gated + NCE (before) | **gated + NCE, open world** |
|:--|--:|--:|
| Reviews / day | 54.6 | **54.8** |
| Benign cases dismissed | 89 | **89** |
| Malicious cases dismissed | 2 of 72 | **0 of 72** |
| Collection-window cases surfaced | 9 | **11** |
| Attack keys learned as routine | 0 | 0 |

- **Effect:** both scp cases now go to review. The benign dismissals and the other attack-step timings are unchanged. The cost is 2 reviews over 14 days.
- **Remaining limits:**
  - Only the target host is checked against coverage. Account and source host are not, because there was no measured case.
  - The log-source list is configuration and must be kept current. A host that stops sending logs but stays on the list is still treated as fully known.

## NCE + analyst (2026-10-11)

- **Run:** `--mode gated --nce live --analyst oracle --max-calls 150`, with the open-world rule. 39 new live calls and 383 from the cache, 0 errors, 5.0 min. The project total is now 455 live calls.

| | gated + analyst (Phase 2) | **gated + NCE + analyst** |
|:--|--:|--:|
| Test-week cases | 432 | **455** |
| Reviews / day | 30.9 (wk1 25.0, wk2 36.7) | **30.0** (wk1 24.6, wk2 35.4) |
| Benign cases dismissed by NCE | – | 35 |
| Malicious cases dismissed | 0 of 72 | **0 of 72** |
| Analyst verdicts benign / malicious | 360 / 72 | 348 / 72 |
| Attack keys learned as routine | 0 | 0 |

- **On top of the analyst, NCE saves 3% of reviews.** All 72 malicious cases are reviewed, the attack-step timings are unchanged, and no attack key was learned.
- **NCE dismissals teach the store less than analyst verdicts, so cases recur.** There are 23 more cases than with the analyst alone.
  - An analyst's "benign" verdict teaches the pattern at once: 309 lineage keys were learned with provenance `analyst`.
  - An NCE dismissal waits in the learning gate: only 4 keys were learned `closed_benign`, and the gate dropped 29.
  - So a dismissed pattern can open new cases until it clears the gate.
