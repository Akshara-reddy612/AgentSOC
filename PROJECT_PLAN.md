# AgentSOC 2.0 — Project plan

Decided 2026-10-12 with Abhishek. This file sets the scope. Work outside it goes to "Later" (section 8) unless the plan is changed by a dated decision recorded here. Progress is tracked in `PROJECT_STATUS.md` and `RESEARCH_LOG.md` as before.

## 1. End goals

**Paper** (working title: *Securing Autonomous Defense*).

- **Thesis:** an LLM-driven SOC has two attack surfaces. The LLM reads log text an attacker can write, and the memory learns from what it sees and from analysts. The full pipeline can defend both while keeping the workload benefit of automation.
- **The pipeline, evaluated as one system:**
  1. NCE (LLM hypotheses);
  2. SSE structural checks + entity binding;
  3. RSEM response ranking;
  4. guardrails;
  5. triage gate;
  6. learning Knowledge Store (behind a learning gate);
  7. outcome monitor;
  8. analyst review loop (verdicts, approvals, unlearning).

**Tool.** A working agentic-SOC prototype with a real web frontend (replacing Streamlit). It shows the whole pipeline on a realistic use case, and someone outside the team can run it from the README.

## 2. Decisions (2026-10-12)

| # | Decision |
|:--|:--|
| P1 | One paper, combined thesis: both attack surfaces, full pipeline |
| P2 | Venue chosen after the draft exists |
| P3 | At most 3 datasets: GUIDE (synthetic corpus v2, contamination), DEDALE (real telemetry, the main evidence) and, optionally, AIT-LDS v2 (generality check, time-boxed) |
| P4 | Demo: a real frontend with accounts that depicts the whole pipeline on the DEDALE attack (section 5) |

## 3. Paper: claims and evidence

| Claim | Evidence | Status |
|:--|:--|:--|
| **C1** Text an attacker writes into logs does not steer the pipeline's actions | GUIDE v2, live, 500 + 500 clean/contaminated pairs: suppression 4 / 428 (dev) and 3 / 437 (held-out), against 4 / 0 responses induced for other reasons (p = 1.0 / 0.25). 0 steered actions executed. Undefended LLM agent on the same pairs: hijacked 48 / 156 (30.8%), against the defended pipeline's 2 / 155 (interim, 183 dev pairs) | Have for the reasoning half; **finish the interrupted runs (M2)**; **E1 needed for the full loop** |
| **C2** A learning Knowledge Store behind a gate cuts analyst load and keeps the attack visible | DEDALE host logs: 6,095 -> 65 reviews / day (static -> gated), 72 / 72 attack cases reviewed. Network: 552 -> 26 / day | Have |
| **C3** Memory poisoning and its defences: without the gate, or through analyst mistakes, the store learns the attacker; the gate and unlearning-on-confirmation prevent it | Ungated: 38 attack patterns learned; 99 attack events alerted, against 400 gated. Analyst missing 20% of attacks: 400 -> 256 attack events alerted; with unlearning, 400 / 400 (+10% reviews) | Have |
| **C4** What the LLM adds on real telemetry, and a failure mode | NCE: -16% reviews alone, -3% on top of an analyst. Closed-world feasibility dismissed 2 real attack cases; the open-world rule fixed it (0 / 72) | Have |
| **C5** Operating the analyst loop | Analyst feedback 65 -> 31 reviews / day. Analyst delay 1 h -> 72 h: 30 -> 50 reviews / day; network containment time equals the delay | Have |

- **Not claimed:** the review-queue order (in-sample; it stays a tool feature).
- **Limits to state:**
  - one real dataset with 2 labelled attacked hosts, unless E3 is done;
  - a simulated analyst;
  - one LLM (gemini-3.1-flash-lite);
  - synthetic entities and payloads in GUIDE v2.

## 4. Remaining experiments

| | Experiment | Needs | Size |
|:--|:--|:--|:--|
| **E1** | **Contamination through the full loop on DEDALE.** See below | API budget | **done 2026-10-18** (114 calls; `RESULTS.md` C1) |
| **E2** | **Freeze.** Re-run every headline number on the final code (NCE from the cache); one results file; `REPRODUCE.md` | nothing | **done 2026-10-18** (`experiments/RESULTS.md`) |
| **E2b** | **Finish the interrupted C1 runs** (found during M1): the undefended agent on the remaining dev pairs (~640 Gemini calls) and gpt-oss-20b on the remaining dev pairs (~740 Groq calls); plus 42 DEDALE alerts missing from the NCE cache (42 calls) | API budget | ~1-3 days of quota |
| E3 | Optional: AIT-LDS v2 generality check of C2-C3. See below | download approval | ~1 week |

- **E1 in detail:**
  - Attacker-written payloads (suppression, identity steering, fake approval claims) go into the command lines of DEDALE's labelled attack events.
  - Runs: gated + live NCE, with and without the analyst.
  - Measures: attack cases dismissed, attack patterns learned as routine, attack events still alerted, misdirected actions.
  - It links C1 and C3: can text in logs get the attacker's pattern learned?
- **E3 in detail:** 2 of the 8 networks (17 GB zipped, CC BY-NC-SA 4.0); needs Linux host detectors. Decided after the paper draft, and only if the draft needs a second real dataset.

## 5. The demo

**Use case: a day in the SOC during the DEDALE attack.**

1. **Learn normal:** the Knowledge Store learns two weeks of benign activity (statistics, graph).
2. **The attack day streams in**, replayed live at an adjustable speed. Most activity is recognised as routine; new patterns become cases; the queue orders them and says why.
3. **Case view:** the full pipeline trace for one case:
   - the alert, with trusted fields and untrusted text kept apart (injected text highlighted);
   - LLM hypotheses and the structural checks on them;
   - ranked responses and the guardrails;
   - the triage decision.
4. **The analyst confirms the attack:**
   - containment of a critical host needs a second analyst;
   - the host goes under watch;
   - patterns learned on it are visibly retracted.
5. **Knowledge Store view:** what was learned, from where (provenance), what was retracted, and the audit trail.
6. **Metrics:** reviews per day, attack coverage, learned and retracted patterns, compared with "no learning" and "no gate".
7. **Contamination:** an instruction injected in a command line, shown flagged and not executed.

**Frontend.**
- React + TypeScript single-page app (Vite).
- Pages: Live (stream + queue), Case (pipeline trace + actions), Knowledge Store (graph, provenance, audit), Metrics, Admin (accounts).
- Graph view with Cytoscape.js; charts with ECharts or Recharts.

**Backend additions.**
- **Live runner:** the SOC loop as a long-running process fed by a replay source (start / pause / speed). Its state is persisted (Knowledge Store + case store) and recovered after a restart.
- **Read APIs:** pipeline trace per case; Knowledge Store browse (nodes, edges, provenance, retractions, audit); metrics.
- **Accounts:** users and roles (analyst, lead), password hashing with Python's built-in scrypt, sessions. This replaces the token list.

Package installs (npm for the frontend; nothing new for Python) need approval, and the user runs them.

## 6. Milestones

| # | Milestone | Depends on | Who | Size |
|:--|:--|:--|:--|:--|
| M1 | E2: freeze, results tables, `REPRODUCE.md` | — | Claude | **done 2026-10-18** |
| M2 | E2b (finish the interrupted runs) and E1 (contamination through the full loop) | API budget approval | Claude | **E1 and the undefended run done 2026-10-18; gpt-oss-20b resumes daily (Groq cap)** |
| M3 | Paper draft. Outline first; Claude drafts methods and results from the M1-M2 tables; the team writes the introduction, related work and discussion | M1, M2 | team + Claude | 1-2 weeks |
| M4 | Demo backend: live runner + recovery, read APIs, accounts | — (alongside M3) | Claude | ~1 week |
| M5 | Frontend | M4, npm approval | Claude + team | 2-3 weeks |
| M6 | Optional E3 (AIT-LDS) | decided after M3 | Claude | ~1 week |
| M7 | Venue choice, final paper, demo video, README | all | team | ~1 week |

Order: M1 -> M2 -> M3 and M4 in parallel -> M5 -> (M6) -> M7.

## 7. Rules

- No datasets beyond the three in P3.
- No new pipeline features unless a claim (section 3) or the demo (section 5) needs them.
- New ideas go to "Later" below, not into the current milestone.
- Each milestone ends with the tracking docs updated, tests passing, and a merge to `main`.
- Live LLM runs need an approved call budget; downloads and installs need approval; pushes are asked for.
- This plan changes only by a dated decision recorded in this file.

## 8. Later (not in scope now)

- Queue order: an out-of-sample test (AIT-LDS or OpTC).
- DARPA OpTC: about 1 TB, with known label and data-quality problems.
- Withdrawing a wrong `malicious` verdict; tuning the 7-day unlearning window.
- Extending four-eyes to privileged accounts.
- Real EDR / firewall connectors (actions stay simulated).
- `perception/normalizer.py` (locked) classifies `destination_domain` as free text.

## 9. Risks

- **Two attacked hosts.** The real-data evidence rests on DEDALE's 2 labelled attacked hosts, so present it as a case study; E3 is the mitigation.
- **Simulated analyst.** Report its results as bounds, not field data.
- **One LLM.** State it as a limit; E1 adds real-telemetry evidence.
- **Frontend scope.** Keep to the pages in section 5; polish comes after function.
- **API budget.** Estimate before every live run.
