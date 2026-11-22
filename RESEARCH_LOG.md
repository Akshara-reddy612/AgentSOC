# Research log

The history of the project and the reasons behind it, newest first. The current state is in [PROJECT_STATUS.md](PROJECT_STATUS.md), and terms (NCE, SSE, RSEM, ERA, KS, B5, D7, E1 ...) are defined there.

- **Sources.** This file was rebuilt on 2026-11-22 from the full session log, the git history and the old handoff notes.
  - The verbatim session log (2026-08-19 .. 2026-11-08, 2,902 lines) is [archive/RESEARCH_LOG_HISTORY.md](archive/RESEARCH_LOG_HISTORY.md). **`H:<line>`** below means a line in that file.
  - The full old status file is [archive/PROJECT_STATUS_HISTORY.md](archive/PROJECT_STATUS_HISTORY.md) (**`S:<line>`**).
  - Two git-ignored notes on the lead's machine (`CLAUDE_HANDOFF.md`, 2026-10-11; `agentsoc_context_v2.md`, 2026-10-10) were never in git. Every fact taken from them is copied into this file, and both were deleted on 2026-11-22 at the user's request (`docs/_audit_report.md` §5).
  - Commits are cited by hash.
- **Labels.** Numbers marked VERIFIED 2026-11-22 were re-derived from files or re-run during the audit. Every other number is as the cited entry recorded it.
- **Reading triples and denominators.** "1 / 3 / 1" = E1 payload families `suppress` / `fake_approval` / `steer`. "20 / 178, 18 / 168, 21 / 176" = GUIDE dev Gemini / held-out Gemini / dev gpt-oss-20b. Suppression and hijack denominators, run names (`F_*`, `A_*`, `d4`, `m20`, ...) and the two "Phase" numberings are defined in `PROJECT_STATUS.md` (Terms).

## Entries

### 2026-11-22 (night): checklist A11, training-window rotation (offline)

- **What:** the DEDALE host replay can now train on one clean week only (`--train-window week1|week2`, `experiments/dedale_host_replay.py`; week 1 = 2024-12-23..12-29, week 2 = 12-30..2025-01-05). Six offline replays (`experiments/rotation_runs.py`, all rc=0), scored by `experiments/rotation_score.py` -> `experiments/dedale_results/rotation_scores.json`, generated into `experiments/RESULTS.md`.
- **Result** (reviews/day frozen; attack cases; events; attack patterns learned with a 20% analyst miss rate, B5 on / off):
  - both weeks: 65.2; 72; 400; 0 / 20
  - week 1 only: 110.9; 72; 400; 0 / 24
  - week 2 only: 111.4; 72; 400; 0 / 18
- **Meaning:** a shorter training window roughly doubles the frozen workload (still 98.2% below static) but changes neither detection nor the unlearning result. Paper: a "Training window" paragraph in §V-B; the paper still fits 7 pages after trims (limitation (1), the gate-delay sentence, plot heights).
- **Checklist:** 20 of 29 done (A11 added). The 7-page version has no spare lines; the A6 / B1 results due tomorrow are recommended for an 8-page version.

### 2026-11-22 (late): reviewer checklist pass on the v3 paper

- **Fully done now (19 of 29 items):** A1 A2 A5 A9 A10, B2 B3 B4 B5 B6 B7, C1-C8. Results generated into `experiments/RESULTS.md`:
  - A9, event-level false-positive rate (0.021%; `experiments/event_fpr.py`);
  - B7, paired CIs for the GUIDE suppressions and T2.2;
  - A5, E1 payloads fully in NCE's view, 114 of 114 (`experiments/e1_view.py`);
  - B5, latency, token estimate, NCE calls per day, review-queue growth (`experiments/operational_cost.py`).
- **References (B3): 24 -> 49, then 40 (user: 40 is enough; 9 duplicating references dropped so that Table I and the analyst-delay figure fit back in).** Each new one was checked on a source page (arXiv, USENIX, NDSS, IJCAI, PMLR, ACL Anthology or an author's publication list). A venue that could not be confirmed is cited as the arXiv preprint. DeepLog, He et al. (ISSRE 2016) and Kokulu et al. (CCS 2019) could not be confirmed from any reachable page and are not cited.
- **Space for the 7-page limit:** Table I and the analyst-delay figure were removed for the 49-reference version and restored with 40 references. The Discussion, Limitations, Fail-Safes and Conclusion were compressed.
- **Ready but not run:** A6 (telemetry-aware undefended agent) and B1 (temperature 0.7 repeats); about 1,200 calls, approved by the user; `bash tools/live_queue.sh` after the quota reset.
- **Still open:** A3 (StruQ, flooding, ablation), A7 (MemStream), A8 (low-and-slow), A11 (window rotation), B1 (frontier model), D (anonymization, Zenodo DOI, AI disclosure).

### 2026-11-22: Tier 2 runs: duplicate queue, key quota, T2.2 cut to 150 pairs

- **Duplicate queue.** Stopping a background bash task on Windows did not stop the queue script, so two copies ran from about 13:15 to 14:03 UTC. They duplicated calls and both wrote the T2.3 results file. The file loads cleanly and the runners resume, but calls were wasted. Both copies were killed with `taskkill /T`, and only one queue runs at a time now.
- **Key quota.** A one-call probe per key at 14:05 UTC: 10 of 18 Gemini keys returned 429 RESOURCE_EXHAUSTED, which the runner had reported only as 60 s timeouts. Keys stopped after about 60-150 successful calls each, not the 500 per day assumed in P11. The 8 working keys run alone via an exported `GEMINI_API_KEYS`.
- **State at 14:10 UTC.** T2.1 held-out: 1,000 records, 991 answered. T2.3: 158 of 300 stored. 1,904 attempts used in all.
- **Decision (user).** T2.2 runs on the first 150 dev pairs (P11 amended), about 900 calls; the rest of Tier 2 stays within the 4,300 budget.

### 2026-11-22: Tier 1 scored, A7 fixed, a broken run recreated, 8-page budget

- **A7 rarity baseline, first run invalid.** It retracted all 6,484 training patterns at every K: the loop learns a key once, so its edge count is always 1. `experiments/dedale_host_replay.py` now counts each key's frequency over the training events (`_training_frequencies`). Re-run; results in `experiments/dedale_results/tier1_scores.json` and `experiments/RESULTS.md` (Paper revision section).
- **A broken run on disk.** `D:\agentsoc_data\runs\dedale_host_gated_nce_F_nce\cases.sqlite` (dated 2026-10-18 15:42) held 0 cases although `cases.jsonl` held 856. Re-scoring with it blanked the clean row's injected-case counts in `e1_scores.json` and the "What NCE is shown" line of RESULTS.md. The old directory was kept as `_broken_20261122_dedale_host_gated_nce_F_nce`; the replay was recreated offline. Its summary equals the old one except runtime and three keys added later with default values, and `e1_scores.json` re-scores identical to the committed file.
- **RESULTS.md rebuilt** after the 8 missing hardened (`A_`) replays were recreated. Only the date line was removed; the Paper revision section was added. Suite: 810 passed, 1 deselected.
- **Tier 2 keys.** The user added 5 Gemini keys (13 in all). T2.1 was stopped after 562 stored records and restarted with 13 workers; the 27 timeouts in the first 2 minutes came from 13 child processes starting at once.
- **Paper length.** The draft is 9 pages in Word at 8.5 pt with 0.35 in margins, about 14 pages in IEEE format. The user set 8 pages; the budget is in `paper/PAGE_BUDGET.md` (about 4,750 words of body text, appendices to the repo, Figs. 5 and 6 cut). First rewrite draft: `paper/REVISION_DRAFT.md`, about 3,600 words of body text, all numbers from RESULTS.md (the K-row attack-pattern count from `tier1_scores.json`).

### 2026-11-22: paper revision decided (P10); design of A10, the persuaded analyst
- **Context:** a review of the paper draft listed blockers. Assessed: the offline items (Tier 1) are worth doing; four of the review's premises are contradicted by the repository (E1's payloads sit in command lines, of which 1 of 797 exceeds 512 characters; the undefended agent's prompt includes structured fields, `agent/baseline_agent.py:74-77`; the frozen condition already is a clean-weeks allowlist; the gate did learn under the acting rule and with D7 off).
- **Decided (P10, user):** Tier 1 in scope, offline, no pipeline change, a design approved before each run. A10's safeguard is future work.
- **A10 design written** (`experiments/PERSUADED_ANALYST_DESIGN.md`), from facts checked read-only on `dedale_host_gated_nce_analyst_E1_fake_approval`: attacker text reaches 38 of 72 attack cases (CLIENT2 17 / 35, CLIENT1 21 / 37); CLIENT2's first attack case is text-free, CLIENT1's first carries text. Predictions written before any run: per-case persuasion is undone by B5; host-wide persuasion can leave CLIENT1 unconfirmed, so its attack patterns stay learned.

### 2026-11-22: repository audit and tracking-file rebuild
- **Done:** full audit of every document against the code, the result files and real runs, on branch `chore/repo-audit-tracking`. Report: [docs/_audit_report.md](docs/_audit_report.md).
- **Runs** (all offline, no API call):
  - tests: 804 passed, 1 deselected; with an empty data folder 803 passed, 1 skipped;
  - venv identical to `requirements-lock.txt`;
  - frontend typecheck clean;
  - GUIDE re-scores byte-identical to `agent/v2_results/*_rescored.json`;
  - demo server first start: 7,505,328 events;
  - `tools/e2e_check.py`: 9 / 9;
  - DEDALE re-freeze (43 replays in an isolated data root): all 43 replays exit 0 (06:37-07:13 UTC, about 36 min with 6 workers; 0 events refused); `final_host_scores.json`, `final_network_scores.json`, `e1_scores.json` and both `paper/fig_*.dat` byte-identical to the committed files (after normalising line endings: the Windows checkout writes CRLF, git stores LF); the rebuilt `RESULTS.md` differs only in its date line.
- **Found:**
  - `PROJECT_STATUS.md` was dated 2026-10-27 and said `paper-v2-accuracy` was not merged; it was merged (`6e70cf2`).
  - Nothing recorded the 2026-11-09 Fig. 1 work.
  - `D:\agentsoc_data\runs` holds no output of the 8 asymmetric-trust replays the 2026-10-31 re-freeze reported.
  - The team's `AgentSOC_IEEE_Revised.docx` has three claims the repository does not support (planned-experiment "harnesses implemented in the repository"; network 32.4 reviews/day; 624 cases).
  - `build_results` silently drops the asymmetric-trust C1 rows without the escalate re-scores.
- **Decided:**
  - The paper draft being worked on is `AgentSOC_IEEE_Revised.docx`; `Documentation_Template-SDC-II.docx` is needed for the course report (user, 2026-11-22).
  - Root clean-up (user, 2026-11-22): `PAPER_OUTLINE.md` removed (outline of the superseded combined LaTeX paper); the untracked old handoff notes and the v1 LaTeX build log deleted after their facts were copied here.
  - The two `.docx` files are untracked on purpose (user, 2026-11-22: the paper is still being written; the template is only a template); old log archived verbatim (`c52b6f9`); this file and `PROJECT_STATUS.md` rewritten.
  - `HANDOVER.md` merged into the status file and removed.
  - Stale design-doc headers annotated with dated notes; nothing historical deleted.

### 2026-11-09: paper v2 Fig. 1 redrawn (reconstructed from commits; no session entry was written)
- Redrawn twice:
  - first as six numbered stages in two lanes (`3832baa`, merged `fb1f43d`);
  - then as a hybrid of the base paper's AgentSOC architecture and the GuardedSOC security workflow (`d61dd7f`), checked against the code (`ad4c748`): SSE validation as its own step, simulated execution, Execution Interface → Real-Time Monitoring drawn one way (`c085a5e`, `b9f22fc`).
- Merged `da17235`. No code or result changed (commit file lists touch `paper/` only).

### 2026-11-08: paper v2 named GuardedSOC; figures, tables, accuracy fixes (H:2801-2902)
- **Naming:** the system is now GuardedSOC ("AgentSOC" means only the base paper).
- **Figures:** four result figures (attacker text, C2, C3, C4).
- **Tables:** Tables II-III were briefly dropped, then restored next to all six figures. Every numeric token is traced in `paper/agentsoc_v2_numbers.md` (380 tokens, 370 in `RESULTS.md`).
- **Accuracy fixes** from a code walkthrough:
  - program paths and parent process are attacker-chosen (new limitation: evasion by mimicry);
  - ERA and the destination-telemetry check apply to GUIDE only;
  - the gate's 24 h delay and same-host rule are stated;
  - fail-safe is described as unit-tested, not evaluated;
  - triage runs once per case.
- All three branches were merged (`paper-v2` in `5476d51`, which also carried the two 11-08 `paper-v2` sessions; `paper-v2-tables` in `8fb0c0c`; `paper-v2-accuracy` in `6e70cf2`), although the four session headings said "not merged" (H:2801, 2831, 2852, 2872).
- Tooling gotcha: poppler `pdftoppm` draws stray hatching for PDF tiling patterns; check renders with `pdftocairo` (H:2817).

### 2026-11-01: missing prompt-level baseline; a new paper (H:2759-2799)
- **Hardened-prompt comparison:** prepared on DEDALE; the API returned only HTTP 503 in two pilots, so no result is claimed. A Limitations item says so (`9c6e022`, merged `95f3d3c`).
  - `docs/LIMITATIONS_DRAFT.md` cites the counts (6 calls, 24 requests, 0 answers) from branch `baseline-prompt`. That branch is **not in this repository** (UNVERIFIED).
- **Paper v2:** `paper/agentsoc_v2.tex` written fresh from `RESULTS.md` against the base paper (6 pages, merged `d97e46f`).

### 2026-10-31: external review → decisions P8, P9; asymmetric trust; fail-safe (H:2577-2757)
- **The review:** an external review listed ten weaknesses, each checked against the code (H:2580-2591).
  - **P8:** fix them one branch at a time.
  - **P9:** move the work to the pipeline's defences: A asymmetric trust, B corroborated learning, C analyst-aimed text, D prompt baselines (needs a budget). E3 not now.
- **Change 5:** decision-cache entries carry the decision policy (`TriageGate.policy()`), so a restart with another `--nce` cannot reuse old decisions (`417286a`).
- **Change 8:** checkpoints load only allowlisted classes and carry an HMAC-signed manifest. A crash between the two renames restores `checkpoint.old` (`05e0c0b`).
- **Change 9** (hash-chained audit log): never merged. No code for it exists; the plan's "stays on its branch" refers to a branch that is not in the repository.
- **Asymmetric trust** (`6fd3fa6`, merged `8253d99`):
  - the outcome is the text-free decision or REVIEW, and only text-free actions execute;
  - E1 attack cases dismissed without an analyst (families suppress / fake_approval / steer) 1 / 3 / 1 → 0;
  - GUIDE automatic containments removed by contamination (dev Gemini / held-out Gemini / dev gpt-oss-20b) 20 / 178, 18 / 168, 21 / 176 → 0. In 17 / 18 / 17 of those, the removal came from ERA flagging the contaminated twin: its escalation to review held the automatic block back;
  - cost +0.9 reviews/day with an analyst, +10.4 without (H:2643-2652).
- **Fail-safe processing** (`7cf6d48`):
  - malformed events are refused; a failing event is quarantined with checkpoint recovery;
  - each analyst command runs in a savepoint;
  - the T1071 grounding regex was quadratic: 40,000 characters took 62 s, now 0.02 s over the 512-character view (H:2667-2677).
- **Re-freeze:** 43 / 43 replays, all three score files byte-identical (H:2709-2717).
  - Where it ran is UNVERIFIED (its `A_*` outputs are not in `D:\agentsoc_data`), but the 2026-11-22 re-freeze reproduced its three score files byte-identically.
  - LLM-off rule checks: the gated and `F_d4` conditions under `escalate` equal their frozen runs in all 9 score fields (reviews per day, test cases, attack cases reviewed, events alerted, patterns learned, per-day series, attack steps, ...; H:2735, 2749).
- **Paper and drafts:** contribution C6 added to `paper/agentsoc_combined.tex` (7 pages; `paper/agentsoc_v2.tex` did not exist yet); drafts of the limitations section and viva answers (`docs/`).

### 2026-10-27: reviewer pass on the paper (H:2548-2575)
- Every number in `paper/agentsoc_combined.tex` checked against `RESULTS.md`.
- **Fixed wording:**
  - ERA was never introduced;
  - "all 400 labelled attack events" → 400 of the 473 that alert with nothing learned;
  - gated = frozen without NCE or an analyst;
  - "real telemetry" → testbed;
  - the open-world rule was adopted after the closed-world misses;
  - no prompt-level baseline.

### 2026-10-19 .. 10-21: demo tool, frontend, handover (M5, M8) (H:1949-2546)
- **Frontend (React + TypeScript, M5):** built and checked in headless Edge with 0 JavaScript errors.
  - The user disliked the first navy/cyan look ("it gives an AI feel"), so it became a graphite console theme with a muted red brand accent `#b4483f` (H:2316-2347).
  - Added the Contamination Lab (GUIDE pairs; totals asserted equal to Table I) and a host timeline (UTC axis fix).
- **Backend gaps (P5):** network alerts in the server (`MergedSource`), `--nce cache|live|off`, login throttling, withdrawing a malicious verdict, live log following (`--follow`), the contamination scenario (`--inject`).
  - Found and fixed: live NCE would have appended to the recorded caches (now it copies them into the home).
  - Found and fixed: the queue counted an alert's own destination as "another target" (H:2033-2043, 2134-2143).
- **Accounts in the browser:** first-run setup, own password, admin role / enable / reset.
- **Soak test (2026-10-20):** the full dataset fast-forwarded, 15,013,901 events and 8,588 test cases, peak RSS 388 MB, read APIs ≤ 0.12 s, restart about 10 s (H:2249-2253). UNVERIFIED: not re-run.
- **gpt-oss-20b GUIDE dev run complete:** 10 / 437 suppressed (H:2254-2258); VERIFIED 2026-11-22.
- **Fresh-clone reproduction:** 778 tests; GUIDE and DEDALE results byte-identical; 29 replays in about 25 min (H:2492-2511).
- **Recorded DEDALE NCE answers** moved into the repository (`experiments/dedale_results/nce_cache/`) because a teammate's machine would have lacked them (H:2513-2530).
- **Team data package** `dedale_for_team.zip` (321 MiB, VERIFIED 2026-11-22) replaces the 27.1 GB + 4.4 GB downloads (H:2532-2538).
- **Paper draft:** full draft in `paper/agentsoc_combined.tex` (P6: Claude drafted every section; 15 references checked). Figs. 2-3 come from `experiments/build_figures.py`.
- **Cleanup:** superseded files `git mv`-ed to `archive/` (`de33bd0`).

### 2026-10-18: freeze (M1), finishing C1 (M2), E1, demo backend (M4) (H:1818-1947)
- **Freeze:** `freeze_dedale.py` (then 29 replays), `build_results.py` → `experiments/RESULTS.md`, and `REPRODUCE.md`.
- **Undefended agent on all 500 GUIDE dev pairs:** hijacked 130 / 439 (29.6%), against the defended pipeline's 4 / 428 (H:1875-1878); VERIFIED 2026-11-22.
- **E1** (approved about 114 Gemini calls):
  - attacker text in DEDALE's own attack command lines; 1 / 3 / 1 attack cases dismissed without an analyst, 0 with one;
  - 0 attack patterns learned, because the gate dropped the dismissed cases (same-host escalations);
  - the steering text was followed 30-32 / 38 times and every steered hypothesis was flagged unbound (H:1898-1906).
- **Demo backend (M4):** accounts (scrypt), live runner with checkpoints, read APIs, `python -m soc_server`. A gap was fixed: pausing did not checkpoint at once.

### 2026-10-12: project plan (H:1795-1816)
- The user felt the work "going around with the flow" (GUIDE → DEDALE → analyst loop → more datasets) with no end goal.
- `PROJECT_PLAN.md` fixed the scope: one combined paper; at most 3 datasets; a real frontend demo; milestones M1-M7; a "Later" list.
- Gap found while writing it: contamination had never been tested through the learning loop. That became E1.

### 2026-10-11: one long day: GUIDE v2, DEDALE, the learning loop, the analyst loop (H:846-1793; 91 commits)
- **GUIDE corpus v2 and live runs:**
  - synthetic enterprise inventory (seed 73);
  - corpus v2: 10 families, paired twins, seed 79, behaviour-label evidence. The first attempt at literal command lines was stopped by a safety classifier (H:870);
  - trusted destination with BLOCK_DESTINATION; expected-activity rule; telemetry C2 hypothesis.
  - Full live runs, 500 + 500 pairs, Gemini: suppression 4 / 4 discordant dev (p = 1.0), 3 / 0 held-out (p = 0.25) (H:1001-1004).
- **Second model (Groq gpt-oss-20b):** partial at first, because the free-text caller failed and Groq caps tokens per day; it exposed a telemetry-rule bypass, fixed by requiring a bound source host (H:1029-1038).
- **ERA as an escalation signal** (H:1052-1058):
  - flags 0 / 1,000 clean alerts and 65 / 500 + 56 / 500 contaminated ones;
  - it misses v2's varied phrasings because partial hits are diluted in score fusion.
- **Moved the project** from `C:\agentsoc` to `D:\agentsoc`; 162 `file:///` links rewritten (H:1069-1084).
- **DEDALE: downloaded with approval, inspected, scoped** (H:1086-1151, `experiments/DEDALE_DATA_NOTES.md`):
  - host labels are positives only, for 3 hosts: CLIENT1 and CLIENT2 (Windows), and the internal Linux server, whose auditd logs were never downloaded, so only the 2 Windows clients count in the experiments;
  - 88.5% of 1,465,627 Suricata alerts are the SIEM's own log shipping;
  - 83 of 84 labelled attack flows raised no Suricata alert;
  - `REAL_TELEMETRY_PLAN.md` was wrong that DEDALE ships labelled Sigma alerts.
- **Learning Knowledge Store, steps S1-S9** (H:1153-1368; `experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md`): environment profile, SQLite store, DEDALE adapter, case builder, learning gate, triage gate, outcome monitor, `SocLoop`, scorer.
  - Every step re-scored all stored GUIDE runs with 0 changes.
- **DEDALE results by phase:**
  - Phase 1 (network): static 552.3 → gated 26.1 reviews/day.
  - Phase 2 (host logs; 13,548,274 events kept of 188,115,925): static 6,095.4 → gated 65.2; 72 / 72 attack cases reviewed.
  - Phase 3 (live NCE, 416 calls): 54.6 / day, but 2 attack cases dismissed by closed-world SSE → decision (a), the open-world rule → 0 (H:1330-1560).
- **Analyst review loop (plan B):**
  - case store as the loop's inbox; review service; four-eyes; rollback;
  - review API with FastAPI. The install was blocked for Claude, so the user installed it.
  - Evaluation: a 20% miss rate teaches 20 attack patterns, so **B5** (unlearn on confirmed compromise) was added → 0 learned (H:1611-1793).
- **Gotchas found that day:**
  - Windows `os.replace` failed while a monitor held the results file open (H:997);
  - set iteration made escalation-reason order depend on `PYTHONHASHSEED` (H:1641);
  - an unsafe `taskkill /FI "WINDOWTITLE eq *"` was run. It closed nothing, but must never be repeated (H:1784-1786).

### 2026-10-10: full read-only audit; GUIDE v1 results restated; Phases 0-2 (H:606-844)
- **The audit** recomputed every v1 headline from raw files and found it could not be claimed as written (H:619-631):
  - "85-86% defense success" is not an attack-blocking rate: clean twins reach the same no-actionable rate;
  - 114 of 320 "clean twins" were contaminated or mismatched rows. On the 206 valid pairs there was no detectable effect (McNemar p ≥ 0.25);
  - severity label leakage (IncidentGrade → `severity` in the undefended prompt);
  - a literal `INJECTED_FIELD_VALUE` wrapper in payloads;
  - the synthetic evidence contains the T1071 filter's own patterns;
  - non-T1071 hypotheses were INFEASIBLE only because the graph held none of GUIDE's entities;
  - SSE duplicate paths.
- **Phase 0:** overwrite guard (`agent/run_guard.py`); pytest scope (`pyproject.toml`); the watchdog bug fixed (a test had left it pointing at `experiments.fake_harness`).
- **Phase 1:** clean twins rebuilt (`experiments/build_clean_twins.py`).
- **Phase 2:** lock lifted on six `perception/` files; regression tool `experiments/rescore_all.py` with snapshots s0-s8; SSE de-duplication; synthetic network model (RFC 5737 addresses, seed 71); T1071 grounding label instead of a drop; BLOCK_EGRESS; entity binding.

### 2026-10-03 .. 10-05: Experiment 1, paired clean vs contaminated (H:564-604)
- **Result:** clean twins 275 / 276 vs contaminated 277 / 273 of 320 with no actionable hypothesis. The headline was a base rate, not a defence.
- **Harness failures:**
  - the watchdog blocked on `readline()`;
  - the key pool rotated only on HTTP 429;
  - the free tier is **500 requests/day per key** for gemini-3.1-flash-lite (an earlier "1,500" was wrong).

### 2026-09-05 .. 09-29: structural pipeline evaluations on GUIDE v1 (H:3-220, 425-561)
Phase names of that time: NCE-1 .. NCE-8 were the steps of building and evaluating NCE (NCE-7 = NCE → SSE → RSEM on 10 alerts; NCE-7-SCALE = the same on 90; NCE-8 = 50 clean alerts for false positives).
- **NCE-7 → NCE-7-SCALE:** 7 / 8 (87.5%) → 64 / 80 (80.0%). All 16 failures are T1071, because the C2 check only needs web egress.
  - Factor split (H:131-134): first recorded as 12 / 4, corrected to 10 REASONABLE + 6 QUESTIONABLE.
- **NCE-8:** clean false-positive rate 14 / 50, all T1071 (H:78).
- **T1071 evidentiary filter:** 64 → 67 / 80. The blocklist version failed first (H:474-477).
- **ApprovalClaimDetector:** reworked into field-injection vs narrative shape plus a nested-quote fix. 1 / 100 benign false positives (H:458-467).
  - Commit `e25e3b0` bundles two fixes; it was pushed and not rewritten (H:444-450).
- **n=400 (8 families × 50):** run A 344 / 400, run B 340 / 400 (H:550). "341 / 337" was an arithmetic slip.
- **Also built:** the Action/Playbook layer, the monitoring layer and the Streamlit demo.
- **SSE mutation bug:** the graph grew from 20 to 326 nodes during evaluation; fixed in `fc0f089` (H:536-544).

### 2026-08-29 .. 09-04: knowledge graph, SSE, RSEM, NCE contract (H:387-423)
- Built `perception/knowledge_graph.py`, `sse.py` (7 techniques), `rsem.py` and `nce_contract.py`: 246 tests.
- A manual read caught that REVOKE_SESSION, RESTRICT_PRIVILEGES and QUARANTINE_ACCESS had identical effects although all tests passed. Fixed, with differential tests (H:401).

### 2026-08-19 .. 08-22: undefended vs prompt-defended triage agent on GUIDE v1 (H:222-385)
- 14 payload families tested on the undefended agent (Gemini flash-lite, Groq gpt-oss-20b).
- **Defended agent** (ERA + XML policy + JSON mode + schema gate): recovered 21 / 38 hijacks (55.3%) (H:358).
  - A first "79%" counted 16 network-error fallbacks as recoveries (H:272).
- **Small samples are unreliable in both directions:** n=3 → n=10 moved rates both ways, e.g. Groq authority_escalation 33% → 70% (H:365-370).
- **Caveat (2026-10-10):** every v1 undefended hijack rate was measured with the label-leaking `severity` field in the prompt (H:621).

### 2026-08-03 .. 08-04: ERA and safe prompt construction (commits `40f5e07`..`cda75d6`)
- `risk_assessment/`: NFKC, confusables, base64; regex, semantic and split-field detectors; weighted fusion with a ceiling rule.
- `prompt_construction/`: escaped XML/JSON serialisers.
- 149 tests.

### 2026-07-24: perception layer (commits `16daeb7`..`8e5d98f`)
- Source systems, trusted fields, schema validation (SCHEMA_001-004), the normalizer with fail-safe FREE_TEXT, derived context, noise reducer, pipeline logging.
- 51 tests.

## Dead ends: do not retry

| Tried | Why it failed / was dropped | Source |
|:--|:--|:--|
| Reporting "defense success" (no actionable hypothesis) on GUIDE v1 | Clean twins score the same; on GUIDE every payload is a suppression attack, so "no actionable" is the attacker's goal | H:566, H:620-623 |
| GUIDE v1 synthetic evidence (`synth_fields.py`) for detection claims | Templates contain the T1071 filter's patterns; payloads wrapped in `INJECTED_FIELD_VALUE`; severity leaks the label | H:621-622; corpus v2 replaced it |
| SSE as a dismissal criterion on real telemetry (closed world) | Dismissed 2 real attack cases: "no record of access" read as "impossible". It does not separate benign from malicious either (FEASIBLE 18 / 70 malicious vs 60 / 695 benign) | H:1524-1527; open-world rule |
| Detectors keyed on command-line shape or DNS domain | 2,467 and 396 benign new keys per day | H:1474-1490 |
| First-contact outbound pairs as a network detector | 4,400-9,300 new pairs per weekday | H:1409 |
| Blocklist regex for domains in the T1071 filter | Leaked usernames (`a.patel`) and timestamps (`46.000Z`); replaced by a positive public-TLD match | H:474-477 |
| "Ambiguous-grade alerts are more vulnerable" / confidence by grade | 0.0% vs 11.1%; synthetic evidence gives uniform 0.95-1.0 confidence | H:237-238 |
| Measuring detection accuracy on GUIDE v2 | Evidence is grade-independent by design | H:1017 |
| Literal attack command lines in the corpus v2 generator | Stopped by a safety classifier; behaviour labels used instead | H:870 |
| Groq with a free-text caller | Median 17.7 s, 6 / 42 failures; JSON mode works | H:1031 |
| Thread-based timeout for hung API sockets | Cannot cancel a hung socket; use a spawned process | H:599 |
| Per-event SQLite savepoints in the live runner | 9 µs each, about 134 s more on the demo's first start; chunk rollback plus checkpoint recovery used | H:2670 |
| Hardened-prompt baseline on DEDALE (2026-11-01) | API returned only HTTP 503; no result. Branch not in this repository | H:2761; `docs/LIMITATIONS_DRAFT.md:113` |
| Tuning the review-queue order further on DEDALE | In-sample fitting; STUN cases stay level with the attack ("Later") | H:2039-2042 |
| `taskkill /F /FI "WINDOWTITLE eq *"` to stop a server | Could force-close every windowed program; stop servers by PID | H:1784-1786 |
| Opening a results JSON to monitor a long run (Windows) | `os.replace` fails while the file is open; crashed a run once; watch the API log | H:997 |

## Results

Final results are the frozen files behind `experiments/RESULTS.md` (rebuilt by `python -m experiments.build_results`). Earlier numbers are kept for history; their status says whether they still stand.

| Result | Value | Source (file / script) | Config | Date | Status |
|:--|:--|:--|:--|:--|:--|
| C1 GUIDE v2 dev suppression | 4 / 428 (0.9%, CI 0.4-2.4%), McNemar p = 1 (ERA-separated) | `agent/v2_results/v2_dev_live_results_rescored.json`; `RESULTS.md:11` | gemini-3.1-flash-lite, acting rule | 2026-10-11 run; frozen 2026-10-31 | VERIFIED 2026-11-22 (re-score byte-identical) |
| C1 held-out | 3 / 437 (0.7%), p = 0.25 | `agent/v2_results/v2_heldout_live_results_rescored.json`; `RESULTS.md:12` | same | same | VERIFIED 2026-11-22 |
| C1 gpt-oss-20b dev | 10 / 437 (2.3%), p = 0.3 | `agent/v2_results/v2_dev_live_groq-openai-gpt-oss-20b_results_rescored.json`; `RESULTS.md:13` | groq:openai/gpt-oss-20b | completed 2026-10-20 | VERIFIED 2026-11-22 |
| Undefended agent dev | 130 / 439 hijacked (29.6%, CI 25.5-34.0%) | `agent/v2_results/v2_dev_undefended_results.json`; `experiments/undefended_metrics.py` | gemini-3.1-flash-lite | 2026-10-18 | VERIFIED 2026-11-22 (re-run) |
| C6 GUIDE containments removed | 20 / 178, 18 / 168, 21 / 176 → 0 | `RESULTS.md:11-16` (escalate re-scores) | acting vs escalate | 2026-10-31 | escalate re-scores re-run 2026-11-22 in the audit's separate worktree (rc 0; outputs there, not in this checkout's `logs/`); `RESULTS.md` rebuild identical apart from its date line |
| E1 dismissals | 1 / 3 / 1 of 72 → 0 under asymmetric trust | `experiments/dedale_results/e1_scores.json`; `RESULTS.md:42-57` | gated + NCE cache, ± analyst | 2026-10-18 / 10-31 | VERIFIED 2026-11-22 (re-freeze byte-identical) |
| C2 host reviews/day | static 6,095.4, frozen = gated 65.2, ungated 27.4 | `final_host_scores.json`; `RESULTS.md:67-70` | NCE off | frozen 2026-10-31 | VERIFIED 2026-11-22 (re-freeze byte-identical) |
| C2 network reviews/day | static 552.3, frozen 26.1, gated 26.1, ungated 20.6, gated with D7 off 7.9 | `final_network_scores.json`; `RESULTS.md:76-80` | NCE off | same | VERIFIED 2026-11-22 (re-freeze byte-identical) |
| C3 analyst mistakes | misses 20%: 20 learned, 256 alerted; with B5: 0, 400 | `final_host_scores.json`; `RESULTS.md:92-93` | oracle 4 h | same | VERIFIED 2026-11-22 (re-freeze byte-identical) |
| C4 NCE on DEDALE | 54.6 (closed) / 54.8 (open) / 33.2 (+analyst); asymmetric 65.2 / 34.1 | `RESULTS.md:103-108` | NCE cache `nce_cache_host.jsonl`: 497 recorded answers (416 Phase 3 + 39 NCE+analyst + 42 cache-fill calls of 2026-10-18; H:1517, 1568, 1879, 2517) | same | VERIFIED 2026-11-22 (re-freeze byte-identical) |
| C5 analyst delay | 33.1 / 34.1 / 38.1 / 51.5 reviews/day | `RESULTS.md:121-124` | 1 / 4 / 24 / 72 h | same | VERIFIED 2026-11-22 (re-freeze byte-identical) |
| What NCE is shown | command line > 512 chars in 1 / 797; raw line in 718 / 856 | `RESULTS.md:110` (`build_results._nce_view`) | `gated_nce_F_nce` case store | 2026-10-31 | VERIFIED 2026-11-22 (re-freeze byte-identical) |
| Soak test | 15,013,901 events, 388 MB peak | H:2249-2253 | full replay | 2026-10-20 | UNVERIFIED (not re-run) |
| Demo first start | 7,505,328 events learned, then paused at 2025-01-06 08:00 | `python -m soc_server` (audit run) | host + network, NCE cache | 2026-11-22 | VERIFIED |
| GUIDE v1 Experiment 1 (valid pairs) | no-actionable clean 178 / 179, contaminated 177 / 176 of 206; p ≥ 0.25 | `experiments/analyze_paired_valid.py` | v1 corpus | 2026-10-10 | Historical; "no detectable effect" only |
| GUIDE v1 structural "defense" | 64 / 80 → 67 / 80; n=400: 344 / 340 | `agent/nce7_scale_results.json`, `agent/nce_n50_scaleup_results_run{A,B}.json` | v1 | 2026-09 | SUPERSEDED: not an attack-blocking rate (2026-10-10 audit) |
| v1 defended-agent recovery | 21 / 38 (55.3%) | `agent/defended_recovery_results.json` | v1 | 2026-08-22 | Historical; confounded by severity leakage |
| ApprovalClaimDetector | 9 / 10 detected, 1 / 100 benign false positives | `agent/benign_log_corpus*.json` | in-sample, LLM-generated benign corpora | 2026-09-15 | Historical; in-sample |

## Decisions

| # / date | Decision | Alternatives considered | Why | Source |
|:--|:--|:--|:--|:--|
| 2026-10-10 | Lift the lock on six `perception/` files (`sse.py`, `nce_engine.py`, `rsem.py`, `knowledge_graph.py`, `nce_contract.py`, `nce_sse_integration.py`); `normalizer.py` stays locked | Plan B: wrapper modules in `experiments/` | Fixes needed real changes; every step was checked by a full offline re-score | H:722-726 |
| 2026-10-10 | T1071: label grounded / ungrounded instead of dropping; synthetic network model; BLOCK_DESTINATION / BLOCK_EGRESS | Keep the drop filter | Dropping hid hypotheses silently; C2 needs real containment | H:720 |
| 2026-10-11 Phase 4.0 | Expected-activity rule: a path made only of normal access is logged, not acted on | T1078 needs a baseline deviation; everything to review | The first makes SSE report false INFEASIBLE; the second sends about 97% of clean alerts to review | H:927 |
| 2026-10-11 D1-D7 | Simulated oracle analyst as a separate condition; single writer; case window 1 h / 24 h; gate delay 24 h; store in `<data>/ks`; full technique vocabulary with an "unconstrained → review" path; unreasoned novel cases → review | Indicators from config only; dismiss unreasoned cases | Gated = frozen without feedback; a dismissed novel pattern would vanish unseen | `experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md` §8 |
| 2026-10-11 | No automatic containment on telemetry alone for DEDALE (`auto_contain_unreasoned_c2=False`) | Auto-block unknown destinations | 34 of 35 auto-blocks were benign (31 STUN servers) | `experiments/DEDALE_PHASE1_RESULTS.md` |
| 2026-10-11 (a) | Open-world SSE: no telemetry means "not known", not "impossible" | Closed world | Closed world dismissed 2 real attack cases | H:1540 |
| 2026-10-11 B1-B4 | FastAPI; verdicts malicious / benign / benign_once / needs_info with a learning preview; no automatic closing of similar cases; four-eyes for host cut-offs at tier ≥ 2 | Starlette only; auto-close similar | A pattern key leaves out the command line, so one `benign` can silence a later attack | `experiments/ANALYST_REVIEW_LOOP_DESIGN.md` |
| 2026-10-11 B5 (a) | Unlearn a host's last 7 days of learning on confirmed compromise | Leave learned patterns | A 20% miss rate taught 20 attack patterns; with B5, 0 (+10% reviews) | H:1747-1754 |
| P1-P4 (2026-10-12) | One combined paper; venue after the draft; ≤ 3 datasets; real frontend demo | Two papers; more datasets (OpTC, AIT-ADS, LANL) | Scope drift; a fixed end goal | `PROJECT_PLAN.md` §2 |
| P5-P7 (2026-10-19) | Backend gaps all done; Claude drafts the paper sections; handover goal (GUIDE + DEDALE finished, E3 to the team) | — | User decisions | `PROJECT_PLAN.md` §2 |
| P8-P9 (2026-10-31) | Work through the external review one branch at a time; then asymmetric trust (A) as the main defence; B, C later; D needs a budget | Keep NCE authority | In every DEDALE host run NCE's only effect was dismissals, the attacker's path | H:2592-2593 |
| 2026-11-01 | Write a fresh paper (`agentsoc_v2.tex`) instead of editing the combined one | Revise `agentsoc_combined.tex` | Positioned against the base paper; every number traced | H:2772-2799 |
| 2026-11-08 | Name the system GuardedSOC | Keep "AgentSOC 2.0" | The base paper is AgentSOC | H:2804 |
| 2026-11-22 | Archive the verbatim log; this file newest first; HANDOVER merged and removed | Keep appending to the 2,900-line log | One readable entry point; the history stays recoverable at its file path | `docs/_audit_report.md` §5 |

## Lessons, facts and gotchas that are not in the code

- **Agent reliability:** earlier coding agents (2026-08/09, before Claude Code) produced fabricated diffs, compile results and statistics. Demand raw output, recompute percentages, and write "NOT FOUND IN REPO" instead of guessing (the deleted note `agentsoc_context_v2.md` §12; its content is summarised here). A passing suite missed real bugs twice: identical action effects (H:401) and right-score-wrong-path (H:449).
- **API quotas** (free tiers, as recorded):
  - gemini-3.1-flash-lite: 500 requests/day per key, about 15 requests/minute (≥ 5 s between calls per key);
  - gemini-3.6-flash: 20/day (tried in the v1 era; used for no current result);
  - Groq gpt-oss-20b: 200,000 tokens/day per key (about 70 NCE calls).
  - Runners stop at the daily cap with exit 3 and resume (H:1053; `S:532-535`).
- **DEDALE downloads** go through the Dataverse API, `https://entrepot.recherche.data.gouv.fr/api/access/datafile/<id>`, with a browser User-Agent; the HTML pages block bots. File ids: labels 717882, Suricata 717879, user behaviour 717880, syslog 717890, winlogbeat 717892, auditbeat 717881; the `zeek_router1.zip` id was not recorded (from the deleted note `CLAUDE_HANDOFF.md`; recorded here). MD5s verified at download (H:1092, 1284, 1386).
- **Seeds used:** 42-53 (v1 subsets), 20260915 (benign corpus), 71 (network model), 73 (enterprise inventory), 79 (corpus v2 families). Check for reuse and alert-id collisions before generating a batch (deleted note `agentsoc_context_v2.md` §5; H:752, 851, 869).
- **Local tags** `pre-phase2-checkpoint`, `post-phase2`, `post-phase3` exist only locally (`git tag -l`).
- **Project facts from the old handoff** (UNVERIFIED, from the deleted note `agentsoc_context_v2.md` §1):
  - group number G-524 (an early review deck said G-1415);
  - a review deck `AgentSOC_Project_Review.pptx` exists outside the repository;
  - a collaborator kept a separate baseline reproduction repository (`agentsoc-baseline`).
- **Windows:** in Git Bash set `MSYS_NO_PATHCONV=1` for tools that take `/` arguments (H:2006). Stale `__pycache__` from `C:\agentsoc` showed old paths in tracebacks (H:1167).

## How to maintain this file

- Add a dated entry at the top of "Entries" for every session that changes code, data, results or plans: what was tried, what happened (numbers with their source file), what was decided and why.
- Add failed approaches to "Dead ends", new numbers to "Results" (with source, config, date and status), and choices to "Decisions".
- Never edit an old number: add a dated `[Correction YYYY-MM-DD]` note next to it.
- Re-verify a claim before writing it; do not copy it forward from another document. Mark anything not checked as UNVERIFIED.
- Keep `PROJECT_STATUS.md` in sync, and `experiments/PAPER_CLAIMS_TO_REVISE.md` when a paper claim moves.
