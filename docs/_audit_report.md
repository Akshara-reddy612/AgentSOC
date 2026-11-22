# Repository audit report (2026-11-22)

Full audit of the repository's documentation against the code, the result files and real runs. Done on branch `chore/repo-audit-tracking`, cut from `main` at `da17235` (2026-11-09). No source code, test, config or data file was changed; only documentation and tracking files.

**Status labels:** VERIFIED (checked against code, a file or a run today) · WRONG (contradicted by code / files) · OUTDATED (was true, no longer) · UNVERIFIED (no output, log or run in the repo or on this machine backs it) · MISSING (true, but documented nowhere).

## 1. How the audit was done

| Step | What was done | Evidence |
|:--|:--|:--|
| Inventory | `git ls-files` (477 tracked files before this branch). Every `.py` file parsed with an AST script (docstring, top-level definitions, imports, CLI flags, env vars, reverse dependencies) | Script and output kept outside the repo (scratchpad); summary in §6 |
| Reading | Read in full: README, PROJECT_STATUS, PROJECT_PLAN, HANDOVER, REPRODUCE, DEMO_BACKEND_DESIGN, PAPER_OUTLINE, RESEARCH_LOG (all 2,902 lines), docs/ADDING_A_DATASET, docs/LIMITATIONS_DRAFT, docs/VIVA_QA, experiments/RESULTS, experiments/PAPER_CLAIMS_TO_REVISE, the design notes (LEARNING_KNOWLEDGE_STORE_DESIGN, ANALYST_REVIEW_LOOP_DESIGN, E1_CONTAMINATION_DEDALE_DESIGN, PHASE2_HOST_LOGS_DESIGN, REAL_TELEMETRY_PLAN, DEDALE_DATA_NOTES), frontend/README, archive/README, archive/streamlit/README. Read in part (opening sections): DEDALE_PHASE1/2/3_RESULTS, REVIEW_LOOP_RESULTS, archive/PROJECT_STATUS_HISTORY (headings, environment and known-limitations sections); not read: archive/notes/*, the paper `.tex` sources (only titles, TODOs and numeric tokens were checked) and paper/agentsoc_v2_numbers.md beyond its token counts. Also read: the two git-ignored handoff files (`CLAUDE_HANDOFF.md`, `agentsoc_context_v2.md`), the text of both `.docx` files, and these modules: `soc_server/__main__.py`, `soc_server/datasets.py`, `dedale/__init__.py`, `perception/soc_loop.py`, `perception/triage_gate.py`, `perception/defended_pipeline.py`, `experiments/freeze_dedale.py`, `experiments/rescore_v2.py`, `review_api/__main__.py`. Every other source file was covered by the AST inventory, its module docstring and targeted greps (constants, routes, env vars, writes); not every line of the ~60,000 lines of Python/TypeScript was read | — |
| Git history | All 289 commits on `main` (2026-07-24 .. 2026-11-09); every local branch checked with `git branch --no-merged main` (none unmerged) | `git log --reverse` |
| Runs | Tests, environment check, frontend typecheck, offline reproduction in an isolated worktree, the demo server in a throwaway home, the end-to-end browser check | §2 |

## 2. Commands run and what happened (2026-11-22)

| Command | Result |
|:--|:--|
| `HF_HUB_OFFLINE=1 .venv/Scripts/python.exe -m pytest tests experiments -q -p no:cacheprovider` | **804 passed, 1 deselected in 105.84 s**, exit 0; `git status` unchanged afterwards |
| Same with `AGENTSOC_DATA_DIR=<empty folder>` | **803 passed, 1 skipped, 1 deselected** in 268 s; skipped `tests/test_dedale.py:116` ("DEDALE data not present"); nothing written to the folder |
| `.venv/Scripts/python.exe -m pip freeze` vs `requirements-lock.txt` | Identical (empty diff). Python 3.13.2 |
| `node --version`, `npm --version` | v22.18.0, 10.9.3 |
| `cd frontend && npm run typecheck` (`tsc --noEmit`, TypeScript 7.0.2) | exit 0. `frontend/dist/index.html` dated 2026-10-20 13:02; last `frontend/src` commit `64051be` 13:03:39 the same day (not rebuilt in this audit) |
| REPRODUCE step 3, in a detached worktree of this branch: `python -m experiments.rescore_v2 ...` ×3 (`--llm-authority full`) and ×3 (`escalate`) | All exit 0. The three full-rule outputs have the **same SHA-256** as the committed `agent/v2_results/*_rescored.json` |
| `experiments.attack_metrics`, `undefended_metrics`, `tamper_structured`, `era_offline --report` | All exit 0; undefended 130/439 (29.6%), defended 4/428 (0.9%); ERA flags 0/500 clean in both sets |
| REPRODUCE steps 4-6 in the worktree with an isolated data root (a junction to `D:\agentsoc_data\dedale`, empty `runs/` and `ks/`): `experiments.freeze_dedale --workers 6`, `build_results`, `build_figures` | all 43 replays exit 0 (06:37-07:13 UTC, about 36 min with 6 workers; 0 events refused); `final_host_scores.json`, `final_network_scores.json`, `e1_scores.json` and both `paper/fig_*.dat` byte-identical to the committed files (after normalising line endings: the Windows checkout writes CRLF, git stores LF); the rebuilt `RESULTS.md` differs only in its date line |
| `python -m soc_server --home <throwaway> --port 8799` (isolated data root, `AGENTSOC_CHECKPOINT_KEY` in the scratchpad) | First start: "7,505,328 events processed; checkpoint written"; frontend at `/`, API under `/api`, `/api/docs` 200; `/api/auth/setup` reported `needed: true` and created a throwaway admin; started the replay, paused at 2025-01-06T12:13 (25 s wall), 0 events rejected / failed, 50 cases queued (top: two STUN cases on the VPN server at priority 78, then `case-7561` "powershell.exe starting scvhost.exe on CLIENT2" at 77, the known queue weakness). Server stopped afterwards |
| `python tools/e2e_check.py --url http://127.0.0.1:8799 --user <throwaway admin> --password-file <file>` | **9 / 9 checks passed**, exit 0 (overview, case, host timeline, knowledge store, metrics, contamination lab, lab pair, my account, accounts) |

Not run, on purpose: anything that calls an LLM API (needs a budget approval), `pip install` / `npm install` (installs need approval), `python -m experiments.dedale_extract_winlogbeat` (rewrites `<data>/dedale/derived/`), the real demo homes under `D:\agentsoc_data\`.

## 3. Claims checked

### README.md

| Claim | Source | Status | Evidence | Fix applied |
|:--|:--|:--|:--|:--|
| Needs Python 3.13 and Node 22 | README:50 | VERIFIED | Python 3.13.2, Node v22.18.0 | — |
| Tests: `pytest -q` passes offline | README:57 | VERIFIED | 804 passed, 1 deselected | — |
| Embedding model is 88 MB | README:60 | VERIFIED | `~/.cache/huggingface/hub/models--sentence-transformers--all-MiniLM-L6-v2` = 88M | — |
| Data defaults to `../agentsoc_data`, override `AGENTSOC_DATA_DIR` | README:62 | VERIFIED | `dedale/__init__.py:20-23` | — |
| With an empty data folder the tests pass and one test skips | README:64 | VERIFIED | run above | — |
| Recorded NCE answers ship in `experiments/dedale_results/nce_cache/` and are copied into the data folder | README:65 | VERIFIED | 4 files there; `experiments/dedale_nce.py:94-95` copies when missing | — |
| Server options table (12 options and defaults) | README:91-103 | VERIFIED | `soc_server/__main__.py:75-94` | — |
| `--home` default `<data>/live` | README:94 | VERIFIED | `soc_server/__main__.py:97-98` | — |
| Login throttling 5 per user+address, 20 per address, 15 min | README:149 | VERIFIED | `review_api/accounts.py:233-234` | — |
| scrypt passwords, hashed session tokens | README:147 | VERIFIED | `review_api/accounts.py:39,63`; `SESSION_TTL` 12 h at :38 | — |
| Checkpoint key `~/.agentsoc/checkpoint.key` or `AGENTSOC_CHECKPOINT_KEY` | README:153 | VERIFIED | `soc_server/runner.py:144` | — |
| Audit logs append-only through SQLite triggers | README:154 | VERIFIED | `CREATE TRIGGER` in `perception/case_store.py` (8) and `perception/knowledge_db.py` (2) | — |
| 43 DEDALE replays, about 2 h with 6 workers | README:161 | VERIFIED (count); time VERIFIED: about 36 min on this machine (06:37-07:13 UTC), faster than stated | `experiments/freeze_dedale.py:88-91` gives 43 jobs | — |
| `TriageGate(llm_authority=...)`, default `"full"`; test file `tests/test_asymmetric_trust.py` | README:177 | VERIFIED | `perception/triage_gate.py:102`; file exists | — |
| Headline results C1-C5 | README:30-39 | VERIFIED | each number found in `experiments/RESULTS.md` (C1:11,35; C2:67-70; C3:92-93; C4:103-105; C5:122,124) | — |
| `monitoring/` = earlier monitoring layer, tested, Streamlit tab archived | README:201 | VERIFIED | only `tests/test_monitoring.py` and `archive/streamlit/dashboard.py` import it | — |
| "HANDOVER.md — start here" | README:209 | OUTDATED | HANDOVER.md removed in this audit (§5) | Row now points at `PROJECT_STATUS.md` |
| "PROJECT_PLAN.md — claims C1-C5" | README:210 | OUTDATED | Plan has C6 since 2026-10-31 (`PROJECT_PLAN.md:45`) | Changed to C1-C6 |

### PROJECT_STATUS.md (before this audit)

| Claim | Source | Status | Evidence | Fix applied |
|:--|:--|:--|:--|:--|
| "Where things stand (2026-10-27)" | :5 | OUTDATED | content runs to 2026-11-08; last commit on `main` is 2026-11-09 | File rewritten |
| `paper-v2-accuracy` "not merged" | :13 | WRONG | merged in `6e70cf2` (2026-11-08); `git branch --no-merged main` is empty | Rewritten |
| Fig. 1 redraw of 2026-11-09 | — | MISSING | commits `3832baa`..`da17235` | Added (status and log) |
| 804 tests pass | :66 | VERIFIED | run today | — |
| Full re-freeze 2026-10-31 reproduced all three score files byte-identically | :67 | VERIFIED by a new re-freeze (the 2026-10-31 outputs themselves are absent on this machine) | `D:\agentsoc_data\runs` holds replay outputs dated 2026-10-18/19 only, and none of the 8 `A_*` replays of `freeze_dedale.jobs()` | Stated in the new status |
| Soak test 15,013,901 events, 388 MB, ≤0.12 s, restart ~10 s | :68-72 | UNVERIFIED (not re-run) | only `RESEARCH_LOG` 2026-10-20 | Labelled in the new status |
| `dedale_for_team.zip` is 321 MB | :62 | VERIFIED | `D:\dedale_for_team.zip` 336,956,066 bytes (321 MiB), 2026-10-20 | — |
| "Followed logs must come from DEDALE's hosts ... until the `--dataset` switch exists" | :93 | OUTDATED | `--dataset` exists since 2026-10-20 (`soc_server/datasets.py`); still only DEDALE registered | Reworded |

### PROJECT_PLAN.md

| Claim | Source | Status | Evidence | Fix applied |
|:--|:--|:--|:--|:--|
| P8/P9: review change 9 (hash-chained audit logs) "stays on its branch" | :34 | WRONG | no unmerged branch exists; no hash-chain code anywhere (`git grep -il "prev_hash\|hash.chain"` on `*.py`: nothing) | Dated audit note under the decisions table |
| M3 row does not mention `paper/agentsoc_v2.tex` (GuardedSOC) or the team's `.docx` | :107 | OUTDATED | `paper/agentsoc_v2.tex` since 2026-11-01; `AgentSOC_IEEE_Revised.docx` added 2026-11-22 | Dated audit note |
| One LLM on DEDALE: gemini-3.1-flash-lite | :51 | VERIFIED | `experiments/dedale_nce.py:34` | — |

### HANDOVER.md (removed)

| Claim | Source | Status | Evidence | Fix applied |
|:--|:--|:--|:--|:--|
| "780 pass" | :14 | OUTDATED | 804 today | File removed; content merged into `PROJECT_STATUS.md` |
| Paper "5 pages" | :11 | OUTDATED | 7 pages since 2026-10-31 (`RESEARCH_LOG`); `agentsoc_v2.tex` 7 pages since 2026-11-08 | as above |
| "decisions P1–P7", "claims C1–C5" | :152 | OUTDATED | P8, P9 and C6 exist (`PROJECT_PLAN.md`) | as above |

### REPRODUCE.md

| Claim | Source | Status | Evidence | Fix applied |
|:--|:--|:--|:--|:--|
| Step 3 re-scores reproduce the recorded results | :29-33 | VERIFIED | identical SHA-256 (§2) | — |
| Step 5 builds `RESULTS.md` | :43 | VERIFIED (logic) | `experiments/build_results.py:105-106` silently **leaves out** the asymmetric-trust C1 rows if `logs/*_rescored_escalate.json` are missing; this checkout's `logs/` has none | Gotcha added to REPRODUCE step 5 and to the status |
| Steps 4-6 reproduce the frozen files | :41-44 | VERIFIED | §2 | — |

### Design and results notes

| Claim | Source | Status | Evidence | Fix applied |
|:--|:--|:--|:--|:--|
| "Nothing below is implemented yet" | `experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md:3` | OUTDATED | S1-S9 done 2026-10-11 (its own §7) | Dated note under the status line |
| "P2-1 running; the rest is a proposal" | `experiments/PHASE2_HOST_LOGS_DESIGN.md:3` | OUTDATED | Phase 2 done 2026-10-11 (`DEDALE_PHASE2_RESULTS.md`) | Dated note |
| HTTP API in `api/` | `experiments/ANALYST_REVIEW_LOOP_DESIGN.md:71` | OUTDATED | it is `review_api/` | Dated note |
| "Still open": withdrawing a verdict, restart recovery, accounts | same file, Progress | OUTDATED | withdrawal `e0b60c9` (2026-10-19), restart recovery M4.2 `a0ec071`, accounts M4.1 `b9b6696` | Dated note |
| Hardened-prompt counts are "on the unmerged branch `baseline-prompt`" with `experiments/BASELINE_PROMPT_DESIGN.md` | `docs/LIMITATIONS_DRAFT.md:113` | UNVERIFIED | no such branch or file in this repository (any ref) | Dated note in the sources table |
| Paper outline describes `paper/agentsoc_combined.tex` only | `PAPER_OUTLINE.md` | OUTDATED (file later removed, §5) | `paper/agentsoc_v2.tex` is the newer paper | Dated note |
| Soc-server docstring "NCE uses the recorded hypotheses (cache only, no API calls)" | `soc_server/__main__.py:13` | OUTDATED (source, not changed) | only the default; `--nce live` makes calls (`:81-83`) | Recorded here; source code not edited |

### RESEARCH_LOG.md (before this audit)

| Claim | Source | Status | Evidence | Fix applied |
|:--|:--|:--|:--|:--|
| Five headings "(branch ..., not merged)" for 2026-11-01..08 | :2759, 2772, 2801, 2831, 2852, 2872 | OUTDATED | merged: `95f3d3c`, `d97e46f`, `5476d51`, `8fb0c0c`, `6e70cf2` | Verbatim log archived; new log states the merges |
| Entries in chronological order | whole file | WRONG (order) | top runs 09-13, 09-13, 09-12/13, 09-12, 09-06, 09-05, 08-19, 08-20 ... | New log is newest first |
| 65 file references to moved paths (`scratch/`, `experiments/test_*.py`, `monitoring/dashboard.py`, ...) | various | OUTDATED | moved to `archive/` on 2026-10-20 (`de33bd0`) | Kept verbatim in the archived log; new log uses current paths |

### The team's revised paper `AgentSOC_IEEE_Revised.docx` (added to the working tree 2026-11-22; untracked on purpose (user, 2026-11-22: the paper is still being written; the template is only a template))

| Claim | Source | Status | Evidence | Fix applied |
|:--|:--|:--|:--|:--|
| Six planned experiments "with execution harnesses implemented in the repository" (ablation matrix, hardened prompts incl. spotlighting / instruction hierarchy / StruQ, mimicry, escalation flooding, low-and-slow poisoning, multi-model variance) | docx §IV-D | WRONG | no such code on any commit: `git log --all -S spotlighting` finds only paper/doc commits; `git grep` on `*.py` finds only the `native_format_mimicry` payload family | Entry in `experiments/PAPER_CLAIMS_TO_REVISE.md` |
| Network, 5% false alarms with unlearning: "8 instances of benign destination IP unlearning, ... 26.1 to 32.4 reviews/day" | docx §VI-A | WRONG | 32.4 is in no result file; frozen value 21.2 (`final_network_scores.json`, `RESULTS.md:136`); the 8 are "approved blocks would have hit benign traffic" (`RESULTS.md:138`) | as above |
| "44.6 reviews/day (B5 on; 624 test cases)" | docx §V-C | WRONG | 625 (`final_host_scores.json` `gated_analyst_F_fa5.test_cases`; `RESULTS.md:95`) | as above |
| 35.1 reviews/day, 491 cases (24 h delay, B5 off) | docx §V-C | VERIFIED (not in RESULTS.md) | `RESEARCH_LOG` 2026-10-11 analyst-delay entry / `experiments/dedale_results/review_eval_host.json` (pre-freeze code) | Noted in claims file |
| 67 ALERT_PATTERN + 549 COMMUNICATES_WITH learned with D7 off | docx §V-B | VERIFIED (not in RESULTS.md) | `D:\agentsoc_data\runs\dedale_gated_noact_F_noact\summary.json` | — |
| 84.6%, 67.8%, 98.9%, 15.4%, 83.9%; CIs [0.0, 2.1], [0.0, 2.2], [0.0, 5.1] | docx | VERIFIED (derived) | 400/473, 400/590, 1−65.2/6095.4, 73/473, 718/856; Wilson upper bounds for 0/178, 0/168, 0/72 | — |
| "every studied LLM-agent approach missed at least 40.4% of attack-related alerts" | docx §II | UNVERIFIED | external citation; nothing in the repo | — |

## 4. In the code, documented nowhere (before this audit)

| What | Where | Now documented in |
|:--|:--|:--|
| `AGENTSOC_NEW_PASSWORD` (non-interactive password for the accounts CLI) | `review_api/accounts.py:213` | `PROJECT_STATUS.md` (env vars) |
| Standalone review API with token auth (`python -m review_api --case-store ...`, `AGENTSOC_ANALYST_TOKENS`) | `review_api/__main__.py` | `PROJECT_STATUS.md` |
| `POLICY_VERSION` must be bumped when triage / guardrail rules change | `perception/triage_gate.py:57-59` | `PROJECT_STATUS.md` (conventions) |
| `build_results` silently drops the asymmetric-trust C1 rows without the escalate re-scores | `experiments/build_results.py:105-106` | `REPRODUCE.md`, `PROJECT_STATUS.md` |
| `monitoring/sources/api_source.py`: a localhost HTTP ingestion server on 127.0.0.1:8765 | that file | `PROJECT_STATUS.md` repo map (legacy) |
| v1 GUIDE corpus generators cannot run as written (`/home/claude/...` paths) | `GUIDE_Dataset/processed/synth_fields.py:195`, `inject_payloads.py:291` | `PROJECT_STATUS.md` (known issues) |
| `agent/measure_clean_confidence.py` makes live calls and overwrites its result file (`SMOKE_TEST_ONLY = False`, no `confirm_overwrite`) | that file:60 | `PROJECT_STATUS.md` (known issues) |
| One-off live scripts `agent/list_groq_models.py`, `agent/test_gemini_connection.py`, `agent/test_groq_connection.py` | `agent/` | `PROJECT_STATUS.md` repo map |
| Watchdog env vars `WATCHDOG_*`, `POLL_INTERVAL_S`, `STALL_TIMEOUT_S` | `experiments/run_with_watchdog_B_parallel.py:25-37` | `PROJECT_STATUS.md` (env vars) |

## 5. Handoff, status and notes files: classification and removals

| File | Tracked | Class | Decision |
|:--|:--|:--|:--|
| `PROJECT_STATUS.md` | yes | (a) current, but stale | Rewritten in place |
| `RESEARCH_LOG.md` | yes | (d) unique history | Verbatim copy moved with `git mv` to `archive/RESEARCH_LOG_HISTORY.md` (same precedent as `archive/PROJECT_STATUS_HISTORY.md`, 2026-10-20); a new structured, newest-first `RESEARCH_LOG.md` written |
| `HANDOVER.md` | yes | (b) superseded + (c) stale | Unique content (data package contents, first-hour setup, invariants I1-I6, working rules) merged into `PROJECT_STATUS.md`; **removed with `git rm`** in commit `4b327ec`. Restore: `git show 4b327ec^:HANDOVER.md` |
| `PROJECT_PLAN.md`, `REPRODUCE.md`, `DEMO_BACKEND_DESIGN.md` | yes | (a) | Kept; dated audit notes where stale |
| `PAPER_OUTLINE.md` (2026-10-18) | yes | (b) superseded | Section and writer plan of `paper/agentsoc_combined.tex`, superseded by `paper/agentsoc_v2.tex` and by the `.docx` the user is now working on (user, 2026-11-22). Nothing in it is needed for the current draft; the per-section claim mapping it held is in `PROJECT_PLAN.md` §3. **Removed with `git rm`** in commit ddd0fb2. Restore: `git show ddd0fb2^:PAPER_OUTLINE.md` |
| `docs/LIMITATIONS_DRAFT.md`, `docs/VIVA_QA.md`, `docs/ADDING_A_DATASET.md` | yes | (a) | Kept; one dated note in the limitations draft |
| `experiments/*_DESIGN.md`, `experiments/DEDALE_*.md`, `REVIEW_LOOP_RESULTS.md`, `RESULTS.md`, `PAPER_CLAIMS_TO_REVISE.md` | yes | (a) | Kept; dated notes; new docx section in the claims file |
| `archive/PROJECT_STATUS_HISTORY.md`, `archive/notes/*` | yes | (d) | Kept unchanged |
| `CLAUDE_HANDOFF.md` (2026-10-11, 11,386 bytes) | no (git-ignored) | (b) superseded | First kept (untracked, so not recoverable from git). **Deleted 2026-11-22 at the user's request** ("remove the useless ones ... the rest of the files you decide"). It held the 2026-10-11 move instructions, a copy of the memory rules, results as of 2026-10-11, the pending quota-bound runs (all finished since) and the DEDALE download plan. Its durable facts are in `RESEARCH_LOG.md` ("Lessons, facts and gotchas"): Dataverse API and file ids (labels 717882, Suricata 717879, user behaviour 717880, syslog 717890, winlogbeat 717892, auditbeat 717881), about 70 Groq NCE calls per key per day, local-only tags |
| `agentsoc_context_v2.md` (2026-10-10, 39,294 bytes) | no (git-ignored) | (c) stale | **Deleted 2026-11-22**, same request. It was the user's pre-Claude-Code handoff: v1 architecture, v1 numbers (all in `archive/PROJECT_STATUS_HISTORY.md` and `archive/RESEARCH_LOG_HISTORY.md`), the v1 paper's open defects (paper v1 archived) and a 2026-10-10 future-work plan (built as corpus v2 / entity binding / DEDALE since). Its durable facts are in `RESEARCH_LOG.md`: group G-524 (deck said G-1415), review deck `AgentSOC_Project_Review.pptx` outside the repo, a collaborator's `agentsoc-baseline` repository, seeds used, model quotas, the agent-reliability lessons |
| `agentsoc2_paper_corrected.log` (2026-10-10, 40,388 bytes) | no (`*.log` ignored) | useless | pdfTeX build log of the archived v1 paper. **Deleted 2026-11-22** |
| `agenso_.research_base.pdf` | no (git-ignored) | reference | The base AgentSOC paper (Roy and Singh, arXiv:2604.20134). Kept: cited by the paper and the log |
| `.env`, `.gitignore`, `pyproject.toml`, `requirements.txt`, `requirements-lock.txt` | `.env` no; others yes | tooling | Kept (API keys; git, pytest and install configuration) |
| `AgentSOC_IEEE_Revised.docx`, `Documentation_Template-SDC-II.docx` | no (left untracked at the user's request; never in `main`'s history) | report / template | Kept: the paper draft being worked on and the template needed for the SDC-II course report (user, 2026-11-22) |

## 6. Still UNVERIFIED and needs a person

1. Where the 2026-10-31 re-freeze ran (its `A_*` replay outputs are not in `D:\agentsoc_data\runs`). Low stakes: the 2026-11-22 re-freeze reproduced its score files byte-identically.
2. The soak-test numbers of 2026-10-20 (not re-run).
3. The hardened-prompt pilot counts (6 calls, 24 requests, 0 answers): the branch `baseline-prompt` that held them is not in this repository.
4. Settled by the user on 2026-11-22: the draft being worked on is `AgentSOC_IEEE_Revised.docx`. Its three wrong claims (§3) still need fixing, and its new numbers are not covered by `paper/agentsoc_v2_numbers.md`.
5. The docx's external citation "missed at least 40.4% of attack-related alerts".
