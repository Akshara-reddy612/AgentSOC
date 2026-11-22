# Project status

**Read this first.** The current state of the project, rewritten in place. For history and the reasons behind decisions, see [RESEARCH_LOG.md](RESEARCH_LOG.md). Both files were rebuilt by a full audit on 2026-11-22 ([docs/_audit_report.md](docs/_audit_report.md)). Statements carry their evidence (path, commit or command); anything without evidence is marked UNVERIFIED.

## Summary

AgentSOC 2.0 (the system is called **GuardedSOC** in the newest paper) is a KMIT (Hyderabad) student research project: 5 students and a mentor, with engineering led by Abhishek. It is a research prototype of an LLM-driven Security Operations Centre (SOC) that defends its own two attack surfaces:
- the LLM reads log text an attacker can write (indirect prompt injection, "log contamination");
- the memory (a Knowledge Store that learns what is normal) can be taught the attacker ("memory poisoning").

It builds on the AgentSOC paper (Roy and Singh, IEEE ICAIC 2026, arXiv:2604.20134). It is evaluated on a contamination corpus built from Microsoft GUIDE and on DEDALE (Inria, labelled testbed telemetry). It also runs as a live demo tool with a React web console. It exists to produce one research paper and a working tool someone outside the team can run (`PROJECT_PLAN.md` §1).

**Status (verified 2026-11-22, `main` at `da17235` plus this audit's documentation commits on `chore/repo-audit-tracking`):** pipeline, tool and all GUIDE and DEDALE results are finished and frozen; tests pass (804). The paper is drafted in LaTeX (`paper/agentsoc_v2.tex`), and the team has a later Word revision (`AgentSOC_IEEE_Revised.docx`) that still has three wrong claims. What is left is the team's: choose the paper and venue, fix the paper, record the demo video, and the optional third dataset.

## Terms used in this file

| Term | Meaning |
|:--|:--|
| SOC | Security Operations Centre: analysts triaging security alerts |
| NCE | Narrative Counterfactual Engine: the LLM step. It proposes MITRE ATT&CK hypotheses (technique, account, source and target host) from an alert's evidence text (`perception/nce_engine.py`) |
| SSE | Structural Simulation Engine: checks each hypothesis against the environment graph (FEASIBLE / CONDITIONALLY_FEASIBLE / INFEASIBLE) (`perception/sse.py`) |
| Entity binding | Flags hypothesis entities that the alert's trusted fields do not contain ("unbound": possible steering) (`perception/entity_binding.py`) |
| RSEM | Risk Scoring and Evaluation Module: ranks responses by α·containment − β·business impact (`perception/rsem.py`) |
| Guardrails | Hard floors on actions and playbook status (auto-approved / pending analyst review) (`perception/action_playbook.py`) |
| ERA | Evidence Risk Assessment: regex, embedding-similarity, approval-claim and split-field detectors that score text for injection. It only escalates, and runs on GUIDE only (`risk_assessment/`) |
| KS | Knowledge Store: the SQLite-backed graph the loop learns into (`perception/knowledge_db.py`) |
| Learning gate | Learns a test-period case only if it was dismissed, 24 h after closing, and nothing on the same host escalated meanwhile (`perception/knowledge_updater.py`) |
| Triage gate | Per new case: escalations, then the learned pattern, then the decision cache, then the pipeline with NCE behind a daily budget (`perception/triage_gate.py`) |
| Asymmetric trust | Decision P9 A (2026-10-31): the LLM's output may raise scrutiny, never lower it (`--llm-authority escalate`). The older rule, where NCE output can dismiss or justify an action, is `full` ("acting rule") |
| B5 | Unlearn on confirmed compromise: a malicious verdict retracts what was learned on that host in the last 7 days |
| D7 | Policy for unreasoned novel cases: send them to review (default) instead of dismissing |
| E1 | Experiment: attacker text appended to DEDALE's real attack command lines, run through the full loop |
| GUIDE v2 | 500 dev + 500 held-out clean/contaminated alert pairs built from Microsoft GUIDE rows with synthetic entities, evidence and payloads (`GUIDE_Dataset/processed/v2/`) |
| DEDALE | Inria testbed dataset (doi:10.57745/Y5JLDG, CC BY 4.0): 4 weeks of logs, 2 benign training weeks, one APT; exact labels for 2 attacked Windows clients |
| C1-C6 | The paper's claims (`PROJECT_PLAN.md` §3); results in `experiments/RESULTS.md` |
| P1-P9, M1-M8, I1-I6 | Plan decisions, milestones, design invariants (all in `PROJECT_PLAN.md`; invariants below) |

## Results (frozen; source of every paper number: `experiments/RESULTS.md`, frozen 2026-10-31)

| Claim | Result | Source |
|:--|:--|:--|
| C1 attacker text does not steer actions (GUIDE) | Undefended agent hijacked 130/439 (29.6%). Defended pipeline suppressed 4/428 dev (0.9%), 3/437 held-out, 10/437 with gpt-oss-20b. 0 misdirected actions executed | `RESULTS.md:11-16,35-36`; re-scores re-run 2026-11-22, byte-identical |
| C1 through the full loop (E1, DEDALE) | Attack cases dismissed without an analyst 1 / 3 / 1 of 72 (acting rule), 0 under asymmetric trust; 0 attack patterns learned; the same 400 labelled attack events alerted | `RESULTS.md:42-57`; re-freeze IN PROGRESS 2026-11-22 |
| C2 gated learning cuts load | Host reviews per day 6,095.4 (static) → 65.2 (gated); 72/72 attack cases reviewed. Network 552.3 → 26.1 | `RESULTS.md:67-79` |
| C3 poisoning | Ungated: 38 attack patterns learned. Analyst missing 20%: 20 learned, 256/400 events alerted; with B5: 0, 400/400 | `RESULTS.md:70,88-95` |
| C4 the LLM on real telemetry | NCE −16% reviews (65.2 → 54.8), all of it dismissals; closed-world SSE dismissed 2 attack cases, open world 0; under asymmetric trust NCE dismisses nothing (65.2) | `RESULTS.md:103-110` |
| C5 analyst loop | 33.1 / 34.1 / 38.1 / 51.5 reviews per day at 1 / 4 / 24 / 72 h delay; network containment time = delay | `RESULTS.md:118-140` |
| C6 asymmetric trust | E1 dismissals 1/3/1 → 0; GUIDE automatic containments removed by contamination 20/178, 18/168, 21/176 → 0; cost +0.9 reviews/day with an analyst | `RESULTS.md:11-16,50-57,107-108` |

What may and may not be claimed: [experiments/PAPER_CLAIMS_TO_REVISE.md](experiments/PAPER_CLAIMS_TO_REVISE.md).

## Repository map

| Path | Purpose |
|:--|:--|
| `README.md` | What the system is, quick start, demo options, which rule produces which result |
| `PROJECT_STATUS.md` / `RESEARCH_LOG.md` | This file / history, results with sources, dead ends, decisions |
| `PROJECT_PLAN.md` | Scope: goals, decisions P1-P9, claims C1-C6, milestones M1-M8, rules, "Later" list. Scope changes only by a dated decision there |
| `REPRODUCE.md` | Rebuilding every number offline |
| `DEMO_BACKEND_DESIGN.md` | Demo server design (M4) and what was added after |
| `PAPER_OUTLINE.md` | Section plan of `paper/agentsoc_combined.tex` |
| `CLAUDE.md` | Entry point for coding agents |
| `AgentSOC_IEEE_Revised.docx` | Team's Word revision of the GuardedSOC paper, with authors (added 2026-11-22) |
| `Documentation_Template-SDC-II.docx` | KMIT "Skill Development Course-2" report template (blank) |
| `perception/` | The pipeline and the loop. `soc_loop.py` (the loop), `triage_gate.py`, `defended_pipeline.py` (`run_downstream`, `asymmetric_downstream`), `nce_engine.py` + `nce_contract.py` (NCE), `sse.py`, `entity_binding.py`, `rsem.py`, `action_playbook.py` (guardrails), `outcome.py`, `knowledge_db.py` (persistent KS), `knowledge_graph.py` (graph + synthetic seeds), `knowledge_updater.py` (learning gate, unlearning), `case_builder.py`, `case_store.py` (analyst inbox, audit), `review_service.py` (queue, case view), `outcome_monitor.py`, `host_detection.py` (6 Windows detectors), `environment.py` (environment profile), `network_model.py`, `enterprise_model.py`. Earlier layer still in use by ERA / GUIDE: `normalizer.py` (locked), `models.py`, `pipeline.py`, `schema_validation.py`, `contextualizer.py`, `derived_context_rules.py`, `noise_reducer.py` |
| `risk_assessment/` | ERA (detectors, orchestrator, config incl. `MAX_PROMPT_FIELD_LENGTH = 512` at `config.py:115`) |
| `prompt_construction/` | Safe prompt building; NCE prompt (`nce_prompt_builder.py`) |
| `dedale/` | DEDALE readers (`suricata.py`, `winlogbeat.py`), environment model and 37-host inventory (`environment.py`), `data_dir()` |
| `corpus/` | GUIDE v2 builder (`python -m corpus.build_v2`) |
| `GUIDE_Dataset/` | Raw GUIDE samples, v1 corpora and generators (historical), `processed/v2/` (the v2 corpus) |
| `agent/` | GUIDE runners. Current: `run_v2_eval.py` (defended, live / mock), `run_v2_undefended.py`, `key_pool.py`, `llm_utils.py`, `run_guard.py`. Recorded live outputs: `agent/v2_results/`. Everything else is the v1 era (2026-08/09), historical, mostly live-API scripts |
| `experiments/` | DEDALE replays (`dedale_host_replay.py`, `dedale_replay.py`), scorers, `freeze_dedale.py`, `build_results.py`, `build_figures.py`, `rescore_v2.py`, E1 (`dedale_inject.py`, `e1_score.py`), design/results notes (`*_DESIGN.md`, `DEDALE_*.md`), frozen results (`dedale_results/`, `final_results/`), `RESULTS.md`, the claims file. Also v1 Experiment-1 tooling and 5 test files collected by pytest |
| `soc_server/` | Demo server: `__main__.py` (CLI), `runner.py` (live runner, signed checkpoints, quarantine), `app.py` (read APIs), `sources.py`, `follow.py` (live log files), `lab.py` (Contamination Lab), `datasets.py` (dataset registry) |
| `review_api/` | FastAPI review API (`app.py`), accounts (`accounts.py`, also a CLI) |
| `frontend/` | React + TypeScript (Vite) console; `npm run build` writes `frontend/dist/` (git-ignored), which the server serves |
| `tools/` | `e2e_check.py` (read-only end-to-end check of a running console), `ui_check.py` (screenshots), `browser.py` (headless Edge/Chrome driver) |
| `monitoring/` | Legacy real-time monitoring layer (2026-09). Used only by `tests/test_monitoring.py` and the archived Streamlit app, not by the demo |
| `paper/` | `agentsoc_v2.tex` / `.pdf` (GuardedSOC, newest LaTeX), `agentsoc_v2_numbers.md` (source of every number in it), `agentsoc_combined.tex` / `.pdf` (previous combined paper), `fig_*.dat` (from `build_figures`) |
| `tests/` | 62 test files plus `conftest.py` (signs checkpoints with a temporary key) |
| `docs/` | `ADDING_A_DATASET.md` (E3 recipe), `LIMITATIONS_DRAFT.md`, `VIVA_QA.md`, `_audit_report.md` |
| `archive/` | Superseded material, not maintained (`archive/README.md`): Streamlit demo, paper v1, notes, scratch scripts, `PROJECT_STATUS_HISTORY.md` (full status to 2026-10-20), `RESEARCH_LOG_HISTORY.md` (verbatim log 2026-08-19 .. 2026-11-08) |
| `sample_data/` | Small sample alerts used by tests |
| `pyproject.toml` | pytest config: `testpaths = ["tests", "experiments"]`, smoke tests deselected |
| `requirements.txt` / `requirements-lock.txt` | Minimum versions / exact versions of the venv used for all results |

Not in git: `.env` (API keys), `.venv/`, `logs/` (re-scored GUIDE outputs, run stdout; written by `rescore_v2` and others), `frontend/dist/`, `frontend/node_modules/`, and personal root files (`CLAUDE_HANDOFF.md`, `agentsoc_context_v2.md`, `agenso_.research_base.pdf`, `agentsoc2_paper_corrected.log`). Data lives outside the repo in `<data>` = `AGENTSOC_DATA_DIR`, default `<repo>/../agentsoc_data` (`dedale/__init__.py:20-23`); on this machine `D:\agentsoc_data\` (`dedale/` raw and derived data, `runs/` replay outputs, `ks/` replay stores, `live*`/`demo`/`soak` server homes).

## Architecture

```mermaid
flowchart LR
  subgraph Sources
    H[DEDALE winlogbeat host events] --> HD[host detectors: unlearned key = alert]
    N[Suricata alerts] --> NA[network alert + entities from KS]
    F[--follow live log files] --> HD & NA
  end
  HD & NA --> CB[case builder: idle 1 h / max 24 h]
  CB -->|new case| TG[triage gate]
  TG -->|escalation / watch| P
  TG -->|learned pattern| LP[LOW_PRIORITY]
  TG -->|cache hit| C[same decision]
  TG -->|otherwise| P[pipeline]
  subgraph P[defended pipeline]
    NCE[NCE: LLM hypotheses from untrusted text] --> EB[grounding + entity binding] --> SSE --> RSEM --> GR[guardrails] --> OUT[outcome]
  end
  OUT -->|asymmetric trust: text-free decision or REVIEW| D{decision}
  D -->|REVIEW| CS[case store inbox] --> UI[web console / review API]
  UI -->|verdicts, approvals as commands| L[SocLoop applies commands]
  D -->|closed / dismissed| KU[learning gate] --> KS[(Knowledge Store)]
  L --> KS
  L -->|malicious: B5 retract 7 days| KS
  D -->|auto-approved, simulated| OM[outcome monitor: 7-day watches] --> TG
```

- **Trust split:** the store learns structured fields only (I1). Free text (command lines, script text, raw lines) reaches only NCE, ERA (GUIDE) and the analyst, inside `<untrusted_evidence>`, escaped, 512 characters per field.
- **GUIDE path:** each alert runs alone through `perception/defended_pipeline.run_downstream`, from recorded NCE answers (`experiments/rescore_v2.py`), with ERA and a synthetic inventory graph; no loop.
- **DEDALE path:** the full `SocLoop` (`experiments/dedale_host_replay.py`, `dedale_replay.py`), with the store learned from the benign weeks; no ERA.
- **Server:** one process (`python -m soc_server`) holds a runner thread and the FastAPI app. It checkpoints the stores and the pickled loop, signed with HMAC, and restores after a restart.

**Invariants every change must keep** (`experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md` §2): I1 the store learns structured fields only, never text. I2 no look-ahead. I3 after training, learning only through the gate. I4 labels never enter the pipeline (only scorers and the attack simulation read them). I5 actions are simulated. I6 single writer with an append-only audit log; analysts never write the store, their decisions become commands the loop applies.

## Tech stack (exact; `requirements-lock.txt` = installed venv, checked 2026-11-22)

- **Python 3.13.2** (venv at `.venv`). Key packages: fastapi 0.143.0, uvicorn 0.52.4, starlette 1.6.0, pydantic 2.13.4, networkx 3.6.1, sentence-transformers 5.6.1 (model `all-MiniLM-L6-v2`, 88 MB), torch 2.13.0 (CPU), transformers 5.14.1, google-genai 2.18.1, openai 3.3.1 (Groq client), confusables 1.2.0, pandas 3.0.5, numpy 2.5.1, scipy 1.18.0, statsmodels 0.15.0, pytest 9.1.1, streamlit 1.63.0 (archive only).
- **Frontend:** Node v22.18.0, npm 10.9.3, TypeScript 7.0.2, Vite 8.3.4, React 19.3.1, Mantine 9.7.3, ECharts 6.1.0, Cytoscape 3.34.4, TanStack Query 5.104.4, React Router 7.18.4 (`frontend/package.json`).
- **LLMs (recorded):** `gemini-3.1-flash-lite` (all DEDALE NCE, GUIDE dev and held-out, undefended agent), `groq:openai/gpt-oss-20b` (GUIDE dev only). Answers are in `agent/v2_results/` and `experiments/dedale_results/nce_cache/`.
- **Paper:** LaTeX (IEEEtran), built with MiKTeX `pdflatex`.

## Set up, run, test (each command run 2026-11-22 unless marked)

```
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-lock.txt          # NOT run (installs need approval); venv already matches the lock
.venv\Scripts\python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"   # once, downloads 88 MB; NOT run (model is cached)
set HF_HUB_OFFLINE=1                                                    # bash: export HF_HUB_OFFLINE=1
.venv\Scripts\python -m pytest tests experiments -q                    # RUN: 804 passed, 1 deselected, 106 s
```

- **Tests without data:** `AGENTSOC_DATA_DIR=<empty folder>`: RUN: 803 passed, 1 skipped (`tests/test_dedale.py:116`, "DEDALE data not present"), 1 deselected; nothing written to the folder.
- **Frontend:** `cd frontend && npm install && npm run build`. Not run here (installs need approval); `npm run typecheck` RUN: exit 0. Dev mode: `npm run dev` (port 5173, proxies `/api` to `AGENTSOC_API` or 127.0.0.1:8000).
- **Demo server:** `python -m soc_server` (default home `<data>/live`, port 8000; all options in `README.md`). RUN in a throwaway home on port 8799: first start learned 7,505,328 events and checkpointed, served the built frontend at `/` and the API under `/api` (`/api/docs` 200), first-run admin setup worked; replay to 12:13 stream time took 25 s, 0 events rejected or failed.
- **End-to-end check:** `python tools/e2e_check.py --url http://127.0.0.1:8000 --user <you> --password-file <file>`. RUN against that server: **9 / 9 checks passed**.
- **Accounts CLI:** `python -m review_api.accounts --db <home>/auth.sqlite create-user <name> --role admin` (password from the terminal or `AGENTSOC_NEW_PASSWORD`). Or create the first admin in the browser.
- **Standalone review API (no replay):** `python -m review_api --case-store <cases.sqlite>` with `AGENTSOC_ANALYST_TOKENS="alice:<token>,bob:<token>"` (24+ characters each).
- **Reproduce every number (no API calls):** `REPRODUCE.md`. Steps 3 (GUIDE re-scores) RUN: byte-identical. Steps 4-6 (`freeze_dedale --workers 6`, `build_results`, `build_figures`) RUN in an isolated data root: IN PROGRESS at the time of this commit (started 06:37 UTC 2026-11-22; result recorded in a later commit).
- **DEDALE data:** `<data>/dedale/` needs `system_logs_winlogbeat.zip` (27.1 GB), `suricata_alerts.zip`, `system_logs_labels.zip`; network scoring also needs `zeek_router1.zip` (4.4 GB). Shortcut: `D:\dedale_for_team.zip` (336,956,066 bytes, 2026-10-20) holds `derived/` (1,344 hourly host-event files and `zeek_router1_attack_flows.jsonl`), `suricata_alerts.zip` and `system_logs_labels.zip`. Unzipped into `<data>/dedale/`, it replaces the two big archives and the hour-long extraction (`python -m experiments.dedale_extract_winlogbeat`). This machine has all of it.

**Environment variables:** `AGENTSOC_DATA_DIR` (data root), `HF_HUB_OFFLINE=1` (tests, replays), `AGENTSOC_CHECKPOINT_KEY` (checkpoint HMAC key file; default `~/.agentsoc/checkpoint.key`), `GEMINI_API_KEYS` / `GEMINI_API_KEY`, `GROQ_API_KEYS` / `GROQ_API_KEY` (comma-separated, in `.env`, loaded by `agent/key_pool.py`; never print more than the last 4 characters), `AGENTSOC_ANALYST_TOKENS`, `AGENTSOC_NEW_PASSWORD`, `AGENTSOC_AUDIT_LOG` (playbook audit log; default `logs/action_playbook_audit_log.jsonl`), `AGENTSOC_ALLOW_OVERWRITE=1` (lets a v1 runner overwrite its committed results), `AGENTSOC_API` (Vite dev proxy), `BROWSER` (tools), `PYTHONHASHSEED` (`freeze_dedale` sets 0), `WATCHDOG_*`, `POLL_INTERVAL_S`, `STALL_TIMEOUT_S` (v1 watchdog).

## Feature checklist

| Feature | State | Evidence |
|:--|:--|:--|
| Perception split trusted / untrusted; ERA | DONE | `perception/normalizer.py`, `risk_assessment/`; ERA wired into GUIDE re-scoring only (`experiments/rescore_v2.py:62-66`) |
| NCE (Gemini, Groq), recorded-answer replay, daily-quota stop | DONE | `perception/nce_engine.py`, `experiments/dedale_nce.py`, `agent/llm_utils.py` |
| SSE (open world), entity binding, RSEM, guardrails, outcome | DONE | `perception/sse.py`, `entity_binding.py`, `rsem.py`, `action_playbook.py`, `outcome.py` |
| Asymmetric trust | DONE | `perception/defended_pipeline.py:95-146`, `tests/test_asymmetric_trust.py` |
| Learning KS, gate, unlearning (B5), withdrawal | DONE | `perception/knowledge_db.py`, `knowledge_updater.py`, `soc_loop.py:208-265` |
| Triage gate with decision cache (policy-versioned) and NCE budget | DONE | `perception/triage_gate.py` |
| Analyst loop: case store, queue, four-eyes, rollback | DONE | `perception/case_store.py`, `review_service.py`; four-eyes tier ≥ 2 on DEDALE (`dedale/environment.py:64`) |
| Host detectors (6, Windows only) | DONE | `perception/host_detection.py:153-160` |
| Linux host detectors | NOT STARTED | needed only for E3 (`docs/ADDING_A_DATASET.md` §3) |
| Demo server: replay, follow, inject, live NCE, checkpoints, quarantine | DONE | `soc_server/`; server first start and replay checked 2026-11-22 |
| Accounts, login throttling, first-run setup | DONE | `review_api/accounts.py`, `review_api/app.py:175-291` |
| Web console (Live, Case, Host, Knowledge, Metrics, Lab, accounts) | DONE | `frontend/src/pages/`; typecheck passes; e2e check 9 / 9 on 2026-11-22 |
| Dataset registry | PARTIAL | `soc_server/datasets.py`: only DEDALE registered |
| GUIDE v2 results (both models) | DONE | `agent/v2_results/`, re-scores byte-identical 2026-11-22 |
| DEDALE frozen results incl. E1 and asymmetric trust | DONE (files); re-run re-freeze IN PROGRESS 2026-11-22 | `experiments/dedale_results/final_*_scores.json`, `e1_scores.json` |
| Paper (LaTeX) | PARTIAL | `paper/agentsoc_v2.tex`: authors and repository link are TODO (`:6`) |
| Paper (team Word revision) | PARTIAL | `AgentSOC_IEEE_Revised.docx`: three wrong claims (see Known issues) |
| Prompt-level baseline (P9 D) | NOT STARTED | needs a call budget; the 2026-11-01 pilot got only HTTP 503s; its branch is not in the repo |
| Hash-chained audit log (review change 9) | NOT STARTED | no code; `PROJECT_PLAN.md` P8/P9 said "on its branch", no such branch exists |
| E3 AIT-LDS | NOT STARTED (optional) | `PROJECT_PLAN.md` §4 |
| v1 corpus generators runnable | BROKEN | `GUIDE_Dataset/processed/synth_fields.py:195`, `inject_payloads.py:291` hard-code `/home/claude/...`; v2 builder works |
| Streamlit demo | ARCHIVED | `archive/streamlit/`: 4 of 7 scenario checks pass (pre-existing) |

## Known bugs, limits and gotchas

**Paper:**
- `AgentSOC_IEEE_Revised.docx` has three claims that do not match the repository:
  - §IV-D says the six planned experiments have "execution harnesses implemented in the repository". None exists in any commit.
  - §VI-A gives a network 5% false-alarm workload of 32.4 reviews/day "from benign destination IP unlearning". The frozen value is 21.2, and the 8 are blocks that would have hit benign traffic.
  - §V-C gives 624 test cases; the frozen value is 625.
  - Details: `docs/_audit_report.md` §3, `experiments/PAPER_CLAIMS_TO_REVISE.md`.
- `paper/agentsoc_v2.tex` and the `.docx` have different titles. Which one is submitted is undecided.

**Research limits** (all in the paper):
- one labelled testbed dataset with 2 attacked hosts;
- a simulated (oracle) analyst;
- one LLM on DEDALE;
- synthetic GUIDE entities and payloads;
- E1 injects into command lines only;
- containment is simulated;
- detectors and the open-world rule were chosen on DEDALE itself;
- Suricata alerted on 1 of the 84 labelled attack flows;
- each LLM condition was run once;
- NCE sees 512 characters per field (raw log line cut in 718 of 856 cases).

**Tool:**
- The review queue ranks benign STUN cases on the VPN server level with the attack (`PROJECT_PLAN.md` "Later").
- Followed logs must come from DEDALE's hosts: only DEDALE is registered.
- Steering marks cover entity names only, not suppression text.
- The server binds to localhost, without TLS.
- Live databases are protected only by file permissions.
- Analyst actions after the last checkpoint are lost on a crash.

**Reproduction gotchas:**
- `experiments/build_results.py:105-106` silently leaves out the asymmetric-trust C1 rows unless the three `rescore_v2 ... --llm-authority escalate` runs wrote `logs/*_rescored_escalate.json`. This checkout's `logs/` has none.
- `freeze_dedale` skips any replay whose `summary.json` exists. Use `--rerun` after code changes.
- On this machine `D:\agentsoc_data\runs` has no `A_*` (asymmetric-trust) replay outputs; the 2026-10-31 re-freeze that produced them left nothing there.
- Windows `os.replace` fails while another process holds a results file open: monitor long runs through the API log, never by opening the results JSON.
- In Git Bash, set `MSYS_NO_PATHCONV=1` before `tools/ui_check.py` (it rewrites `/` arguments into Windows paths).

**v1 leftovers** (historical code, not used by the current pipeline):
- `agent/measure_clean_confidence.py` makes live API calls and overwrites its result file without the overwrite guard.
- The v1 corpus generators cannot run as written.
- The v1 watchdogs `run_with_watchdog.py` / `_B.py` accept exit 0 regardless of progress.
- `soc_server/__main__.py:13` says NCE is "cache only"; that is only the default (`--nce live` calls Gemini).
- `frontend/dist/` was built 2026-10-20 13:02, one minute before the last `frontend/src` commit (`64051be`). Rebuild before a demo.

## Next steps (in order)

1. **Choose the paper to submit** (`paper/agentsoc_v2.tex` or the `.docx`). Then fix the three wrong `.docx` claims from `docs/_audit_report.md` §3:
   - remove "with execution harnesses implemented in the repository" from §IV-D;
   - replace "26.1 to 32.4 ... unlearning" with the frozen 21.2 reviews/day and "approved blocks would have hit benign traffic 8 times";
   - change 624 to 625.
   If the LaTeX paper is kept, fill the author block and repository link (`paper/agentsoc_v2.tex:6`).
2. **M7:** choose the venue (P2), then record the demo video. Before recording, rebuild the frontend (`cd frontend && npm run build`; the user runs installs) and run `tools/e2e_check.py`.
3. **Optional E3 (AIT-LDS):** only if the paper needs a second real dataset. Follow `docs/ADDING_A_DATASET.md`; download approval first (17 GB, CC BY-NC-SA 4.0).
4. **Optional P9 D (prompt-level baseline):** needs a written design and an approved call budget. Nothing exists in the repository to build on.
5. **Housekeeping (needs a yes):**
   - give `agent/measure_clean_confidence.py` the `agent/run_guard.confirm_overwrite` guard;
   - mark or fix the v1 generators' `/home/claude` paths;
   - decide whether the untracked personal root files stay.

## Open questions for a human

- Which paper is canonical, and does the `.docx` belong in git (committed in `c0ef3ed` by this audit to keep it safe)?
- Is review change 9 (hash-chained audit log) dropped? `PROJECT_PLAN.md` said it was on a branch that does not exist.
- Does anyone still have the `baseline-prompt` branch (`docs/LIMITATIONS_DRAFT.md:113` cites counts from it)?
- Where did the 2026-10-31 re-freeze run (its outputs are not in `D:\agentsoc_data`)?

## Conventions

- **Git:** one branch per change. Commit each step with its tests, and merge into `main` with `--no-ff` when the full suite passes. Push to `origin` (github.com/Akshara-reddy612/AgentSOC) only when asked; never push tags or side branches unasked. Commit messages: a short imperative summary, then details; end with the `Co-Authored-By` trailer the agent harness specifies.
- **Tracking:** every change updates this file in place and adds an entry to `RESEARCH_LOG.md`. Update `experiments/PAPER_CLAIMS_TO_REVISE.md` when a claim moves. Historical numbers are never edited: add a dated `[Correction YYYY-MM-DD]` note instead.
- **Scope:** `PROJECT_PLAN.md`. New ideas go to its "Later" list.
- **Approvals:** live LLM runs need an approved call budget (estimate calls first). Downloads need approval after size, licence and disk use are reported ("yes" to a plan is not approval to download). `pip` / `npm` installs are run by the user.
- **Code:**
  - Run Python as `python -m ...` from the repository root.
  - Data stays outside the repo; downloaded files are read with `python -I`.
  - `perception/normalizer.py` is locked (change only with a recorded decision).
  - Bump `perception/triage_gate.py` `POLICY_VERSION` when a triage or guardrail rule changes.
  - No number in the paper is typed by hand: it comes from `RESULTS.md` (`build_results`) or `paper/agentsoc_v2_numbers.md`.
- **Outputs:**
  - Replays write to `<data>/runs/<run>/` (`summary.json`, `cases.jsonl`, case store) and `<data>/ks/<run>.sqlite`.
  - GUIDE re-scores write to `logs/` (git-ignored).
  - Frozen scores go to `experiments/dedale_results/`, recorded LLM output to `agent/v2_results/`, and figure data to `paper/fig_*.dat`.

## How to maintain this file

- Update it in place whenever code, data, results or plans change, in the same commit as the change.
- Every status claim must be re-verified (run the command, read the file, check `git log`) before it is written. Never copy a claim forward from an older version or another document.
- Put dates and evidence next to claims; mark anything you could not check as UNVERIFIED.
- History belongs in `RESEARCH_LOG.md`, not here.
