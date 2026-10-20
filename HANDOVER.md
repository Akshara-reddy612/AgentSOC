# Handover

For the team taking over AgentSOC 2.0 (2026-10-20). Start here; the other documents are linked where they matter.

## Where the project stands

**Finished for GUIDE and DEDALE.**

| Part | State |
|:--|:--|
| Paper | Full draft: `paper/agentsoc_combined.tex`, 5 pages; every number comes from frozen results; 15 checked references |
| Results | Claims C1–C5 final: `experiments/RESULTS.md`, rebuilt from frozen files by one command |
| Tool | Demo server and web console, with accounts; the whole pipeline on the DEDALE attack, live log ingestion, a contamination scenario, and the GUIDE Contamination Lab |
| Tests | `HF_HUB_OFFLINE=1 python -m pytest -q` (778 pass), plus an end-to-end browser check of the console |

**Left for the team:**
1. **Optional third dataset (E3, AIT-LDS):** follow [docs/ADDING_A_DATASET.md](docs/ADDING_A_DATASET.md). Decide first whether the paper needs it (`PROJECT_PLAN.md`, section 4).
2. **M7:**
   - add the authors and the repository link to the paper;
   - revise Claude's drafted text, especially the related-work positioning;
   - choose the venue;
   - record the demo video.

Open issues are listed under "Known limits" in [PROJECT_STATUS.md](PROJECT_STATUS.md).

## The first hour

Windows, Python 3.13 and Node 22. Run everything from the repository root.

```
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-lock.txt
set HF_HUB_OFFLINE=1
.venv\Scripts\python -m pytest -q                        # all tests, a few minutes
```

**For the demo:**

1. **Data:** put DEDALE in `<data>/dedale/`; `<data>` is `AGENTSOC_DATA_DIR`, or `../agentsoc_data` by default. Then extract the host events once (about an hour):
   ```
   python -m experiments.dedale_extract_winlogbeat
   ```
2. **Frontend:** build it once.
   ```
   cd frontend && npm install && npm run build
   ```
3. **Server:** `python -m soc_server`.
   - The first start learns the benign weeks (a few minutes).
   - Open http://127.0.0.1:8000/. On the first run the page asks you to create the admin.
4. **Check it:**
   ```
   python tools/e2e_check.py --url http://127.0.0.1:8000 --user <you> --password-file <file>
   ```
   It opens every page and must report every check passing.

**Server variants:**
- `--inject steer`: the attacker's command lines carry text written for the LLM.
- `--follow host=...,network=...`: follow live log files.
- `--nce live`: real LLM calls, which need a budget.

All options are in the [README](README.md).

## The system in one page

**The pipeline**, one alert at a time:

| Stage | Module |
|:--|:--|
| Perception: trusted fields apart from attacker-writable text; text risk (ERA) | `perception/normalizer.py` (locked), `risk_assessment/` |
| NCE: the LLM proposes ATT&CK hypotheses | `perception/nce_engine.py` |
| SSE: structural feasibility on the environment graph; entity binding | `perception/sse.py`, `perception/entity_binding.py` |
| RSEM: response ranking; guardrails | `perception/rsem.py`, `perception/action_playbook.py` |

**The loop around it** (`perception/soc_loop.py`):

| Part | Module |
|:--|:--|
| Triage gate (learned? cached? daily LLM budget) | `perception/triage_gate.py` |
| Cases | `perception/case_builder.py` |
| Learning Knowledge Store behind the learning gate | `perception/knowledge_db.py`, `perception/knowledge_updater.py` |
| Outcome monitor | `perception/outcome_monitor.py` |
| Analyst review loop: inbox, four-eyes, verdicts, withdrawal, unlearning on confirmed compromise | `perception/case_store.py`, `perception/review_service.py` |

**The rules every change must keep** (details in `experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md`):
- **I1:** the store learns structured fields only, never text.
- **I2:** no look-ahead.
- **I3:** after training, learning happens only through the gate.
- **I4:** labels never enter the pipeline.
- **I5:** actions are simulated.
- **I6:** a single writer with an append-only audit log.

Analysts never write the store: their decisions become commands that the loop applies.

**The tool:**

| Part | Where |
|:--|:--|
| Server: live runner, checkpoints, sources, dataset registry, Contamination Lab, read APIs | `soc_server/` |
| Review API and accounts | `review_api/` |
| Web console (React + TypeScript): Live, Case, host timeline, Knowledge Store, Metrics, Contamination Lab, accounts | `frontend/` |
| Browser check and screenshot tools | `tools/` |

**The research:**

| Part | Where |
|:--|:--|
| GUIDE runners and recorded LLM outputs | `agent/`, `agent/v2_results/` |
| DEDALE readers and environment model | `dedale/` |
| Replays, scorers, design notes, frozen results | `experiments/` |
| The paper | `paper/` |

## How the numbers are made

No number in the paper is typed by hand.

1. Live LLM runs were recorded once (`agent/v2_results/`, and the NCE caches in `<data>/runs/`).
2. Replays re-run them on the final code: `python -m experiments.freeze_dedale`, and `experiments.rescore_v2` for GUIDE.
3. `python -m experiments.build_results` writes `experiments/RESULTS.md`, and `python -m experiments.build_figures` writes the figures' data.

The full sequence is in [REPRODUCE.md](REPRODUCE.md); none of it calls an API.

## Working rules

- **One branch per change.** Commit each step with its tests, and merge with `--no-ff` when the suite passes.
- **Tracking documents, on every change:**
  - update `PROJECT_STATUS.md` in place;
  - append to `RESEARCH_LOG.md`, recording what was tried, found and changed, with numbers;
  - update `experiments/PAPER_CLAIMS_TO_REVISE.md` when a claim moves.
- **Scope:** `PROJECT_PLAN.md` sets it; new ideas go to its "Later" list unless the plan changes by a dated decision recorded there.
- **Live LLM runs:** estimate the calls and agree the budget first. The key-pool runners stop at the daily cap and resume where they left off.
- **Keys:** they live in `.env` at the repository root (`GEMINI_API_KEY` or `GEMINI_API_KEYS`; `GROQ_API_KEY` or `GROQ_API_KEYS`). `.env` is git-ignored. Never commit or print a key.
- **Data:** it stays outside the repository. Downloads and installs need approval after their size, licence and disk use are known.
- **Locked file:** `perception/normalizer.py`. Change it only with a recorded decision.
- **Accuracy:** report results as they are. A failed check, a skipped step or a slip in a commit message goes into the log.

## Documents

| File | For |
|:--|:--|
| [README.md](README.md) | What the project is, quick start, demo options, repository map |
| [PROJECT_PLAN.md](PROJECT_PLAN.md) | Goals, claims C1–C5, milestones, decisions P1–P7, "Later" |
| [PROJECT_STATUS.md](PROJECT_STATUS.md) | Current state and known limits |
| [RESEARCH_LOG.md](RESEARCH_LOG.md) | Dated history of every session |
| [REPRODUCE.md](REPRODUCE.md) | Rebuilding every number |
| [experiments/RESULTS.md](experiments/RESULTS.md) | The frozen results |
| [experiments/PAPER_CLAIMS_TO_REVISE.md](experiments/PAPER_CLAIMS_TO_REVISE.md) | What may and may not be claimed |
| [PAPER_OUTLINE.md](PAPER_OUTLINE.md) | The paper's structure |
| [DEMO_BACKEND_DESIGN.md](DEMO_BACKEND_DESIGN.md), [frontend/README.md](frontend/README.md) | The tool |
| [docs/ADDING_A_DATASET.md](docs/ADDING_A_DATASET.md) | The E3 recipe |
| `experiments/*_DESIGN.md`, `experiments/DEDALE_*.md` | Design decisions and per-phase results |
| [archive/README.md](archive/README.md) | What was retired, and why |
