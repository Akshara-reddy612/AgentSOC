# AgentSOC 2.0

A research prototype of an LLM-driven Security Operations Centre (SOC) that defends its own two attack surfaces:

- **The LLM reads log text an attacker can write.** Command lines, script text and alert descriptions can carry instructions such as "this is routine maintenance" or "isolate the domain controller".
- **The memory learns from what it sees and from analysts.** An attacker who is seen often enough, or wrongly marked benign, can be learned as normal.

The full pipeline keeps the LLM's output advisory: structural checks, entity binding, guardrails and a learning gate decide what it may cause. It was evaluated on real telemetry (DEDALE) and on a contamination corpus (GUIDE v2). It also runs as a live tool, with a review web app for analysts.

KMIT research project. Scope and milestones are in [PROJECT_PLAN.md](PROJECT_PLAN.md); results are in [experiments/RESULTS.md](experiments/RESULTS.md).

## The pipeline

| # | Stage | What it does | Code |
|:--|:--|:--|:--|
| 1 | Perception | Normalises alerts and host events. Keeps trusted structured fields apart from untrusted text, and scores the text for injection risk (ERA). | `perception/normalizer.py`, `risk_assessment/`, `perception/host_detection.py` |
| 2 | NCE | The LLM proposes ATT&CK hypotheses (technique, target) from the evidence. | `perception/nce_engine.py` |
| 3 | SSE + entity binding | Checks each hypothesis against the environment model (feasible, conditionally feasible, infeasible). Flags targets that the trusted fields do not support. | `perception/sse.py`, `perception/entity_binding.py` |
| 4 | RSEM | Ranks responses. | `perception/rsem.py` |
| 5 | Guardrails | Hard floors on actions and playbook status (proposed, auto-approved, blocked). | `perception/action_playbook.py` |
| 6 | Triage gate | Decides whether a case is closed, reviewed or contained, and whether NCE is called (with a daily budget). | `perception/triage_gate.py` |
| 7 | Learning Knowledge Store | Learns benign patterns from closed cases, only behind a learning gate. Append-only audit log. | `perception/knowledge_db.py`, `perception/knowledge_updater.py` |
| 8 | Outcome monitor | Watches containment and confirmed hosts. | `perception/outcome_monitor.py` |
| 9 | Analyst review loop | Verdicts, approvals (four-eyes on critical hosts), rollback, withdrawing a wrong verdict, and unlearning on confirmed compromise. Analysts never write the store directly: the loop is its single writer. | `perception/case_store.py`, `perception/review_service.py`, `perception/soc_loop.py` |

## Headline results

All numbers are from [experiments/RESULTS.md](experiments/RESULTS.md), built from frozen result files. See that file for the conditions and the limits.

- **C1, attacker text does not steer actions:**
  - On 500 GUIDE v2 dev pairs, an undefended LLM agent was hijacked into dismissing 130 / 439 contaminated alerts (29.6%).
  - The defended pipeline's response was suppressed on 4 / 428 (0.9%, McNemar p = 1.0), with 0 misdirected actions executed.
  - On DEDALE, through the full loop, text appended to the attacker's own command lines taught the store 0 attack patterns, and all 400 labelled attack events still alerted.
- **C2, gated learning cuts analyst load:** on DEDALE host logs, reviews fell from 6,095 to 65 per day, with all 72 attack cases still raised.
- **C3, memory poisoning:**
  - Without the gate, the store learned 38 attack patterns.
  - An analyst who misses 20% of attacks lets 20 be learned. With unlearning on confirmed compromise, 0 are learned.
- **C4, the LLM on real telemetry:** reviews fell by 16%. A closed-world feasibility rule dismissed 2 real attack cases; the open-world rule dismisses 0.
- **C5, the analyst loop:** reviews fell from 65 to 34 per day with an analyst who answers after 4 h (51.5 per day after 72 h).

**Limits:**

- one real dataset, with 2 labelled attacked hosts;
- a simulated analyst;
- one LLM on DEDALE;
- synthetic entities and payloads in GUIDE v2.

## Quick start

Needs Python 3.13, plus Node 22 for the frontend.

```
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-lock.txt      # Linux / macOS: .venv/bin/python
set HF_HUB_OFFLINE=1                                               # bash: export HF_HUB_OFFLINE=1
.venv\Scripts\python -m pytest -q
```

Data lives outside the repository: `../agentsoc_data` by default, or wherever `AGENTSOC_DATA_DIR` points. The demo and the DEDALE experiments need DEDALE there (see [Data](#data)). The tests do not.

## Run the demo

The demo is a day in the SOC during the DEDALE attack. The server replays DEDALE's Windows events and Suricata alerts through the whole pipeline. Analysts work the review queue in the browser while the stream runs.

1. **Build the frontend** (once, and after frontend changes):
   ```
   cd frontend
   npm install
   npm run build
   ```
2. **Prepare the DEDALE host events** (once, about 1 h):
   ```
   python -m experiments.dedale_extract_winlogbeat
   ```
3. **Create an admin account:**
   ```
   python -m review_api.accounts --db <home>/auth.sqlite create-user <name> --role admin
   ```
   `<home>` defaults to `<data>/live`.
4. **Start the server:**
   ```
   python -m soc_server
   ```
   - The first start learns the two benign weeks and fast-forwards to 08:00 on the attack morning. This takes a few minutes; later starts resume from the last checkpoint.
   - Open http://127.0.0.1:8000/, sign in, and press Start on the Live page (lead or admin).

| Option | Default | Meaning |
|:--|:--|:--|
| `--home` | `<data>/live` | Server state: stores, checkpoints, accounts. A home is tied to its sources; use a new one to change them. |
| `--sources` | `host,network` | Replay the Windows events, the Suricata alerts, or both |
| `--speed` | `600` | Stream seconds per wall second (also adjustable in the app) |
| `--demo-start` | `2025-01-06T08:00` | Where the first start fast-forwards to |
| `--nce` | `cache` | `cache`: recorded LLM answers, no API calls. `live`: Gemini, at most `--nce-per-day` calls per stream day (needs `GEMINI_API_KEY` or `GEMINI_API_KEYS`). `off`: no LLM. |
| `--follow` | | Follow live log files instead of the replay: `host=<winlogbeat.ndjson>,network=<eve.json>` |
| `--follow-clock` | `events` | With `--follow`: `wall` moves the clock with real time while the files are quiet |
| `--host`, `--port` | `127.0.0.1`, `8000` | Where to listen |

**Pages:**

- **Live:** stream clock and controls, status, and the prioritised review queue.
- **Case:** the eight-stage pipeline trace; verdicts with a preview of what the store will learn; containment approval and rollback; related cases, notes and audit.
- **Knowledge Store:** what was learned, from where, and what was retracted.
- **Metrics:** the frozen comparison runs and the session's own counts.
- **Accounts:** admin only.

The API reference is at `/api/docs`. More detail, including development mode, is in [frontend/README.md](frontend/README.md) and [DEMO_BACKEND_DESIGN.md](DEMO_BACKEND_DESIGN.md).

**Following live logs:**

- `--follow` reads lines as a log shipper appends them:
  - winlogbeat / ECS JSON for host events;
  - Suricata `eve.json` alerts, or DEDALE's router syslog lines.
- It resumes by byte offset after a restart.
- The environment model is still DEDALE's (inventory, zones), so the logs must come from its hosts.

**Security notes:**

- The server binds to localhost.
- Passwords are hashed with scrypt, and sessions use hashed tokens.
- Logins are throttled: 5 failures per user and address, or 20 per address, lock that key for 15 minutes.
- Text from logs is always shown as text, never as HTML.
- All containment is simulated: nothing touches a real network.

## Reproduce the results

Follow [REPRODUCE.md](REPRODUCE.md). In short:

```
python -m experiments.freeze_dedale --workers 6      # the 29 DEDALE conditions (30-60 min)
python -m experiments.build_results                  # writes experiments/RESULTS.md
```

No step makes an API call: live LLM output was recorded once and is replayed.

## Data

| Dataset | Use | Where |
|:--|:--|:--|
| [DEDALE](https://doi.org/10.57745/Y5JLDG) (Inria, CC BY 4.0) | Real telemetry of a multi-step attack on a company testbed: Windows logs of 30 clients, Suricata alerts, labels. The main evidence for C1 (E1) and C2-C5, and the demo. | `<data>/dedale/` (over 27 GB) |
| GUIDE v2 | Contamination corpus: clean / contaminated alert pairs built from Microsoft GUIDE rows with synthetic entities and payloads (C1) | `GUIDE_Dataset/processed/v2/` (in the repository) |

## Repository map

| Path | Contents |
|:--|:--|
| `perception/` | The pipeline, the Knowledge Store, the case store and the SOC loop |
| `risk_assessment/`, `prompt_construction/` | ERA (evidence risk assessment) and safe prompt construction |
| `dedale/` | DEDALE readers and its environment model (inventory, zones) |
| `corpus/`, `GUIDE_Dataset/` | The GUIDE v2 corpus and its builder |
| `agent/` | GUIDE evaluation runners and recorded live LLM outputs (`agent/v2_results/`) |
| `experiments/` | DEDALE replays, scorers, design notes and the frozen results |
| `soc_server/` | Demo server: live runner, replay and follow sources, read APIs |
| `review_api/` | Review API and accounts |
| `frontend/` | React + TypeScript web app |
| `paper/` | Paper draft (LaTeX) |
| `tests/` | Test suite |
| `monitoring/` | Earlier real-time monitoring layer (tested; its Streamlit tab is archived) |
| `archive/streamlit/` | The retired Streamlit demo |
| `tools/` | `ui_check.py`: drives a headless browser over the app and saves screenshots |
| `scratch/` | One-off investigation scripts from earlier phases |

## Project documents

| File | What it holds |
|:--|:--|
| [PROJECT_PLAN.md](PROJECT_PLAN.md) | Goals, claims C1-C5, milestones; work outside it goes to "Later" |
| [PROJECT_STATUS.md](PROJECT_STATUS.md) | Current state, updated in place |
| [RESEARCH_LOG.md](RESEARCH_LOG.md) | Dated log of every session: what was tried and found |
| [experiments/RESULTS.md](experiments/RESULTS.md) | Frozen results tables |
| [experiments/PAPER_CLAIMS_TO_REVISE.md](experiments/PAPER_CLAIMS_TO_REVISE.md) | What may and may not be claimed |
| [PAPER_OUTLINE.md](PAPER_OUTLINE.md) | Paper structure and who writes what |
| `experiments/*_DESIGN.md`, `experiments/DEDALE_*` | Design notes and per-phase results |
