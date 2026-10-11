# Analyst review loop — design (plan item B, 2026-10-11, draft)

**Goal:** real analysts can work the cases the system raises. They see a queue, open a case with its evidence, give a verdict, and approve, reject or roll back the proposed actions. Everything they do is stored and audited, and their verdicts teach the Knowledge Store exactly as the simulated analyst does today. This is the backend the future frontend will call; no UI here.

## Where we are

- **What exists:**
  - `SocLoop` (`perception/soc_loop.py`) already has an analyst hook: `analyst(case, decision, at)`, called a fixed delay (4 h) after each REVIEW case.
  - "benign" -> the updater learns the case (provenance `analyst`) and, since 2026-10-11, lifts the case's hold on the learning gate.
  - "malicious" -> the proposed containment is approved and watched, an external destination is marked known-bad, and the host is flagged.
  - In the DEDALE experiments this analyst is an oracle that reads the labels.
- **What is missing for real use:**
  1. Verdicts are pulled by a callback at a fixed delay, not pushed by a person whenever they decide.
  2. Cases, decisions and verdicts live in per-run JSONL files; no persistent store.
  3. No queue, no case view, no action approval or rollback, no audit of analyst actions.
  4. No API.

## Components

### 1. Case store (`perception/case_store.py`)

- A SQLite database **separate from the Knowledge Store**. The Knowledge Store holds only trusted, structured knowledge (invariant I1). The case store holds what analysts need, including attacker-influenced text (command lines, raw events) and LLM output. Keeping them apart keeps I1 simple: nothing in the case store is ever read as knowledge.
- **Tables:**
  - `cases`: id, key, detector or signature, host, opened / last seen / closed, status.
  - `alerts`: per alert; structured fields and raw text in separate columns, so the text is marked untrusted.
  - `decisions`: the triage gate's decision with its hypotheses, SSE verdicts, reasons and playbook.
  - `actions`: proposed / approved / rejected / executed / rolled back, with who and when.
  - `verdicts`.
  - `audit`: append-only, enforced by triggers as in `ks_log`.
- **Written by the loop** (`on_case` / `on_alert` hooks, which already exist) and **by the review service**. Replays can write to it too, so the same queue can be inspected after a DEDALE replay.

### 2. Review service (`perception/review_service.py`)

The Python API the HTTP layer and tests call:

- `queue(filters) -> [case summary]`, ordered by a transparent priority score:
  - flagged host, known-bad contact, host criticality tier, a FEASIBLE hypothesis, number of alerts, age.
  - Each item shows why it is where it is.
- `case(case_id)`: evidence in three labelled groups:
  - **trusted telemetry fields**;
  - **untrusted text** (command lines, raw events: may contain attacker-written instructions);
  - **system reasoning** (NCE hypotheses, marked as LLM output; SSE / RSEM / guardrail results).

  It also shows related cases (same host, same key) and open watches.
- `claim(case_id, analyst)`, `submit_verdict(case_id, verdict, analyst, note)`.
- `approve_action / reject_action / rollback_action(action_id, analyst, reason)`.
- **Verdicts are a fixed vocabulary** (proposal):

  | Verdict | Effect |
  |:--|:--|
  | `malicious` | Today's "malicious": containment approved and watched, destination known-bad, host flagged |
  | `benign` | Learned as routine (provenance `analyst`); lifts the learning hold |
  | `benign_once` | Closed without learning: allowed this time, still alerts next time (e.g. a one-off admin task) |
  | `needs_info` | Stays open, keeps its hold on learning |

- **Notes are free text** and stay in the case store; they never reach the Knowledge Store (I1).

### 3. Pushed verdicts in the loop

- `SocLoop.apply_verdict(case_id, verdict, analyst, at)` becomes the single path for verdicts. The simulated analyst (the callback with a delay) becomes one caller of it, and the review service another.
- **Regression:** the oracle replay through the new path must reproduce the current `gated_analyst` numbers exactly.

### 4. Actions

- **Simulated, as now (invariant I5).** "Executed" means:
  - the action and its effect are recorded (e.g. destination blocked, host isolated) in the store's dry-run form;
  - the outcome monitor watches it (as `register(approved_by=...)` already does).
- **Rollback** writes the reversal and ends the watch, both audited.
- **Real connectors** (EDR, firewall) are out of scope; an interface for them is left for later.

### 5. HTTP API (`api/`)

- JSON over HTTP with **Starlette + uvicorn, both already installed** (no download).
- **Endpoints:**
  - `GET /queue`;
  - `GET /cases/{id}`;
  - `POST /cases/{id}/claim`;
  - `POST /cases/{id}/verdict`;
  - `POST /actions/{id}/approve | reject | rollback`;
  - `GET /audit`.
- **Authentication until the frontend has accounts:** one token per analyst from `.env`, compared in constant time, never logged. Every write records the analyst.

## Evaluation

1. **Plumbing regression:** a DEDALE replay with the oracle analyst sending verdicts through the review service reproduces `gated_analyst` (Phase 2) and `gated_nce_analyst` exactly.
2. **Delay sensitivity:** 1 h / 4 h / 24 h / 72 h analyst delay. What does a slower team cost in reviews and in containment time?
3. **Noisy analyst:** a share of wrong verdicts (e.g. 5% malicious called benign). How much attack activity is learned as routine, and does the gate or the outcome monitor catch it? This is the poisoning risk of analyst feedback.
4. **API tests:** auth, the audit trail, invalid transitions (e.g. roll back an action that was never executed), concurrency (two analysts claim the same case).

## Open decisions

- **B1 API framework:** Starlette (installed, recommended) or FastAPI (a download; adds automatic OpenAPI docs for the frontend team). Switching later is cheap, because the service layer holds the logic.
- **B2 Verdict vocabulary:** the four above, or only malicious / benign.
- **B3 Should `benign` on a case also clear similar open cases** (same key, same host)? This saves work but can hide a second, malicious instance. Proposal: no; show them as related cases instead.
- **B4 Who may approve containment:** any analyst, or a second analyst for hard-floor actions (four-eyes)? Proposal: any analyst, with four-eyes as a profile option.

## Order of work

1. Case store.
2. `apply_verdict` refactor + regression replay.
3. Review service.
4. Actions + rollback.
5. HTTP API.
6. Evaluations 2-3.

Each step is committed with tests; no API calls are needed.
