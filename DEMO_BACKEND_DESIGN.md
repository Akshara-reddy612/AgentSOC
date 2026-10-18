# Demo backend (M4) — design (2026-10-18)

Serves the demo in `PROJECT_PLAN.md` section 5: a day in the SOC during the DEDALE attack, with a real frontend (M5).

## Shape: one server process

`python -m soc_server --data <dir>` runs one process:

- **Runner thread:** the SOC loop, fed by a replay source (DEDALE host events or network alerts) at an adjustable speed.
- **FastAPI app:** the existing review API, plus live control, read APIs and accounts.

One process keeps the Knowledge Store's single writer (I6) simple. The runner writes; API reads of the Knowledge Store go through their own read-only SQLite connection (WAL), never the runner's in-memory graph.

## Steps

| # | Step | Content |
|:--|:--|:--|
| 4.1 | Accounts | `users` (username, role analyst / lead / admin, scrypt hash from Python's standard library, disabled flag) and `sessions` (random token, expiry) in an auth database. `POST /auth/login`, `/auth/logout`, `/me`. Admin creates users. Replaces the token list; four-eyes still means two different usernames. Live control is lead / admin only |
| 4.2 | Live runner and recovery | The loop in a background thread. Start / pause / speed (event time per wall second) / status. **Checkpoints:** at chunk boundaries the runner pauses, copies the Knowledge Store and the case store (SQLite backup API), and pickles the loop's in-memory state (open cases, gate queue, watches, awaiting verdicts, decision cache) with the stream position. On restart it restores the latest checkpoint and resumes, so a crash loses at most one chunk of replay time |
| 4.3 | Read APIs | `/cases/{id}/trace`: the pipeline stage by stage (alert -> trusted / untrusted evidence -> hypotheses -> SSE -> RSEM -> guardrails -> triage -> learning effect). `/knowledge/...`: node and edge counts by provenance, a host's learned patterns, retractions, the audit log, a neighbourhood graph for the Cytoscape view. `/metrics`: per-day reviews, cases by outcome, learned and retracted patterns, alerts processed; the frozen comparison runs (no learning, no gate) from `RESULTS.md` files |
| 4.4 | Server and seed | `python -m soc_server`; first start builds the training-period store (two benign weeks) once and checkpoints it, so the demo starts at "attack day minus a few hours" |

Each step is committed with tests. No new Python packages are needed.

## Not in M4

- TLS.
- Multi-tenant.
- Real sensor ingestion: the source is a replay; a live log tail could plug into the same runner later ("Later" list).
