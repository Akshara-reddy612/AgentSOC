# Demo backend (M4) — design (2026-10-18)

Serves the demo in `PROJECT_PLAN.md` section 5: a day in the SOC during the DEDALE attack, with a real frontend (M5).

## Shape: one server process

`python -m soc_server [--home <dir>]` runs one process:

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

## Added after M4 (2026-10-19)

| Addition | Content |
|:--|:--|
| Network alerts | `--sources host,network` (default) merges the Windows events and the Suricata alerts in stream time (`MergedSource`). A home records which sources built it and refuses others |
| NCE modes | `--nce cache` (recorded answers, no API calls; default), `live` (Gemini, at most `--nce-per-day` calls per stream day), `off`. Live mode works on a copy of the recorded cache in the home, so the frozen results' caches are never written |
| Live log ingestion | `--follow host=<path>,network=<path>` (`soc_server/follow.py`): winlogbeat / ECS JSON lines and Suricata eve.json or DEDALE syslog lines, read as they are appended, unpaced, resumed by byte offset. Training still comes from the DEDALE replay; `--follow-clock wall` moves the clock with real time while the files are quiet |
| Contamination scenario | `--inject suppress|fake_approval|steer` (plan section 5, item 7): the attacker's command lines carry E1's payloads, and with `--nce cache` the LLM answers are E1's recorded ones |
| Login throttling | 5 failures per user + address, or 20 per address, in 15 min lock that key for 15 min (HTTP 429 with Retry-After) |
| Withdrawing a verdict | `POST /cases/{id}/withdraw` (lead / admin): a wrong 'malicious' verdict is withdrawn; the loop ends the host's watch, restores the patterns it retracted and the destination's previous reputation, and the case returns to the queue |
| Accounts in the browser | First-run admin setup (`/auth/setup`, once, only while no account exists); own password (`/auth/password`); admin role change, enable, password reset (`/admin/users/*`) |
| Console data | `/live/activity` (cases per stream hour, closed vs sent to an analyst), `/techniques` (ATT&CK names), queue items with kind, tier, feasible techniques and a grouping key, `/hosts/{host}/timeline`, `/knowledge/hostnames` |
| Contamination Lab | `/lab/*` (`soc_server/lab.py`): GUIDE v2 pairs replayed from the recorded runs; totals equal the paper's Table I (tested) |
| Dataset registry | `soc_server/datasets.py`; `--dataset` picks one (DEDALE registered). Status carries the dataset label; Metrics' comparison runs come from the dataset |

## Not built

- TLS.
- Multi-tenant.
- An environment model for networks other than DEDALE: followed logs must come from DEDALE's hosts.
- Highlighting suppression payloads in the case view: the console marks names a steered hypothesis took from attacker text (entity binding); text that names no entity is shown but not marked. (The Contamination Lab marks the exact inserted text, since there the clean twin is known.)
