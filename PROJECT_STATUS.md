# Project status

The current state of AgentSOC 2.0, updated in place. Scope and decisions: [PROJECT_PLAN.md](PROJECT_PLAN.md). Dated history: [RESEARCH_LOG.md](RESEARCH_LOG.md). The full status as it stood before this file was shortened, with every earlier phase, is in [archive/PROJECT_STATUS_HISTORY.md](archive/PROJECT_STATUS_HISTORY.md).

## Where things stand (2026-10-27)

The goal now is the handover (decision P7). Before the project goes to the team, everything for GUIDE and DEDALE is finished and stable. The team's remaining work is the optional third dataset (AIT-LDS, E3) and the M7 items: venue, authors, demo video.

| Milestone | State |
|:--|:--|
| M1 Freeze, `RESULTS.md`, `REPRODUCE.md` | Done 2026-10-18 |
| M2 Interrupted runs, E1 | Done 2026-10-20 (gpt-oss-20b complete: all 500 dev pairs) |
| M3 Paper draft | Full draft 2026-10-19 (`paper/agentsoc_combined.tex`, 15 checked references). Figs. 2 and 3 drawn 2026-10-20. Reviewer pass 2026-10-27: wording fixed where a reviewer could object (`RESEARCH_LOG.md`). 2026-10-31: contribution C6 (asymmetric trust: System paragraph, Results subsection and Table III, Discussion) and the fail-safe findings added; 7 pages. 2026-11-01: a Limitations item that no prompt-level defence was evaluated as a baseline (hardened-prompt comparison prepared, not completed: API overload errors); merged 2026-11-01; `docs/LIMITATIONS_DRAFT.md` matches it. 2026-11-01: a new paper, `paper/agentsoc_v2.tex`, written fresh from `RESULTS.md` against the base paper (merged into main and pushed that day). 2026-11-08, on `paper-v2` (not merged): the system is named GuardedSOC ("AgentSOC" now means only the base paper) and four result figures were added (attacker text, C2, C3, C4) and replace Tables II and III; 6 pages; every number traced in `paper/agentsoc_v2_numbers.md`. The team revises it; authors and the repository link are TODO |
| M4 Demo backend | Done 2026-10-18; extended 2026-10-19 (network alerts, live logs, contamination scenario, accounts in the browser) |
| M5 Frontend | Done 2026-10-20 (design pass, Contamination Lab, host timeline in M8) |
| M6 E3 (AIT-LDS) | Optional; for the team (P7) |
| M7 Venue, final paper, demo video | Team |
| M8 Handover | Done 2026-10-21, see below |

**M8 handover checklist:**

| Item | State |
|:--|:--|
| gpt-oss-20b run, final tables | Done 2026-10-20 |
| Full-replay soak test | Done 2026-10-20 (below) |
| Repository cleanup | Done 2026-10-20 (`archive/README.md`) |
| Frontend design pass | Done 2026-10-20: graphite console theme with a muted red accent (user-approved); every page restyled; host timeline added |
| Contamination Lab page (GUIDE) | Done 2026-10-20 (totals asserted equal to Table I) |
| Paper Figs. 2 and 3 | Done 2026-10-20 (`experiments/build_figures.py`) |
| Fresh-clone check; one-command end-to-end browser check | Done 2026-10-20: E2E check 9 / 9; a fresh clone passes all tests and reproduces every result byte-identically (below) |
| `HANDOVER.md`, adding-a-dataset guide, `--dataset` switch in the server | Done 2026-10-20 (`HANDOVER.md`, `docs/ADDING_A_DATASET.md`, `soc_server/datasets.py`) |

## Results

All final for GUIDE and DEDALE: [experiments/RESULTS.md](experiments/RESULTS.md), built only from frozen result files.

- **C1, attacker text does not steer actions:**
  - GUIDE v2, 500 dev and 500 held-out pairs, Gemini as the LLM: the pipeline's response was suppressed on 4 / 428 and 3 / 437 pairs (p = 1.0 and 0.25).
  - The undefended agent on the same dev pairs was hijacked on 130 / 439 (29.6%).
  - With gpt-oss-20b on the dev pairs: 10 / 437 (2.3%, p = 0.3).
  - 0 misdirected actions executed in every run.
  - E1 on DEDALE through the full loop: 1-3 of 72 attack cases dismissed without an analyst (0 with one), 0 attack patterns learned, the same 400 labelled attack events as the clean run still alerted.
  - **Asymmetric trust (2026-10-31, decision P9 A; `--llm-authority escalate`):** NCE's hypotheses may raise scrutiny, never lower it. E1: 0 of 72 attack cases dismissed in every family and condition (was 1 / 3 / 1), 0 learned, 400 alerted; the attacker's text changes no workload (65.2 / 34.1 reviews per day, as clean). GUIDE: suppression unchanged (4 / 428, 3 / 437, 10 / 437: those responses depended on the LLM reading the text), and automatic containments removed by contamination 20 / 178, 18 / 168, 21 / 176 (11%, mostly ERA's own escalation holding back the block) -> 0. Cost on DEDALE: +0.9 reviews per day with an analyst (34.1 vs 33.2), +10.4 without (65.2 vs 54.8); on GUIDE, none.
- **C2, gated learning:** learning the benign weeks cut host reviews from 6,095 to 65 per day, and every attack step still reached review (72 attack cases; 400 of the 473 labelled attack events that alert with nothing learned). Without NCE or an analyst, gated = frozen: the gate learns only dismissed cases. Correct analyst verdicts take it to 31-34. Network: 552 to 26 per day.
- **C3, poisoning:**
  - Ungated learning learned 38 attack patterns.
  - An analyst who misses 20% of the attacks: 20 patterns learned and 256 / 400 attack events still alerted. With unlearning on confirmed compromise: 0 learned, 400 / 400 alerted.
- **C4, the LLM on real telemetry:** -16% reviews. The closed-world feasibility check dismissed 2 attack cases; the open-world check dismisses 0. That reduction is NCE dismissing cases (89 without an analyst, 30 with one), the same path E1's attacker uses; under asymmetric trust NCE dismisses nothing (65.2 / 34.1 reviews per day, as with NCE off).
- **C5, the analyst loop:** 33 to 52 reviews per day as the analyst's delay grows from 1 h to 72 h. Network containment time equals the delay.

**What may and may not be claimed:** [experiments/PAPER_CLAIMS_TO_REVISE.md](experiments/PAPER_CLAIMS_TO_REVISE.md).

## The tool

- **Server:** `python -m soc_server`. It runs the DEDALE replay (host and network), follows live log files (`--follow`), or runs the contamination scenario (`--inject`). NCE replays recorded answers by default; `--nce live` takes a daily budget. Asymmetric trust is on by default (`--llm-authority escalate`; `full` runs the earlier pipeline).
- **Frontend:**
  - Live (SOC overview), Case (8-stage pipeline flow with possible-steering marks and an entity graph), host timeline, Knowledge Store, Metrics, Contamination Lab (GUIDE);
  - My account; Accounts (admin);
  - first-run admin setup in the browser.
- **Datasets:** `soc_server/datasets.py` holds everything dataset-specific; DEDALE is registered (`--dataset dedale`).
- **Checks:** `tools/e2e_check.py` opens every page of a running console (9 / 9 pass).
- **Data for teammates:** `dedale_for_team.zip` (321 MB, processed DEDALE files) replaces the 31.5 GB raw download; see `HANDOVER.md`. The recorded LLM answers ship in the repository.
- **Checkpoints (2026-10-31, review change 8):** loading resolves only the classes a checkpoint holds; each checkpoint is signed (HMAC, per-user key outside the home) and a changed one is refused before any live file is touched; a crash between the checkpoint's two renames restores `checkpoint.old`. Older unsigned checkpoints still load and the next one is signed.
- **Decision cache (2026-10-31, review change 5):** a cached decision is reused only under the same decision policy (triage-rule version, unreasoned policy, NCE version), so a restart with another `--nce` does not reuse old decisions. Re-freeze: frozen scores byte-identical.
- **Fail-safe processing (2026-10-31):** malformed events are refused and counted; an event the pipeline fails on is quarantined and the runner recovers from its latest checkpoint (it used to die silently); analyst commands that fail are recorded as failed; a pipeline error in triage sends the case to review; the T1071 grounding check reads only what NCE was shown (crafted 40,000-character text: 62 s before, 0.02 s now). `<home>/quarantine.jsonl`, `/live/status` counters.
- **Tests:** `HF_HUB_OFFLINE=1 python -m pytest -q`: 804 passed, 1 deselected, with the DEDALE package in the data folder (2026-10-31; 780 before changes 5 and 8, asymmetric trust and fail-safe processing). No dataset is needed: with an empty data folder the one data-dependent test skips.
- **Reproduction:** `freeze_dedale` now also runs E1 and the asymmetric-trust conditions (43 replays: 20 host, 12 E1, 11 network); on this machine the 8 current-pipeline E1 rows reproduce the committed `e1_scores.json` exactly (before, E1 could not be rebuilt from `REPRODUCE.md`). A full re-freeze after the fail-safe merge (2026-10-31) reproduced all three score files byte-identically.
- **Soak test (2026-10-19/20):**
  - the server fast-forwarded through the whole dataset, 15,013,901 events: two training weeks and 14 test days, 8,588 test cases;
  - no crash, peak memory 388 MB;
  - every read API answered in at most 0.12 s at that scale;
  - a hard stop and restart restored an identical state in about 10 s.
- **Reproduction from a fresh clone (2026-10-20):** a clean `git clone`, with only `AGENTSOC_DATA_DIR` set and an isolated data root (the original runs untouched).
  - All 778 tests pass.
  - The three GUIDE re-scorings, `RESULTS.md` (apart from its date line) and the figure data are identical.
  - The full DEDALE freeze (29 replays, all exit 0) gives byte-identical `final_host_scores.json` and `final_network_scores.json`.

## Known limits and open issues

**Research limits** (all in the paper's Limitations; the first six also in `RESULTS.md`):
- one labelled testbed dataset, with 2 labelled attacked hosts;
- a simulated analyst;
- one LLM on DEDALE;
- GUIDE's entities and payloads are synthetic;
- E1 injects text into command lines only;
- containment is simulated;
- the host detectors (chosen from a test-week measurement that included the labelled attack events) and the open-world rule (adopted after the closed-world misses) were chosen on DEDALE itself;
- Suricata alerted on 1 of the 84 labelled attack flows, so the network results rest on very few attack cases;
- each LLM condition was run once.

**Tool:**
- The review-queue order is tuned on DEDALE host data. Benign STUN cases on the VPN server rank level with the attack cases ("Later": count host peers by distinct pattern; drop placeholder targets such as "unknown").
- Followed logs must come from DEDALE's hosts: the environment model is DEDALE's until the `--dataset` switch exists.
- The steering marks cover names the LLM took from attacker text (entity binding). Suppression payloads, which name no entity, are not marked.
- The server binds to localhost and has no TLS.

## Tracking rule

Every change updates this file (in place), appends to `RESEARCH_LOG.md`, and updates `experiments/PAPER_CLAIMS_TO_REVISE.md` when a claim changes.
