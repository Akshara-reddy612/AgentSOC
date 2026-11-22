# CLAUDE.md

**Read [PROJECT_STATUS.md](PROJECT_STATUS.md) and [RESEARCH_LOG.md](RESEARCH_LOG.md) first.**
- PROJECT_STATUS.md: what the project is, its current state, the repo map, how to run it, what to do next.
- RESEARCH_LOG.md: the history, results with their sources, dead ends, decisions.

Scope is fixed by [PROJECT_PLAN.md](PROJECT_PLAN.md).

## Commands (run from the repository root, Windows paths shown)

```
.venv\Scripts\python -m pytest tests experiments -q            # with HF_HUB_OFFLINE=1; 804 passed, 1 deselected (2026-11-22)
.venv\Scripts\python -m soc_server                             # demo server, http://127.0.0.1:8000 (default home <data>/live)
.venv\Scripts\python tools\e2e_check.py --url http://127.0.0.1:8000 --user <you> --password-file <file>
cd frontend && npm run typecheck                                # npm run build after frontend changes (installs: the user runs them)
.venv\Scripts\python -m experiments.rescore_v2 <results.json> --set dev [--llm-authority escalate]   # REPRODUCE.md step 3
.venv\Scripts\python -m experiments.freeze_dedale --workers 6   # 43 DEDALE replays, offline
.venv\Scripts\python -m experiments.build_results               # writes experiments/RESULTS.md
```

Data lives outside the repository in `AGENTSOC_DATA_DIR` (default `<repo>/../agentsoc_data`; on this machine `D:\agentsoc_data`).

## Do not

- **No live LLM run without an approved call budget.** NCE replays recorded answers by default (`--nce cache`); `--nce live` and anything under `agent/run_*` call paid APIs.
- **No downloads or package installs without approval.** First report size, licence and disk use; the user runs `pip` / `npm` installs.
- **Never print API keys** (`.env`, `GEMINI_API_KEYS`, `GROQ_API_KEYS`); show the last 4 characters at most. Never commit `.env`.
- **Do not edit `perception/normalizer.py`** (team-locked) without a recorded decision.
- **Do not overwrite frozen results** or recorded LLM output: `experiments/dedale_results/`, `agent/v2_results/`, `experiments/dedale_results/nce_cache/`. Do not run the real demo homes under `D:\agentsoc_data\` (`live`, `demo`, `soak`, ...) for experiments; use a new `--home`.
- **Never type a paper number by hand:** it comes from `experiments/RESULTS.md` or `paper/agentsoc_v2_numbers.md`.
- **Git:** do not push, tag or force anything unasked. Work on a branch, commit per step, and merge with `--no-ff` only when the suite passes.
- **Never monitor a long run by opening its results JSON** (Windows `os.replace` then fails). Watch the API log instead.

## Every change

1. Update `PROJECT_STATUS.md` in place.
2. Add a dated entry to `RESEARCH_LOG.md`.
3. Update `experiments/PAPER_CLAIMS_TO_REVISE.md` if a paper claim moves.

Re-verify status claims; do not copy them forward.
