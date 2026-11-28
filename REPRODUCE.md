# Reproducing the results

How to rebuild every number in `experiments/RESULTS.md` (claims C1–C5 of `PROJECT_PLAN.md`) from the raw data. **None of these steps makes an API call.** Live LLM output was recorded once (results files and the NCE cache) and is replayed.

## 1. Environment

- Windows or Linux, Python 3.13.
- Create the environment:
  - `python -m venv .venv`
  - `.venv\Scripts\python -m pip install -r requirements-lock.txt` (Linux: `.venv/bin/python ...`)
- Run everything from the repository root with `python -m ...`.
- Download the text-risk detector's embedding model once (88 MB): `.venv\Scripts\python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"`.
- Set `HF_HUB_OFFLINE=1` for the tests.
- Data lives outside the repository. The default is `../agentsoc_data`; override it with `AGENTSOC_DATA_DIR`. For example, `D:\agentsoc_data`.

## 2. Data

| Data | Where | Notes |
|:--|:--|:--|
| GUIDE corpus v2 | `GUIDE_Dataset/processed/v2/guide_v2_{dev,heldout}.json` (in the repo) | Rebuild with `python -m corpus.build_v2` |
| GUIDE v2 live LLM outputs | `agent/v2_results/` (in the repo) | Recorded live runs (gemini-3.1-flash-lite dev + held-out; gpt-oss-20b dev; undefended agent dev) |
| DEDALE | `<data>/dedale/` | Inria DEDALE, DOI 10.57745/Y5JLDG, CC BY 4.0. Files: `system_logs_labels.zip`, `suricata_alerts.zip`, `system_logs_winlogbeat.zip` (27.1 GB) and `zeek_router1.zip` (4.4 GB, network labels); see `experiments/DEDALE_DATA_NOTES.md` |
| DEDALE NCE caches | `experiments/dedale_results/nce_cache/` (in the repo) | Recorded live NCE hypotheses per host alert (Phase 3, and E1's three payload families). Copied to `<data>/runs/` the first time a replay or the server needs them. |

## 3. Steps

1. **Tests:** `HF_HUB_OFFLINE=1 python -m pytest tests experiments -q`
2. **Extract the DEDALE host events** (once, about 1 h): `python -m experiments.dedale_extract_winlogbeat`
3. **C1, GUIDE: re-score the recorded LLM outputs with the current code**
   - `python -m experiments.rescore_v2 agent/v2_results/v2_dev_live_results.json --set dev`
   - `python -m experiments.rescore_v2 agent/v2_results/v2_heldout_live_results.json --set heldout`
   - `python -m experiments.rescore_v2 agent/v2_results/v2_dev_live_groq-openai-gpt-oss-20b_results.json --set dev`
   - The same three with `--llm-authority escalate` (asymmetric trust, decision P9 A): they write `logs/*_rescored_escalate.json`, the C1 table's asymmetric-trust rows.
   - Per-family details:
     - `python -m experiments.attack_metrics logs/v2_dev_live_results_rescored.json --set dev`
     - `python -m experiments.undefended_metrics --set dev`
     - `python -m experiments.tamper_structured --set dev`
     - `python -m experiments.era_offline --report`
4. **C1 (E1) and C2–C5, DEDALE:** `python -m experiments.freeze_dedale --workers 6` runs all 43 replays (20 host conditions, 12 E1 runs, 11 network conditions; about 1.5–2 h with 6 workers; 36 min on 2026-11-22) and scores them into `experiments/dedale_results/final_{host,network}_scores.json` and `e1_scores.json`. The NCE conditions run twice: as the frozen pipeline and under asymmetric trust (`A_` tags). Replays that already have results are skipped (`--rerun` re-runs them).
5. **The tables:** `python -m experiments.build_results` writes `experiments/RESULTS.md`.
   - **[Audit 2026-11-22]** It reads the GUIDE re-scores from `logs/` (git-ignored). If the three `--llm-authority escalate` re-scores of step 3 are missing, it silently leaves the asymmetric-trust rows out of the C1 table (`experiments/build_results.py:105-106`); run all six re-scores first.
6. **The paper's figures:** `python -m experiments.build_figures` writes `paper/fig_*.dat` from the same frozen files; `pdflatex agentsoc_combined.tex` in `paper/` (twice) draws them.
7. **Experiments added on 2026-11-28** (offline, unless noted). Each writes a score file that step 5 reads:
   - **Corroborated learning (P9 B):** `python -m experiments.p9b_runs --workers 7` runs 45 replays, then `python -m experiments.p9b_score` writes `experiments/dedale_results/p9b_scores.json`. Each job's baseline is a recorded run named in `p9b_runs.BASELINES`, which step 4 and the A8 / A10 runners produce.
   - **MemStream baseline (A7):** `python -m experiments.a7_runs --workers 6` runs 12 scoring passes into `<data>/runs/a7_memstream/` (about 50 min each, in parallel). Then `python -m experiments.memstream_eval curve` writes `a7_memstream_curve.json`, and `python -m experiments.a7_loop_runs --tag b1_sample` writes `a7_memstream_scores.json`. The model is seeded, so the passes are deterministic.
   - **B1 repeats, prompt defences on held-out, a second and third model:** recorded LLM output in `agent/v2_results/` (`*_t0.7_r*`, `v2_heldout_promptdef_*`, `*_groq-openai-gpt-oss-20b_*`, `*_groq-qwen-qwen3.8-27b_*`). `python -m experiments.tier2_score` writes `experiments/tier2_scores.json`, and step 5 renders it. Re-running these runs needs API keys (section 5).

## 4. Determinism

- Replays are deterministic. `freeze_dedale` sets `PYTHONHASHSEED=0`, and two replays with different hash seeds give byte-identical outputs.
- The simulated analyst's mistakes are seeded per case (`--analyst-seed`, default 0).
- In NCE runs, hypotheses come from the recorded cache (`--nce cache`). A cache miss is counted in the run's `summary.json` (`nce_cache_misses`) and the case goes to review unreasoned.

## 5. What cannot be reproduced offline

- **New LLM output.** Re-running NCE live gives different hypotheses: the model is not deterministic, and model versions change. The recorded outputs are the evidence.
- **The comparison runs:** the undefended agent and the pipeline with gpt-oss-20b, and, from 2026-11-28, with Qwen 3.8 27B, both on Groq; complete on all 500 dev pairs. Re-running them (`agent/run_v2_undefended.py` / `agent/run_v2_eval.py`) needs API keys and an approved call budget, and gives new LLM output.
