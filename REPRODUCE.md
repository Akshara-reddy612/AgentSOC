# Reproducing the results

How to rebuild every number in `experiments/RESULTS.md` (claims C1–C5 of `PROJECT_PLAN.md`) from the raw data. **None of these steps makes an API call.** Live LLM output was recorded once (results files and the NCE cache) and is replayed.

## 1. Environment

- Windows or Linux, Python 3.13.
- Create the environment:
  - `python -m venv .venv`
  - `.venv\Scripts\python -m pip install -r requirements-lock.txt` (Linux: `.venv/bin/python ...`)
- Run everything from the repository root with `python -m ...`.
- Set `HF_HUB_OFFLINE=1` for the tests.
- Data lives outside the repository. The default is `../agentsoc_data`; override it with `AGENTSOC_DATA_DIR`. For example, `D:\agentsoc_data`.

## 2. Data

| Data | Where | Notes |
|:--|:--|:--|
| GUIDE corpus v2 | `GUIDE_Dataset/processed/v2/guide_v2_{dev,heldout}.json` (in the repo) | Rebuild with `python -m corpus.build_v2` |
| GUIDE v2 live LLM outputs | `agent/v2_results/` (in the repo) | Recorded live runs (gemini-3.1-flash-lite dev + held-out; gpt-oss-20b dev; undefended agent dev) |
| DEDALE | `<data>/dedale/` | Inria DEDALE, DOI 10.57745/Y5JLDG, CC BY 4.0. Files: `system_logs_labels.zip`, `suricata_alerts.zip`, `system_logs_winlogbeat.zip` (27.1 GB), plus the Zeek router logs used for network labels (`experiments/DEDALE_DATA_NOTES.md`) |
| DEDALE NCE cache | `<data>/runs/nce_cache_host.jsonl` | Recorded live NCE hypotheses per host alert (Phase 3) |

## 3. Steps

1. **Tests:** `HF_HUB_OFFLINE=1 python -m pytest tests experiments -q`
2. **Extract the DEDALE host events** (once, about 1 h): `python -m experiments.dedale_extract_winlogbeat`
3. **C1, GUIDE: re-score the recorded LLM outputs with the current code**
   - `python -m experiments.rescore_v2 agent/v2_results/v2_dev_live_results.json --set dev`
   - `python -m experiments.rescore_v2 agent/v2_results/v2_heldout_live_results.json --set heldout`
   - `python -m experiments.rescore_v2 agent/v2_results/v2_dev_live_groq-openai-gpt-oss-20b_results.json --set dev`
   - Per-family details:
     - `python -m experiments.attack_metrics logs/v2_dev_live_results_rescored.json --set dev`
     - `python -m experiments.undefended_metrics --set dev`
     - `python -m experiments.tamper_structured --set dev`
     - `python -m experiments.era_offline --report`
4. **C2–C5, DEDALE:** `python -m experiments.freeze_dedale --workers 6` runs all 29 replay conditions (about 30–60 min) and scores them into `experiments/dedale_results/final_{host,network}_scores.json`.
5. **The tables:** `python -m experiments.build_results` writes `experiments/RESULTS.md`.

## 4. Determinism

- Replays are deterministic. `freeze_dedale` sets `PYTHONHASHSEED=0`, and two replays with different hash seeds give byte-identical outputs.
- The simulated analyst's mistakes are seeded per case (`--analyst-seed`, default 0).
- In NCE runs, hypotheses come from the recorded cache (`--nce cache`). A cache miss is counted in the run's `summary.json` (`nce_cache_misses`) and the case goes to review unreasoned.

## 5. What cannot be reproduced offline

- **New LLM output.** Re-running NCE live gives different hypotheses: the model is not deterministic, and model versions change. The recorded outputs are the evidence.
- **The comparison runs** (undefended agent; gpt-oss-20b), complete on all 500 dev pairs. Re-running them (`agent/run_v2_undefended.py` / `agent/run_v2_eval.py`) needs API keys and an approved call budget, and gives new LLM output.
