# Archived: the Streamlit demo

Retired on 2026-10-19 and replaced by the demo server (`python -m soc_server`) and the React frontend (`frontend/`). See the main README.

What is here:

| File | What it was |
|:--|:--|
| `streamlit_app.py` | Walkthrough of seven curated GUIDE scenarios (NCE -> SSE -> RSEM -> action layer), replayed from saved results |
| `dashboard.py` | Its "Live monitoring" tab, formerly `monitoring/dashboard.py`. The rest of `monitoring/` is still in place and tested. |
| `verify_demo_scenarios.py` | Checks that the seven scenarios load, formerly `scratch/verify_demo_scenarios.py` |
| `.streamlit/config.toml` | Its theme |

It is kept so the earlier demo can still be shown. It is not maintained.

`verify_demo_scenarios.py` passes 4 of 7 scenarios, the same as before archiving. Scenarios 2, 4 and 5 expect RSEM top actions that the pipeline no longer produces, because it has changed since they were curated.

To run it from this folder, where the config is picked up:

```
cd archive/streamlit
streamlit run streamlit_app.py
python verify_demo_scenarios.py
```
