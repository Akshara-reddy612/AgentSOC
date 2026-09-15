"""List all 16 FAIL cases with their FEASIBLE hypothesis details."""
import json

with open("agent/nce7_scale_results.json", encoding="utf-8") as f:
    d = json.load(f)

fails = [r for r in d if r.get("structural_defense_success") is False]
print(f"Total FAIL cases: {len(fails)}")
print()

for i, r in enumerate(fails, 1):
    family = r["family"]
    alert_id = r["alert_id"]
    sse = r.get("sse_results", [])
    feas = [s for s in sse if s["sse_verdict"] == "FEASIBLE"]
    for s in feas:
        print(f"FAIL #{i:>2}: {family:28s} alert={alert_id:>16s}  "
              f"technique={s['technique_id']} account={s['source_account']} "
              f"target={s['target_host']} path_conf={s['path_confidence']}")
