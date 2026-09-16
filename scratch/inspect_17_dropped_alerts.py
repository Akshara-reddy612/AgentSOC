import sys
sys.path.insert(0, r"c:\agentsoc")
import json
from pathlib import Path
from perception.nce_engine import alert_to_nce_input

heldout = {str(a["alert_id"]): a for a in json.loads(Path("GUIDE_Dataset/processed/guide_heldout_140_alerts.json").read_text(encoding="utf-8"))}
sample500 = {str(a["alert_id"]): a for a in json.loads(Path("GUIDE_Dataset/processed/guide_sample_500_alerts.json").read_text(encoding="utf-8"))}

def get_alert(aid):
    if aid in heldout: return heldout[aid]
    if aid in sample500: return sample500[aid]
    raise ValueError(f"Alert {aid} not found")

CONTAMINATED_7 = [
    "1116691498166", "1185410975231", "1374389536962",
    "455266536788", "833223657293", "858993461383", "8589936265"
]

CLEAN_10 = [
    "1108101562368", "1597727837376", "1614907703806", "171798691841",
    "395136991850", "566935684681", "584115555473", "584115556518",
    "936302871568", "962072675584"
]

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

def inspect_alert(aid, category):
    print("=" * 80)
    print(f"[{category}] ALERT ID: {aid}")
    print("=" * 80)
    alert = get_alert(aid)
    nce_in = alert_to_nce_input(alert)
    for k, v in nce_in.evidence_fields.items():
        if v:
            clean_v = v.replace("\r", " ").replace("\n", " ")
            print(f"  {k}: {clean_v}")
        else:
            print(f"  {k}: <EMPTY>")
    print()

print("CONTAMINATED ALERTS (7):")
for aid in CONTAMINATED_7:
    inspect_alert(aid, "CONTAMINATED")

print("\nCLEAN ALERTS (10):")
for aid in CLEAN_10:
    inspect_alert(aid, "CLEAN")
