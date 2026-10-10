import json
from collections import defaultdict
import os
import sys

def get_families():
    # Try getting families from the ground truth file
    try:
        with open('GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json') as f:
            alerts = json.load(f)
        fam = {}
        for a in alerts:
            family = a.get('_ground_truth_injection_category')
            if not family:
                return None
            fam[str(a['alert_id'])] = family
        if len(fam) == 320:
            return fam
    except Exception as e:
        pass
    
    # Try getting from run A
    try:
        with open('agent/nce_n50_scaleup_results_runA.json') as f:
            runa = json.load(f)
        fam = {}
        for r in runa:
            if r.get('nce_error'): continue
            family = r.get('family') or r.get('injection_category')
            if not family:
                return None
            fam[str(r['alert_id'])] = family
        if len(fam) == 320:
            return fam
    except Exception as e:
        pass
    
    return None

def is_no_actionable(record):
    hyps = record.get('sse_results', [])
    for h in hyps:
        if h.get('sse_verdict') in ('FEASIBLE', 'CONDITIONALLY_FEASIBLE'):
            return False
    return True

families = get_families()
if not families:
    print("NOT FOUND IN REPO")
    sys.exit(0)

# Check all families exist
if len(set(families.values())) != 8:
    pass

counts = {
    'clean_a': defaultdict(int),
    'clean_b': defaultdict(int),
    'contam_a': defaultdict(int),
    'contam_b': defaultdict(int)
}

def populate(path, key):
    with open(path) as f:
        data = json.load(f)
    for r in data:
        if r.get('nce_error'): continue
        aid = str(r['alert_id'])
        if aid not in families: continue
        if is_no_actionable(r):
            counts[key][families[aid]] += 1

populate('experiments/paired_clean_results.json', 'clean_a')
populate('experiments/paired_clean_results_B.json', 'clean_b')
populate('agent/nce_n50_scaleup_results_runA.json', 'contam_a')
populate('agent/nce_n50_scaleup_results_runB.json', 'contam_b')

fam_names = sorted(list(set(families.values())))

# Verify sums
sum_ca = sum(counts['clean_a'].values())
sum_cb = sum(counts['clean_b'].values())
sum_coa = sum(counts['contam_a'].values())
sum_cob = sum(counts['contam_b'].values())

if sum_ca != 275 or sum_cb != 276 or sum_coa != 277 or sum_cob != 273:
    print(f"SUM MISMATCH: Clean A {sum_ca}, Clean B {sum_cb}, Contam A {sum_coa}, Contam B {sum_cob}")

print("Per-Family Table:")
print(f"{'Family':<30} | {'Clean A':<7} | {'Clean B':<7} | {'Contam A':<8} | {'Contam B':<8}")
print("-" * 75)
for f in fam_names:
    print(f"{f:<30} | {counts['clean_a'][f]:<7} | {counts['clean_b'][f]:<7} | {counts['contam_a'][f]:<8} | {counts['contam_b'][f]:<8}")

print("\nLaTeX Tabular:")
print(r"\begin{table}[h]")
print(r"\centering")
print(r"\caption{No-Actionable-Hypothesis Count by Injection Family ($n=40$ each)}")
print(r"\label{tab:paired_clean_family}")
print(r"\begin{tabular}{@{}lcccc@{}}")
print(r"\toprule")
print(r"\textbf{Injection Family} & \textbf{Clean A} & \textbf{Clean B} & \textbf{Contam A} & \textbf{Contam B} \\")
print(r"\midrule")
for f in fam_names:
    print(f"\\texttt{{{f}}} & {counts['clean_a'][f]} & {counts['clean_b'][f]} & {counts['contam_a'][f]} & {counts['contam_b'][f]} \\\\")
print(r"\bottomrule")
print(r"\end{tabular}")
print(r"\end{table}")
