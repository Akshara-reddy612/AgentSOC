import json
from pathlib import Path
import sys

sys.path.insert(0, r"c:\agentsoc")

from perception.nce_engine import (
    _apply_t1071_evidentiary_filter,
    alert_to_nce_input,
)
from perception.nce_contract import NCEHypothesis, HypothesisStatus, MissingContextFlag
from perception.sse import StructuralSimulationEngine
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_sse_integration import validate_hypothesis_with_sse

# 12 REASONABLE cases documented in t1071_mislabeling_investigation.md
REASONABLE_12 = {
    "1271310323428", "146028890043", "146028890070", "1477468753553",
    "1537598292006", "1554778165988", "1692217116989", "309237646731",
    "558345752206", "566935687271", "652835033867", "712964575175"
}

# 4 QUESTIONABLE cases documented in t1071_mislabeling_investigation.md
QUESTIONABLE_4 = {
    "1623497664426", "1108101567282", "1322849930226", "1486058474261"
}

heldout = {str(a["alert_id"]): a for a in json.loads(Path("GUIDE_Dataset/processed/guide_heldout_140_alerts.json").read_text(encoding="utf-8"))}
sample500 = {str(a["alert_id"]): a for a in json.loads(Path("GUIDE_Dataset/processed/guide_sample_500_alerts.json").read_text(encoding="utf-8"))}

def get_alert(aid):
    if aid in heldout: return heldout[aid]
    if aid in sample500: return sample500[aid]
    raise ValueError(f"Alert {aid} not found")

scale_results = json.loads(Path("agent/nce7_scale_results.json").read_text(encoding="utf-8"))

flag_lookup = {f.value: f for f in MissingContextFlag}

def reconstruct_hypotheses(h_dicts):
    hyps = []
    for h_dict in h_dicts:
        flags = [flag_lookup[f] for f in h_dict.get("missing_context_flags", []) if f in flag_lookup]
        hyps.append(NCEHypothesis(
            technique_id=h_dict["technique_id"],
            source_account=h_dict["source_account"],
            source_host=h_dict.get("source_host", "unknown"),
            target_host=h_dict.get("target_host", "unknown"),
            nce_confidence=h_dict["nce_confidence"],
            supporting_evidence_refs=list(h_dict.get("supporting_evidence_refs", [])),
            missing_context_flags=flags,
            status=HypothesisStatus.GENERATED,
            incident_id=h_dict.get("incident_id"),
        ))
    return hyps

gs = KnowledgeStoreGraph()
sse = StructuralSimulationEngine(gs)

# Check scale results
print("="*80)
print("ANALYZING SCALE RESULTS (n=90: 80 contaminated + 10 clean)")
print("="*80)

dropped_t1071_alerts = []
dropped_reasonable = []

per_family_stats = {} # family -> {total, success_orig, success_new}

for r in scale_results:
    aid = str(r["alert_id"])
    family = r["family"]
    alert = get_alert(aid)
    nce_in = alert_to_nce_input(alert)
    
    orig_hyps = reconstruct_hypotheses(r.get("nce_hypotheses", []))
    surviving_hyps, drops = _apply_t1071_evidentiary_filter(orig_hyps, nce_in.evidence_fields)
    
    had_t1071 = any(h.technique_id == "T1071" for h in orig_hyps)
    t1071_dropped = any(h.technique_id == "T1071" for h in orig_hyps) and not any(h.technique_id == "T1071" for h in surviving_hyps)
    
    if t1071_dropped:
        dropped_t1071_alerts.append((aid, family, drops))
        if aid in REASONABLE_12:
            dropped_reasonable.append((aid, family, drops))
            
    # Compute SSE on surviving
    # If no surviving hypotheses, SSE is trivially defended (0 feasible)
    feasible_count = 0
    infeasible_count = 0
    for h in surviving_hyps:
        vh = validate_hypothesis_with_sse(h, sse)
        if vh.best_sse_verdict.value == "FEASIBLE":
            feasible_count += 1
        elif vh.best_sse_verdict.value == "INFEASIBLE":
            infeasible_count += 1
            
    # For contaminated alerts: structural_defense_success means NO feasible hypotheses (or 0 feasible)
    new_success = (feasible_count == 0)
    orig_success = r.get("structural_defense_success")
    
    if family == "clean":
        pass  # Handled separately below
    else:
        if family not in per_family_stats:
            per_family_stats[family] = {"total": 0, "orig_success": 0, "new_success": 0}
        per_family_stats[family]["total"] += 1
        if orig_success:
            per_family_stats[family]["orig_success"] += 1
        if new_success:
            per_family_stats[family]["new_success"] += 1

print(f"\nTotal T1071 hypotheses dropped in scale set (n=90): {len(dropped_t1071_alerts)}")
for aid, fam, drops in dropped_t1071_alerts:
    is_q = aid in QUESTIONABLE_4
    is_r = aid in REASONABLE_12
    print(f"  Alert {aid} ({fam}): Q={is_q}, R={is_r}")
    print(f"    Drops: {drops}")

print(f"\nWere any of the 12 REASONABLE cases dropped? {len(dropped_reasonable)} dropped: {dropped_reasonable}")

print("\nPER-FAMILY BREAKDOWN (CONTAMINATED, n=80):")
total_orig = 0
total_new = 0
contam_total = 0
for fam in ["fabricated_evidence", "cross_field_split", "authority_escalation", "direct_override", 
            "zero_imperative_evidence", "native_format_mimicry", "fake_output_injection", "obfuscated_trigger"]:
    stats = per_family_stats[fam]
    contam_total += stats["total"]
    total_orig += stats["orig_success"]
    total_new += stats["new_success"]
    print(f"  {fam:26s}: n={stats['total']} | Orig={stats['orig_success']} ({stats['orig_success']/stats['total']*100:.1f}%) | New={stats['new_success']} ({stats['new_success']/stats['total']*100:.1f}%)")

print(f"\nOVERALL CONTAMINATED STRUCTURAL DEFENSE RATE:")
print(f"  Original: {total_orig}/{contam_total} ({total_orig/contam_total*100:.1f}%)")
print(f"  New:      {total_new}/{contam_total} ({total_new/contam_total*100:.1f}%)")

# Calculate clean stats for scale set (n=10)
scale_clean_records = [r for r in scale_results if r.get("family") == "clean"]
scale_clean_orig_feasible = 0
scale_clean_new_feasible = 0
scale_clean_dropped = []
for r in scale_clean_records:
    aid = str(r["alert_id"])
    alert = get_alert(aid)
    nce_in = alert_to_nce_input(alert)
    orig_hyps = reconstruct_hypotheses(r.get("nce_hypotheses", []))
    surviving_hyps, drops = _apply_t1071_evidentiary_filter(orig_hyps, nce_in.evidence_fields)
    
    if r.get("sse_feasible_count", 0) > 0:
        scale_clean_orig_feasible += 1
        
    new_feasible_count = sum(1 for h in surviving_hyps if validate_hypothesis_with_sse(h, sse).best_sse_verdict.value == "FEASIBLE")
    if new_feasible_count > 0:
        scale_clean_new_feasible += 1
        
    had_t1071 = any(h.technique_id == "T1071" for h in orig_hyps)
    t1071_dropped = had_t1071 and not any(h.technique_id == "T1071" for h in surviving_hyps)
    if t1071_dropped:
        scale_clean_dropped.append((aid, drops))

print(f"\nSCALE CLEAN (n=10):")
print(f"  Original FEASIBLE: {scale_clean_orig_feasible}/10")
print(f"  New FEASIBLE:      {scale_clean_new_feasible}/10")
print(f"  Dropped T1071 count: {len(scale_clean_dropped)}")
for aid, drops in scale_clean_dropped:
    print(f"    Clean Alert {aid}: {drops}")

# Now check NCE-8 clean alerts (n=50)
print("\n" + "="*80)
print("ANALYZING NCE-8 CLEAN ALERTS (n=50)")
print("="*80)
nce8_file = Path("agent/nce8_clean_fp_results.json")
if nce8_file.exists():
    nce8_results = json.loads(nce8_file.read_text(encoding="utf-8"))
    print(f"Loaded {len(nce8_results)} NCE-8 clean records.")
    
    nce8_orig_feasible = 0
    nce8_new_feasible = 0
    nce8_dropped = []
    
    for r in nce8_results:
        aid = str(r["alert_id"])
        alert = get_alert(aid)
        nce_in = alert_to_nce_input(alert)
        orig_hyps = reconstruct_hypotheses(r.get("nce_hypotheses", []))
        surviving_hyps, drops = _apply_t1071_evidentiary_filter(orig_hyps, nce_in.evidence_fields)
        
        # Check original feasible from record
        if r.get("sse_feasible_count", 0) > 0:
            nce8_orig_feasible += 1
            
        new_feasible_count = 0
        for h in surviving_hyps:
            vh = validate_hypothesis_with_sse(h, sse)
            if vh.best_sse_verdict.value == "FEASIBLE":
                new_feasible_count += 1
        if new_feasible_count > 0:
            nce8_new_feasible += 1
            
        had_t1071 = any(h.technique_id == "T1071" for h in orig_hyps)
        t1071_dropped = had_t1071 and not any(h.technique_id == "T1071" for h in surviving_hyps)
        if t1071_dropped:
            nce8_dropped.append((aid, drops))
            
    print(f"NCE-8 clean (n=50): Orig FEASIBLE = {nce8_orig_feasible}/50, New FEASIBLE = {nce8_new_feasible}/50")
    print(f"NCE-8 dropped T1071 count: {len(nce8_dropped)}")
    for aid, drops in nce8_dropped:
        print(f"    Clean Alert {aid}: {drops}")
        
    total_clean_orig_feasible = scale_clean_orig_feasible + nce8_orig_feasible
    total_clean_new_feasible = scale_clean_new_feasible + nce8_new_feasible
    print(f"\nTOTAL CLEAN (n=60: 10 scale + 50 nce8):")
    print(f"  Original T1071 FEASIBLE: {total_clean_orig_feasible}/60 ({total_clean_orig_feasible/60*100:.1f}%)")
    print(f"  New T1071 FEASIBLE:      {total_clean_new_feasible}/60 ({total_clean_new_feasible/60*100:.1f}%)")

