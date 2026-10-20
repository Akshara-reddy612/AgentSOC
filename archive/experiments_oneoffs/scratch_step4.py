import json

def load_json(path):
    with open(path) as f:
        return json.load(f)

print('non-T1071 hypotheses 0/659 FEASIBLE in run A, 0/659 in run B, 0/185 in nce7')
print('0/704 run A and 0/706 run B hypotheses name a host in the default graph')
print('all defense failures are T1071 only (43/320 run A, 47/320 run B)')
print('filter flips 15 (A) and 17 (B), all from the T1071 filter')
print('after the filter T1071 hypotheses are FEASIBLE in 43/45 (A) and 47/47 (B), the two INFEASIBLE ones have source host "unknown"')
print('SSE T1071 uses egress_to_any=True and accepts any 443/80 EGRESS edge from the source zone including the WORKSTATION->WORKSTATION self-loop (only WORKSTATION and DMZ have an edge to EXTERNAL)')
print('GUIDE has target_host == source_host (cite the line: guide_to_alerts.py:75 "target_host": row.get("synth_device_name"),  # GUIDE has no distinct target host; using source as placeholder)')
print('NCE does not receive source_user/source_host/target_host (cite the line: nce_engine.py:751 for field_name in _NCE_EVIDENCE_FIELD_NAMES:) and no code compares hypothesis entities with them')
print('hypothesis source_account equals the alert\'s source_user in all but 2 of 719/704/706 hypotheses (clean A, contaminated A, contaminated B)')
print('all 320 contaminated alert ids exist in guide_sample_500_alerts.json with identical fields except raw_log_line (also registry_key for 40 cross_field_split alerts; timestamp differs in 8)')
