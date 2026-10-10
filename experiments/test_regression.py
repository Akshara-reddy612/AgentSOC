import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from perception.knowledge_graph import KnowledgeStoreGraph
from perception.sse import StructuralSimulationEngine
from perception.nce_engine import alert_to_nce_input, _apply_t1071_evidentiary_filter
from perception.nce_sse_integration import validate_hypothesis_with_sse
from perception.nce_contract import HypothesisStatus, NCEHypothesis, MissingContextFlag
from experiments.run_paired_clean_eval_B_parallel import _serialize_hypothesis, _serialize_validated

def deserialize_hypothesis(h_dict) -> NCEHypothesis:
    flags = [MissingContextFlag(f) for f in h_dict.get('missing_context_flags', [])]
    return NCEHypothesis(
        technique_id=h_dict['technique_id'],
        source_account=h_dict.get('source_account'),
        source_host=h_dict.get('source_host'),
        target_host=h_dict.get('target_host'),
        nce_confidence=h_dict.get('nce_confidence', 0.0),
        supporting_evidence_refs=set(h_dict.get('supporting_evidence_refs', [])),
        missing_context_flags=flags,
        status=HypothesisStatus(h_dict.get('status', 'GENERATED'))
    )

def main():
    gs = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(gs)

    with open('GUIDE_Dataset/processed/guide_sample_500_alerts.json', encoding='utf-8') as f:
        clean_by_id = {str(a['alert_id']): a for a in json.load(f)}
    
    with open('GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json', encoding='utf-8') as f:
        contam_by_id = {str(a['alert_id']): a for a in json.load(f)}

    files_to_test = [
        ('Clean A', 'experiments/paired_clean_results.json', clean_by_id),
        ('Clean B', 'experiments/paired_clean_results_B.json', clean_by_id),
        ('Contam A', 'agent/nce_n50_scaleup_results_runA.json', contam_by_id),
        ('Contam B', 'agent/nce_n50_scaleup_results_runB.json', contam_by_id)
    ]

    for name, path_str, alerts_by_id in files_to_test:
        with open(path_str, encoding='utf-8') as f:
            records = json.load(f)
            
        passes = 0
        fails = 0
        no_actionable_rescored = 0
        total = 0
        
        for rec in records:
            if rec.get('nce_error'):
                continue
            
            aid = str(rec['alert_id'])
            if aid not in alerts_by_id:
                continue
                
            total += 1
            alert = alerts_by_id[aid]
            nce_input = alert_to_nce_input(alert)

            baseline_hyps = [deserialize_hypothesis(h) for h in rec.get('nce_hypotheses_orig', [])]

            surviving_hyps, drops = _apply_t1071_evidentiary_filter(
                baseline_hyps, nce_input.evidence_fields
            )
            
            validated_filtered = []
            for h in surviving_hyps:
                vh = validate_hypothesis_with_sse(h, sse)
                validated_filtered.append(vh)

            feasible_filtered = sum(1 for vh in validated_filtered
                                    if vh.hypothesis.status == HypothesisStatus.FEASIBLE)
            
            if feasible_filtered == 0:
                no_actionable_rescored += 1
                
            if feasible_filtered == rec.get('sse_feasible_count', 0):
                passes += 1
            else:
                fails += 1
                
        print(f"{name}: Matches={passes}/{total}, Mismatches={fails}/{total}, Rescored No-Actionable={no_actionable_rescored}/{total}")

if __name__ == '__main__':
    main()
