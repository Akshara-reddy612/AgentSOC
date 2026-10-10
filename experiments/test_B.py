import json

def get_alert_info():
    with open('agent/nce_n50_scaleup_results_runB.json', encoding='utf-8') as f:
        run_b = json.load(f)
    with open('agent/nce_n50_scaleup_results_runA.json', encoding='utf-8') as f:
        run_a = json.load(f)
        
    # We want the alert from 3c which is Run B: 1/47.
    # 3c was: Contaminated alerts with surviving T1071 FEASIBLE hypothesis that pass filter ONLY due to injected payload.
    # My previous script used runB_pass_only_because_payload.
    # We need to re-find it.
    
    with open('GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json', encoding='utf-8') as f:
        contam = {str(a['alert_id']): a for a in json.load(f)}
    with open('GUIDE_Dataset/processed/guide_sample_500_alerts.json', encoding='utf-8') as f:
        clean = {str(a['alert_id']): a for a in json.load(f)}
        
    import sys; sys.path.insert(0, 'c:/agentsoc')
    from experiments.analyze_filter_flips import check_predicates
    
    def get_ev(a):
        return {k: a.get(k) or '' for k in ['process_name', 'command_line', 'registry_key', 'parent_process', 'file_path', 'raw_log_line']}

    target_aid = None
    runA_rec = None
    runB_rec = None
    
    for aid, rec in {str(r['alert_id']): r for r in run_b}.items():
        if rec.get('nce_error'): continue
        if any(h.get('technique_id') == 'T1071' and h.get('sse_verdict') == 'FEASIBLE' for h in rec.get('sse_results', [])):
            c_alert = contam[aid]
            cl_alert = clean[aid]
            c_ev = get_ev(c_alert)
            cl_ev = get_ev(cl_alert)
            
            c_ip, c_dom, c_beac, _, _ = check_predicates(c_ev)
            cl_ip, cl_dom, cl_beac, _, _ = check_predicates(cl_ev)
            
            c_passes = c_ip or c_dom or c_beac
            cl_passes = cl_ip or cl_dom or cl_beac
            
            if c_passes and not cl_passes:
                target_aid = aid
                runB_rec = rec
                break
                
    print(f"Target Alert ID: {target_aid}")
    print(f"Is it 962072675970? {target_aid == '962072675970'}")
    
    print("\n--- Run B Record ---")
    print(f"Key Index: {runB_rec.get('key_index')}")
    print("Hypotheses and SSE Verdicts:")
    for h in runB_rec.get('sse_results', []):
        print(f"  Technique: {h.get('technique_id')}, Verdict: {h.get('sse_verdict')}, Conf: {h.get('nce_confidence')}")
        
    # Now Run A
    runA_dict = {str(r['alert_id']): r for r in run_a}
    runA_rec = runA_dict.get(target_aid)
    if runA_rec:
        print("\n--- Run A Record ---")
        print(f"Key Index: {runA_rec.get('key_index')}")
        print("Hypotheses and SSE Verdicts:")
        if runA_rec.get('sse_results'):
            for h in runA_rec.get('sse_results', []):
                print(f"  Technique: {h.get('technique_id')}, Verdict: {h.get('sse_verdict')}, Conf: {h.get('nce_confidence')}")
        else:
            print(f"  sse_results: {runA_rec.get('sse_results')}")
            print(f"  nce_hypotheses_orig: {runA_rec.get('nce_hypotheses_orig')}")
            print(f"  filter drops: {runA_rec.get('evidentiary_filter_drops')}")
            for h in runA_rec.get('nce_hypotheses', []):
                print(f"  (pre-SSE) Technique: {h.get('technique_id')}, Conf: {h.get('nce_confidence')}")

if __name__ == '__main__':
    get_alert_info()
