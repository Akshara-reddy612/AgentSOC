import sys; sys.path.insert(0, 'c:/agentsoc')
import json
from perception.nce_engine import _has_external_ip, _has_non_internal_domain, _has_beaconing_command, _BEACONING_PATTERNS, _DOMAIN_RE, _IPV4_RE, _is_private_ip, _INTERNAL_HOSTNAME_PATTERNS, _INTERNAL_DOMAIN_SUFFIXES

def check_predicates(ev):
    ext_ip = False
    domain = False
    beacon = False
    
    beacon_match = None
    beacon_context = None
    
    for v in ev.values():
        if not v: continue
        # IP
        for m in _IPV4_RE.finditer(v):
            if not _is_private_ip(m.group(0)):
                ext_ip = True
        
        # Domain
        for m in _DOMAIN_RE.finditer(v):
            candidate = m.group(0)
            if not _IPV4_RE.fullmatch(candidate) and not _INTERNAL_HOSTNAME_PATTERNS.match(candidate):
                if not any(candidate.lower().endswith(s) for s in _INTERNAL_DOMAIN_SUFFIXES):
                    domain = True

        # Beacon
        bm = _BEACONING_PATTERNS.search(v)
        if bm:
            beacon = True
            beacon_match = bm.group(0)
            start = max(0, bm.start() - 20)
            end = min(len(v), bm.end() + 20)
            beacon_context = v[start:end]

    return ext_ip, domain, beacon, beacon_match, beacon_context

def main():
    with open('GUIDE_Dataset/processed/guide_sample_500_alerts.json', encoding='utf-8') as f:
        clean = {str(a['alert_id']): a for a in json.load(f)}
    
    with open('GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json', encoding='utf-8') as f:
        contam = {str(a['alert_id']): a for a in json.load(f)}
        
    with open('agent/nce_n50_scaleup_results_runA.json', encoding='utf-8') as f:
        run_a = {str(r['alert_id']): r for r in json.load(f)}
        
    with open('agent/nce_n50_scaleup_results_runB.json', encoding='utf-8') as f:
        run_b = {str(r['alert_id']): r for r in json.load(f)}

    def get_ev(a):
        return {k: a.get(k) or '' for k in ['process_name', 'command_line', 'registry_key', 'parent_process', 'file_path', 'raw_log_line']}

    counts = {
        'contam_ip': 0, 'clean_ip': 0,
        'contam_dom': 0, 'clean_dom': 0,
        'contam_beacon': 0, 'clean_beacon': 0,
        'flips': 0
    }
    
    flips_list = []
    clean_beacon_matches = []
    
    runA_feasible_t1071_alerts = []
    for aid, rec in run_a.items():
        if rec.get('nce_error'): continue
        if any(h.get('technique_id') == 'T1071' and h.get('sse_verdict') == 'FEASIBLE' for h in rec.get('sse_results', [])):
            runA_feasible_t1071_alerts.append(aid)
            
    runB_feasible_t1071_alerts = []
    for aid, rec in run_b.items():
        if rec.get('nce_error'): continue
        if any(h.get('technique_id') == 'T1071' and h.get('sse_verdict') == 'FEASIBLE' for h in rec.get('sse_results', [])):
            runB_feasible_t1071_alerts.append(aid)

    runA_pass_only_because_payload = 0
    runB_pass_only_because_payload = 0

    for aid, c_alert in contam.items():
        cl_alert = clean[aid]
        
        c_ev = get_ev(c_alert)
        cl_ev = get_ev(cl_alert)
        
        c_ip, c_dom, c_beac, c_b_m, c_b_ctx = check_predicates(c_ev)
        cl_ip, cl_dom, cl_beac, cl_b_m, cl_b_ctx = check_predicates(cl_ev)
        
        counts['contam_ip'] += int(c_ip)
        counts['clean_ip'] += int(cl_ip)
        counts['contam_dom'] += int(c_dom)
        counts['clean_dom'] += int(cl_dom)
        counts['contam_beacon'] += int(c_beac)
        counts['clean_beacon'] += int(cl_beac)
        
        c_passes = c_ip or c_dom or c_beac
        cl_passes = cl_ip or cl_dom or cl_beac
        
        if c_passes != cl_passes:
            counts['flips'] += 1
            flip_reason = []
            if c_ip != cl_ip: flip_reason.append('IP')
            if c_dom != cl_dom: flip_reason.append('Domain')
            if c_beac != cl_beac: flip_reason.append('Beacon')
            
            flips_list.append({
                'aid': aid,
                'family': c_alert.get('_ground_truth_injection_category', 'unknown'),
                'flipped': flip_reason,
                'match': c_b_m if c_beac else None,
                'context': c_b_ctx if c_beac else None
            })
            
            if aid in runA_feasible_t1071_alerts:
                runA_pass_only_because_payload += 1
            if aid in runB_feasible_t1071_alerts:
                runB_pass_only_because_payload += 1
                
        if cl_beac:
            clean_beacon_matches.append((aid, cl_b_m, cl_b_ctx))

    print(f"3a. Predicate counts over {len(contam)} alerts:")
    print(f"  Contam: IP={counts['contam_ip']}, Domain={counts['contam_dom']}, Beacon={counts['contam_beacon']}")
    print(f"  Clean:  IP={counts['clean_ip']}, Domain={counts['clean_dom']}, Beacon={counts['clean_beacon']}")
    print(f"  Alerts where overall filter outcome flipped: {counts['flips']}")
    
    print(f"\n3b. Filter outcome flips ({len(flips_list)} alerts):")
    for fl in flips_list:
        print(f"  Alert {fl['aid']} (family: {fl['family']}) flipped: {fl['flipped']}. Match: '{fl['match']}', Context: '{fl['context']}'")
        
    print(f"\n3c. Contaminated alerts with surviving T1071 FEASIBLE hypothesis that pass filter ONLY due to injected payload:")
    print(f"  Run A: {runA_pass_only_because_payload}/{len(runA_feasible_t1071_alerts)}")
    print(f"  Run B: {runB_pass_only_because_payload}/{len(runB_feasible_t1071_alerts)}")
    
    print(f"\n3d. Clean alerts passing beacon predicate ({len(clean_beacon_matches)} total):")
    for i, (aid, match, ctx) in enumerate(clean_beacon_matches[:5]):
        print(f"  Alert {aid}, Match '{match}', Context: '{ctx}'")

if __name__ == '__main__':
    main()
