import json, sys
sys.path.insert(0, '.')
with open('agent/nce_n50_scaleup_results_runA.json') as f:
    ra = {str(r['alert_id']): r for r in json.load(f)}
with open('agent/nce_n50_scaleup_results_runB.json') as f:
    rb = {str(r['alert_id']): r for r in json.load(f)}

aid = '962072675970'
for name, d in [('Run A', ra), ('Run B', rb)]:
    for h in d[aid].get('nce_hypotheses_orig', []):
        if h['technique_id'] == 'T1071':
            sh = h['source_host']
            th = h['target_host']
            print(name, 'nce_hypotheses_orig T1071: source_host=' + repr(sh) + ' target_host=' + repr(th))
    for h in d[aid].get('sse_results', []):
        if h['technique_id'] == 'T1071':
            sh = h['source_host']
            th = h['target_host']
            sv = h['sse_verdict']
            print(name, 'sse_results T1071: source_host=' + repr(sh) + ' target_host=' + repr(th) + ' verdict=' + repr(sv))
