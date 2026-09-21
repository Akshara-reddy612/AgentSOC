import sys
sys.path.insert(0, '.')
import json
import random
from collections import defaultdict
from perception.nce_engine import (
    _has_external_ip, _has_non_internal_domain, _has_beaconing_command,
    _IPV4_RE, _is_private_ip, _DOMAIN_RE, _BEACONING_PATTERNS,
    _INTERNAL_HOSTNAME_PATTERNS, _INTERNAL_DOMAIN_SUFFIXES,
    alert_to_nce_input
)

data = json.load(open('agent/nce_n50_scaleup_results.json'))
raw_alerts = json.load(open('GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json'))
raw_map = {str(a['alert_id']): a for a in raw_alerts}

post_filter_undefended = [r for r in data if not r['structural_defense_success']]

by_family = defaultdict(list)
for r in post_filter_undefended:
    by_family[r['family']].append(r)

rng = random.Random(53)
sampled = []
for fam in sorted(by_family.keys()):
    k = 1 if fam == 'authority_escalation' else 2
    items = sorted(by_family[fam], key=lambda x: str(x['alert_id']))
    chosen = rng.sample(items, k)
    sampled.extend(chosen)

out_lines = []
out_lines.append(f"Total post-filter undefended: {len(post_filter_undefended)}")
out_lines.append(f"Sampled {len(sampled)} alerts across {len(by_family)} families (seed=53):\n")

for idx, item in enumerate(sampled, 1):
    aid = str(item['alert_id'])
    fam = item['family']
    raw = raw_map[aid]
    
    nce_input = alert_to_nce_input(raw)
    ef = nce_input.evidence_fields
    
    ext_ips = []
    domains = []
    beacons = []
    
    for f_name, val in ef.items():
        if not val:
            continue
        for m in _IPV4_RE.finditer(val):
            ip = m.group(0)
            if not _is_private_ip(ip):
                ext_ips.append((f_name, ip))
        for m in _DOMAIN_RE.finditer(val):
            dom = m.group(0)
            if not _IPV4_RE.fullmatch(dom):
                if not _INTERNAL_HOSTNAME_PATTERNS.match(dom) and not any(dom.lower().endswith(s) for s in _INTERNAL_DOMAIN_SUFFIXES):
                    domains.append((f_name, dom))
        for m in _BEACONING_PATTERNS.finditer(val):
            beacons.append((f_name, m.group(0)))
            
    # Evaluation: Does it genuinely contain real network/C2 evidence?
    # True C2 evidence: external IP or public domain or beaconing tool/URL.
    # Check if the trigger is genuine network/C2 or benign artifact / injection trick
    out_lines.append(f"### [{idx}/15] Alert `{aid}` | Family: `{fam}`")
    out_lines.append(f"- **Surviving Hypotheses**: `{[h['technique_id'] for h in item['nce_hypotheses']]}`")
    out_lines.append(f"- **SSE Verdicts**: `{[s.get('sse_verdict') or s.get('status') for s in item['sse_results']]}`")
    out_lines.append(f"- **Filter Trigger Signals**:")
    out_lines.append(f"  - External IPs: `{ext_ips}`")
    out_lines.append(f"  - Domains: `{domains}`")
    out_lines.append(f"  - Beaconing Patterns: `{beacons}`")
    out_lines.append(f"- **Raw Evidence Fields**:")
    for k, v in ef.items():
        if v:
            out_lines.append(f"  - `{k}`: {repr(v)}")
    out_lines.append("")

output_text = "\n".join(out_lines)
with open("scratch/spot_check_report.md", "w", encoding="utf-8") as f:
    f.write(output_text)
print("Report written to scratch/spot_check_report.md")
