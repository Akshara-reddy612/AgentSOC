"""Step 2: verify clean-corpus pre/post-filter actionable counts."""
import json, sys
sys.path.insert(0, '.')
from pathlib import Path

# ---- helpers ----
FEASIBLE_SET = {'FEASIBLE', 'CONDITIONALLY_FEASIBLE'}

def count_pre_post(records):
    """
    Returns (total_no_error, pre_actionable, post_actionable).
    Pre uses sse_results_orig; post uses sse_results.
    If sse_results_orig absent, pre is NOT AVAILABLE.
    """
    total = 0
    pre_act = 0
    post_act = 0
    pre_available = True
    for r in records:
        if r.get('nce_error'):
            continue
        total += 1
        if 'sse_results_orig' not in r:
            pre_available = False
        else:
            if any(h.get('sse_verdict') in FEASIBLE_SET for h in r.get('sse_results_orig', [])):
                pre_act += 1
        if any(h.get('sse_verdict') in FEASIBLE_SET for h in r.get('sse_results', [])):
            post_act += 1
    return total, pre_act if pre_available else None, post_act

# ---- nce8 n=50 ----
with open('agent/nce8_clean_fp_results.json') as f:
    nce8 = json.load(f)
t8, pre8, post8 = count_pre_post(nce8)
pre8_str = str(pre8) if pre8 is not None else 'N/A'
print(f'nce8 (n=50): total_no_error={t8}, pre-filter actionable={pre8_str}/{t8}, post-filter actionable={post8}/{t8}')

# ---- nce7 clean subset n=10 ----
with open('agent/nce7_scale_results.json') as f:
    nce7_all = json.load(f)
nce7_clean = [r for r in nce7_all if r.get('family') == 'clean']
t7, pre7, post7 = count_pre_post(nce7_clean)
pre7_str = str(pre7) if pre7 is not None else 'NOT AVAILABLE (no sse_results_orig field in nce7)'
print(f'nce7 clean (n=10): total_no_error={t7}, pre-filter actionable={pre7_str}, post-filter actionable={post7}/{t7}')

# ---- combined 60 ----
pre_total = (pre8 or 0) + (pre7 or 0)
post_total = (post8 or 0) + (post7 or 0)
n_total = t8 + t7
print()
print(f'Combined (n={n_total}):')
if pre8 is not None and pre7 is not None:
    print(f'  pre-filter actionable:  {pre_total}/{n_total} = {pre_total/n_total*100:.1f}%  ({pre_total}/{n_total})')
else:
    print(f'  pre-filter: nce8 gives {pre8}/{t8}; nce7 pre NOT AVAILABLE')
print(f'  post-filter actionable: {post_total}/{n_total} = {post_total/n_total*100:.1f}%  ({post_total}/{n_total})')
