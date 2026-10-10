"""Step 4 audit counts — read-only, no API calls."""
import json, sys
sys.path.insert(0, '.')
from perception.nce_contract import HypothesisStatus

# --- helpers ---
FEASIBLE_SET = {'FEASIBLE', 'CONDITIONALLY_FEASIBLE'}

def load_json(path):
    with open(path) as f:
        return json.load(f)

def is_default_graph_host(name):
    """Very rough check: default KnowledgeStoreGraph seeds specific named hosts."""
    if not name or name in ('unknown', 'N/A', ''):
        return False
    # The seeded hostnames are those in knowledge_graph.py seed data
    # We'll check by importing
    return None  # handled separately

ra = load_json('agent/nce_n50_scaleup_results_runA.json')
rb = load_json('agent/nce_n50_scaleup_results_runB.json')
nce7 = load_json('agent/nce7_scale_results.json')
nce7_contam = [r for r in nce7 if r.get('family') != 'clean']

# --- non-T1071 FEASIBLE counts ---
def non_t1071_feasible(records, sse_field='sse_results'):
    total_hyps = 0
    feas = 0
    for r in records:
        if r.get('nce_error'): continue
        for h in r.get(sse_field, []):
            if h.get('technique_id') != 'T1071':
                total_hyps += 1
                if h.get('sse_verdict') in FEASIBLE_SET:
                    feas += 1
    return total_hyps, feas

th_a, fa = non_t1071_feasible(ra)
th_b, fb = non_t1071_feasible(rb)
th_7, f7 = non_t1071_feasible(nce7_contam)
print(f'Non-T1071 hypotheses / FEASIBLE:')
print(f'  Run A: {th_a} hypotheses, {fa} FEASIBLE')
print(f'  Run B: {th_b} hypotheses, {fb} FEASIBLE')
print(f'  nce7 contam: {th_7} hypotheses, {f7} FEASIBLE')
total_hyps = th_a + th_b + th_7
total_feas = fa + fb + f7
print(f'  TOTAL: {total_hyps} hypotheses, {total_feas} FEASIBLE')

# --- All defense failures are T1071 only ---
def defense_failures(records, sse_field='sse_results'):
    failures = 0
    for r in records:
        if r.get('nce_error'): continue
        if any(h.get('sse_verdict') in FEASIBLE_SET for h in r.get(sse_field, [])):
            failures += 1
    return failures

def defense_failures_non_t1071(records, sse_field='sse_results'):
    failures = 0
    for r in records:
        if r.get('nce_error'): continue
        if any(h.get('sse_verdict') in FEASIBLE_SET and h.get('technique_id') != 'T1071'
               for h in r.get(sse_field, [])):
            failures += 1
    return failures

fa_total = defense_failures(ra)
fb_total = defense_failures(rb)
fa_nont1071 = defense_failures_non_t1071(ra)
fb_nont1071 = defense_failures_non_t1071(rb)
total_A = sum(1 for r in ra if not r.get('nce_error'))
total_B = sum(1 for r in rb if not r.get('nce_error'))
print(f'\nDefense failures (post-filter actionable):')
print(f'  Run A: {fa_total}/{total_A} total, {fa_nont1071}/{total_A} non-T1071')
print(f'  Run B: {fb_total}/{total_B} total, {fb_nont1071}/{total_B} non-T1071')

# --- filter flips (pre -> post) ---
def filter_flip_count(records):
    """alerts that went from FEASIBLE pre to no-FEASIBLE post, or vice versa"""
    flips = 0
    for r in records:
        if r.get('nce_error'): continue
        pre = any(h.get('sse_verdict') in FEASIBLE_SET for h in r.get('sse_results_orig', []))
        post = any(h.get('sse_verdict') in FEASIBLE_SET for h in r.get('sse_results', []))
        if pre != post:
            flips += 1
    return flips

fa_flips = filter_flip_count(ra)
fb_flips = filter_flip_count(rb)
print(f'\nFilter flips (FEASIBLE status changed pre->post filter):')
print(f'  Run A: {fa_flips}/320')
print(f'  Run B: {fb_flips}/320')

# --- after filter, T1071 FEASIBLE alerts: how many have ALL T1071 hyps passing? ---
def t1071_feasible_stats(records, sse_field='sse_results'):
    # How many alerts have at least one T1071 hypothesis in sse_results?
    has_t1071_surviving = 0
    t1071_feasible = 0
    t1071_surviving_total = 0
    for r in records:
        if r.get('nce_error'): continue
        t1071_hyps = [h for h in r.get(sse_field, []) if h.get('technique_id') == 'T1071']
        if t1071_hyps:
            has_t1071_surviving += 1
            t1071_surviving_total += len(t1071_hyps)
            if any(h.get('sse_verdict') in FEASIBLE_SET for h in t1071_hyps):
                t1071_feasible += 1
    return has_t1071_surviving, t1071_feasible, t1071_surviving_total

a_surv, a_feas, a_tot = t1071_feasible_stats(ra)
b_surv, b_feas, b_tot = t1071_feasible_stats(rb)
print(f'\nT1071 post-filter stats:')
print(f'  Run A: {a_surv} alerts with surviving T1071 hyp, {a_feas} FEASIBLE ({a_feas}/{a_surv})')
print(f'  Run B: {b_surv} alerts with surviving T1071 hyp, {b_feas} FEASIBLE ({b_feas}/{b_surv})')
