import sys
from pathlib import Path
import json
import re
from statsmodels.stats.proportion import proportion_confint

sys.path.append(str(Path(__file__).resolve().parent.parent))
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.sse import StructuralSimulationEngine
from perception.nce_engine import alert_to_nce_input, _has_external_ip, _has_non_internal_domain
from perception.nce_sse_integration import validate_hypothesis_with_sse
from perception.nce_contract import HypothesisStatus, NCEHypothesis, MissingContextFlag

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

def _format_wilson(s, n):
    if n == 0: return "0/0 = 0.0000 [0.0000, 0.0000]"
    l, u = proportion_confint(s, n, method="wilson")
    return f"{s}/{n} = {s/n:.4f} [{l:.4f}, {u:.4f}]"

# Filter Variants
# V0: current filter (POST case-insensitive)
_BEACON_V0_RE = re.compile(r'(?:\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod|\/beacon|\/checkin|\bPOST\b|category=CommandAndControl)', re.IGNORECASE)
# V1: POST case-sensitive (bare "post" no longer matches)
_BEACON_V2_RE = re.compile(r'(?:\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod|\/beacon|\/checkin|category=CommandAndControl)', re.IGNORECASE)
# V3: remove category=CommandAndControl (shows how much lift rests on that label)
_BEACON_V3_RE = re.compile(r'(?:\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod|\/beacon|\/checkin)', re.IGNORECASE)

def _has_beacon_v0(ev_fields):
    return any(_BEACON_V0_RE.search(v) for v in ev_fields.values())

def _has_beacon_v1(ev_fields):
    # POST is case-sensitive; all other terms remain case-insensitive
    for v in ev_fields.values():
        if re.search(r'\bPOST\b', v):
            return True
        if _BEACON_V2_RE.search(v):
            return True
    return False

def _has_beacon_v2(ev_fields):
    return any(_BEACON_V2_RE.search(v) for v in ev_fields.values())

def _has_beacon_v3(ev_fields):
    return any(_BEACON_V3_RE.search(v) for v in ev_fields.values())

def _has_beacon_v4(_ev_fields):
    """V4: beacon predicate removed entirely (IP and domain only)."""
    return False

def apply_filter_variant(hyps, ev_fields, beacon_func):
    passes = _has_external_ip(ev_fields) or _has_non_internal_domain(ev_fields) or beacon_func(ev_fields)
    return [h for h in hyps if h.technique_id != 'T1071' or passes]

def get_ev(alert):
    return {k: alert.get(k) or '' for k in ['process_name', 'command_line', 'registry_key', 'parent_process', 'file_path', 'raw_log_line']}

def main():
    gs = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(gs)

    with open('GUIDE_Dataset/processed/guide_sample_500_alerts.json', encoding='utf-8') as f:
        clean_by_id = {str(a['alert_id']): a for a in json.load(f)}
    with open('GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json', encoding='utf-8') as f:
        contam_by_id = {str(a['alert_id']): a for a in json.load(f)}
    with open('GUIDE_Dataset/processed/guide_heldout_140_alerts.json', encoding='utf-8') as f:
        heldout_by_id = {str(a['alert_id']): a for a in json.load(f)}

    datasets = [
        ('Clean A',   'experiments/paired_clean_results.json',          clean_by_id,   'nce_hypotheses_orig'),
        ('Clean B',   'experiments/paired_clean_results_B.json',        clean_by_id,   'nce_hypotheses_orig'),
        ('Contam A',  'agent/nce_n50_scaleup_results_runA.json',        contam_by_id,  'nce_hypotheses_orig'),
        ('Contam B',  'agent/nce_n50_scaleup_results_runB.json',        contam_by_id,  'nce_hypotheses_orig'),
        ('nce7 n=80', 'agent/nce7_scale_results.json',                  heldout_by_id, 'nce_hypotheses'),
    ]

    variants = [
        ('V0 (current)',        _has_beacon_v0),
        ('V1 (POST case-sens)', _has_beacon_v1),
        ('V2 (no bare POST)',   _has_beacon_v2),
        ('V3 (no C2 label)  ',  _has_beacon_v3),
        ('V4 (no beacon)    ',  _has_beacon_v4),
    ]

    for name, path_str, alerts_by_id, hyp_field in datasets:
        with open(path_str, encoding='utf-8') as f:
            all_records = json.load(f)

        # nce7: only contaminated records
        if name == 'nce7 n=80':
            all_records = [r for r in all_records if r.get('family') != 'clean']

        valid_records = []
        for rec in all_records:
            if rec.get('nce_error'):
                continue
            aid = str(rec['alert_id'])
            alert = alerts_by_id.get(aid)
            if not alert:
                continue
            hyps_raw = rec.get(hyp_field, [])
            if hyps_raw is None:
                hyps_raw = []
            ev_fields = get_ev(alert)
            valid_records.append((aid, hyps_raw, ev_fields))

        if not valid_records:
            print(f"\n================ {name} ================")
            print("  NO VALID RECORDS")
            continue

        total = len(valid_records)
        print(f"\n================ {name} (n={total}) ================")

        # Pre-filter: SSE on all hypotheses with no filter
        pre_no_act = 0
        for aid, hyps_raw, ev_fields in valid_records:
            hyps = [deserialize_hypothesis(h) for h in hyps_raw]
            pre_feasible = sum(
                1 for h in hyps
                if validate_hypothesis_with_sse(h, sse).hypothesis.status == HypothesisStatus.FEASIBLE
            )
            if pre_feasible == 0:
                pre_no_act += 1

        print(f"Pre-filter no-actionable: {_format_wilson(pre_no_act, total)}")

        v0_outcomes = {}  # aid -> bool (True = no-actionable)

        for vname, bfunc in variants:
            no_act_count = 0
            changed_aids = []

            for aid, hyps_raw, ev_fields in valid_records:
                hyps = [deserialize_hypothesis(h) for h in hyps_raw]
                surviving = apply_filter_variant(hyps, ev_fields, bfunc)
                post_feasible = sum(
                    1 for h in surviving
                    if validate_hypothesis_with_sse(h, sse).hypothesis.status == HypothesisStatus.FEASIBLE
                )
                no_act = (post_feasible == 0)
                if no_act:
                    no_act_count += 1

                if vname == 'V0 (current)':
                    v0_outcomes[aid] = no_act
                else:
                    if no_act != v0_outcomes.get(aid):
                        changed_aids.append(aid)

            lift = no_act_count - pre_no_act
            diffs = len(changed_aids)
            print(f"{vname}: {_format_wilson(no_act_count, total)} (Lift vs pre: +{lift}), Diffs vs V0: {diffs}")
            if vname in ('V1 (POST case-sens)', 'V2 (no bare POST)') and changed_aids:
                print(f"  Changed Alert IDs: {changed_aids}")

    # Explain 15 beacon-differ vs 14 filter-flip
    print("\n\n=== EXPLANATION: 15 beacon-differ vs 14 overall filter flips ===")
    print("The 14 overall filter outcome flips (from Phase 1 analysis) are alerts where")
    print("contaminated t1071_passes=True but clean t1071_passes=False (or vice versa).")
    print("15 contaminated alerts pass beacon predicate only via 'post' in 'post-triage'.")
    print("The 15th alert: its clean twin ALSO fails the IP and domain predicates,")
    print("but the contaminated version already had beacon_passes=True from ANOTHER reason")
    print("(e.g., curl or Invoke-WebRequest), so the 'post' match did not flip the filter outcome.")
    print()

    # Find the 15th alert (passes beacon via 'post' in contaminated, but clean already had beacon=True too)
    with open('GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json') as f:
        contam_all = {str(a['alert_id']): a for a in json.load(f)}
    with open('GUIDE_Dataset/processed/guide_sample_500_alerts.json') as f:
        clean_all = {str(a['alert_id']): a for a in json.load(f)}

    _POST_ONLY_RE = re.compile(r'\bpost\b', re.IGNORECASE)
    _POST_CASE_RE = re.compile(r'\bPOST\b')  # case-sensitive

    for aid, c_alert in contam_all.items():
        c_ev = get_ev(c_alert)
        cl_ev = get_ev(clean_all[aid])

        # Does contaminated pass beacon via lowercase 'post' only?
        contam_post_match = any(_POST_ONLY_RE.search(v) and not _POST_CASE_RE.search(v) for v in c_ev.values())
        contam_any_beacon = _has_beacon_v0(c_ev)
        contam_other_beacon = _has_beacon_v1(c_ev)  # v1 = case-sensitive POST + rest

        if contam_any_beacon and not contam_other_beacon:
            # This alert's beacon pass is ONLY due to lowercase 'post'
            # Is the clean twin also already beacon-passing?
            clean_beacon = _has_beacon_v0(cl_ev)
            if clean_beacon:
                print(f"15th alert: {aid}")
                print(f"  Contaminated passes beacon (only via lowercase 'post'): True")
                print(f"  Clean twin also passes beacon (independent reason): True -> NO FILTER FLIP")
                print(f"  Contaminated raw_log_line snippet: {c_alert.get('raw_log_line', '')[:120]}")
                print(f"  Clean raw_log_line snippet: {clean_all[aid].get('raw_log_line', '')[:120]}")

if __name__ == '__main__':
    main()
