# Manual diagnostic script (NOT a pytest test): read-only analysis, run from the project root.


def main() -> None:
    import sys; from pathlib import Path; sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import json
    import logging
    from perception.nce_engine import (
        _has_external_ip, _has_non_internal_domain, _has_beaconing_command, _apply_t1071_evidentiary_filter
    )
    from perception.nce_contract import NCEHypothesis, MissingContextFlag

    def make_hypothesis(h):
        d = dict(h)
        d['missing_context_flags'] = [
            MissingContextFlag(f) if isinstance(f, str) else f
            for f in d.get('missing_context_flags', [])
        ]
        return NCEHypothesis(**d)

    aid = 962072675970
    with open('GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json', 'r') as f:
        alert = next(a for a in json.load(f) if str(a['alert_id']) == str(aid))

    evidence = {
        'process_name': alert.get('process_name') or '',
        'command_line': alert.get('command_line') or '',
        'registry_key': alert.get('registry_key') or '',
        'parent_process': alert.get('parent_process') or '',
        'file_path': alert.get('file_path') or '',
        'raw_log_line': alert.get('raw_log_line') or ''
    }

    print('has_ext_ip:', _has_external_ip(evidence))
    print('has_domain:', _has_non_internal_domain(evidence))
    print('has_beacon:', _has_beaconing_command(evidence))

    with open('agent/nce_n50_scaleup_results_runB.json', 'r') as f:
        run_b = next(r for r in json.load(f) if str(r['alert_id']) == str(aid))

    hypotheses_b = [make_hypothesis(h) for h in run_b['nce_hypotheses_orig']]
    surviving_b, drops_b = _apply_t1071_evidentiary_filter(hypotheses_b, evidence)
    print(f"Run B drops: {drops_b}")
    print(f"Run B surviving T1071: {[h.technique_id for h in surviving_b if h.technique_id == 'T1071']}")

    with open('agent/nce_n50_scaleup_results_runA.json', 'r') as f:
        run_a = next(r for r in json.load(f) if str(r['alert_id']) == str(aid))

    hypotheses_a = [make_hypothesis(h) for h in run_a['nce_hypotheses_orig']]
    surviving_a, drops_a = _apply_t1071_evidentiary_filter(hypotheses_a, evidence)
    print(f"Run A drops: {drops_a}")
    print(f"Run A surviving T1071: {[h.technique_id for h in surviving_a if h.technique_id == 'T1071']}")


if __name__ == "__main__":
    main()
