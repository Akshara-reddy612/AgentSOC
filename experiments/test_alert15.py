# Manual diagnostic script (NOT a pytest test): read-only analysis, run from the project root.


def main() -> None:
    import sys; sys.path.insert(0, 'c:/agentsoc')
    import json
    from perception.nce_engine import _has_external_ip, _has_non_internal_domain, _has_beaconing_command

    def get_ev(a):
        return {k: a.get(k) or '' for k in ['process_name','command_line','registry_key','parent_process','file_path','raw_log_line']}

    with open('GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json') as f:
        contam = {str(a['alert_id']): a for a in json.load(f)}
    with open('GUIDE_Dataset/processed/guide_sample_500_alerts.json') as f:
        clean = {str(a['alert_id']): a for a in json.load(f)}

    aid = '1219770714799'
    c_ev = get_ev(contam[aid])
    cl_ev = get_ev(clean[aid])

    print(f'Alert {aid}:')
    print(f'  Contam: IP={_has_external_ip(c_ev)}, Domain={_has_non_internal_domain(c_ev)}, Beacon={_has_beaconing_command(c_ev)}')
    print(f'  Clean:  IP={_has_external_ip(cl_ev)}, Domain={_has_non_internal_domain(cl_ev)}, Beacon={_has_beaconing_command(cl_ev)}')
    c_passes = _has_external_ip(c_ev) or _has_non_internal_domain(c_ev) or _has_beaconing_command(c_ev)
    cl_passes = _has_external_ip(cl_ev) or _has_non_internal_domain(cl_ev) or _has_beaconing_command(cl_ev)
    print(f'  Contam t1071_passes={c_passes}, Clean t1071_passes={cl_passes}, Outcome flips={c_passes != cl_passes}')
    print(f'  Contam raw_log_line: {contam[aid].get("raw_log_line", "")[:200]}')
    print(f'  Clean  raw_log_line: {clean[aid].get("raw_log_line", "")[:200]}')


if __name__ == "__main__":
    main()
