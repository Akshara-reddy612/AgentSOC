# Manual diagnostic script (NOT a pytest test): read-only analysis, run from the project root.


def main() -> None:
    import sys; sys.path.insert(0, 'c:/agentsoc')
    import json, re
    from perception.nce_engine import _BEACONING_PATTERNS

    _POST_CASE_RE = re.compile(r'\bPOST\b')
    _OTHER_RE = re.compile(r'(?:\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod|\/beacon|\/checkin|category=CommandAndControl)', re.IGNORECASE)

    def get_ev(a):
        return {k: a.get(k) or '' for k in ['process_name','command_line','registry_key','parent_process','file_path','raw_log_line']}

    with open('GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json') as f:
        contam = {str(a['alert_id']): a for a in json.load(f)}
    with open('GUIDE_Dataset/processed/guide_sample_500_alerts.json') as f:
        clean = {str(a['alert_id']): a for a in json.load(f)}

    only_post = []
    for aid, c in contam.items():
        c_ev = get_ev(c)
        cl_ev = get_ev(clean[aid])

        contam_v0 = any(_BEACONING_PATTERNS.search(v) for v in c_ev.values())
        contam_other = any(_OTHER_RE.search(v) for v in c_ev.values()) or any(_POST_CASE_RE.search(v) for v in c_ev.values())

        if contam_v0 and not contam_other:
            clean_v0 = any(_BEACONING_PATTERNS.search(v) for v in cl_ev.values())
            only_post.append((aid, clean_v0, c.get('_ground_truth_injection_category')))

    print(f'Alerts where contam passes beacon ONLY via lowercase post: {len(only_post)}')
    for aid, clean_v0, fam in only_post:
        flip = not clean_v0
        print(f'  aid={aid} family={fam} clean_beacon={clean_v0} filter_outcome_flips={flip}')

    # Show the 15th one's raw_log_line
    non_flips = [(aid, clean_v0, fam) for aid, clean_v0, fam in only_post if clean_v0]
    print(f'\nNon-flipping (15th): {len(non_flips)} alert(s)')
    for aid, _, fam in non_flips:
        c = contam[aid]
        cl = clean[aid]
        print(f'Alert {aid} (family={fam}):')
        print(f'  Contam raw_log_line: {c.get("raw_log_line", "")[:200]}')
        print(f'  Clean  raw_log_line: {cl.get("raw_log_line", "")[:200]}')


if __name__ == "__main__":
    main()
