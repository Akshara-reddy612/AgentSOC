# Manual diagnostic script (NOT a pytest test): read-only analysis, run from the project root.


def main() -> None:
    import sys; from pathlib import Path; sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import json
    import re

    PATTERNS = [
        (r'\bcurl\b', 'curl'),
        (r'\bwget\b', 'wget'),
        (r'Invoke-WebRequest', 'Invoke-WebRequest'),
        (r'Invoke-RestMethod', 'Invoke-RestMethod'),
        (r'\/beacon', '/beacon'),
        (r'\/checkin', '/checkin'),
        (r'\bPOST\b', 'POST (uppercase)'),
        (r'\bpost\b', 'post (lowercase/other case)'),
        (r'category=CommandAndControl', 'category=CommandAndControl')
    ]

    def analyze_alerts(alerts_file, name_label):
        with open(alerts_file, encoding='utf-8') as f:
            alerts = json.load(f)

        with open('experiments/paired_clean_results.json', encoding='utf-8') as f:
            valid_aids = {str(r['alert_id']) for r in json.load(f) if not r.get('nce_error')}

        counts = {name: {'first': 0, 'only': 0, 'examples': []} for _, name in PATTERNS}
        c2_inside = 0
        c2_outside = 0

        for a in alerts:
            if str(a['alert_id']) not in valid_aids: continue

            ev_fields = [
                a.get('process_name') or '',
                a.get('command_line') or '',
                a.get('registry_key') or '',
                a.get('parent_process') or '',
                a.get('file_path') or '',
                a.get('raw_log_line') or ''
            ]

            matches_found = set()
            first_match = None
            first_match_raw = None

            for v in ev_fields:
                if 'category=CommandAndControl' in v:
                    inj_start = v.find('INJECTED_FIELD_VALUE="')
                    c2_idx = v.find('category=CommandAndControl')
                    if inj_start != -1 and c2_idx > inj_start:
                        c2_inside += 1
                    else:
                        c2_outside += 1

            for pat, name in PATTERNS:
                pat_matched = False
                matched_raw = None
                for v in ev_fields:
                    if name == 'POST (uppercase)':
                        m = re.search(pat, v)
                    elif name == 'post (lowercase/other case)':
                        m = re.search(pat, v, re.IGNORECASE)
                        if m and m.group(0) == 'POST': m = None
                    else:
                        m = re.search(pat, v, re.IGNORECASE)

                    if m:
                        pat_matched = True
                        matched_raw = v
                        break

                if pat_matched:
                    matches_found.add(name)
                    if first_match is None:
                        first_match = name
                        first_match_raw = matched_raw

            if first_match:
                counts[first_match]['first'] += 1
                if len(counts[first_match]['examples']) < 3:
                    counts[first_match]['examples'].append(first_match_raw)

            if len(matches_found) == 1:
                counts[list(matches_found)[0]]['only'] += 1

        print(f'\n--- {name_label} ---')
        for name, stats in counts.items():
            print(f"{name}: first={stats['first']}, only={stats['only']}")
            for ex in stats['examples']:
                start = max(0, ex.lower().find(name.lower().split(' ')[0]) - 20)
                end = min(len(ex), start + 100)
                print(f"  ...{ex[start:end]}...")

        print(f'category=CommandAndControl inside payload: {c2_inside}')
        print(f'category=CommandAndControl outside payload: {c2_outside}')

    analyze_alerts('GUIDE_Dataset/processed/guide_sample_500_alerts.json', 'CLEAN TWINS')
    analyze_alerts('GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json', 'CONTAMINATED')


if __name__ == "__main__":
    main()
