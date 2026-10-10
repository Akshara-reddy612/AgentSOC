import sys; sys.path.insert(0, 'c:/agentsoc')
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
    (r'\bpost\b', 'post (lowercase/other)'), # Case insensitive matching later
    (r'category=CommandAndControl', 'category=CommandAndControl')
]

def analyze_alerts(alerts_file, is_contam):
    with open(alerts_file, encoding='utf-8') as f:
        alerts = json.load(f)
        
    counts = {p[1]: {'first': 0, 'only': 0, 'examples': []} for p in PATTERNS}
    c2_inside = 0
    c2_outside = 0
    
    for a in alerts:
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
            if not v: continue
            
            # For category=CommandAndControl inside/outside payload
            if 'category=CommandAndControl' in v:
                # Check if it's inside INJECTED_FIELD_VALUE
                inj_start = v.find('INJECTED_FIELD_VALUE="')
                c2_idx = v.find('category=CommandAndControl')
                if inj_start != -1 and c2_idx > inj_start:
                    c2_inside += 1
                else:
                    c2_outside += 1

            for pat, name in PATTERNS:
                if name == 'POST (uppercase)':
                    m = re.search(pat, v)
                elif name == 'post (lowercase/other)':
                    m = re.search(r'\bpost\b', v, re.IGNORECASE)
                    if m and m.group(0) == 'POST':
                        continue # Handled by uppercase
                else:
                    m = re.search(pat, v, re.IGNORECASE)
                    
                if m:
                    matches_found.add(name)
                    if first_match is None:
                        first_match = name
                        first_match_raw = v
        
        if first_match:
            counts[first_match]['first'] += 1
            if len(counts[first_match]['examples']) < 3:
                counts[first_match]['examples'].append(first_match_raw)
                
        if len(matches_found) == 1:
            counts[list(matches_found)[0]]['only'] += 1

    print(f"\n--- {alerts_file} ---")
    for name, stats in counts.items():
        print(f"Pattern '{name}': First match = {stats['first']}, Only match = {stats['only']}")
        if stats['examples']:
            print("  Examples:")
            for ex in stats['examples']:
                # Truncate for display
                start = max(0, ex.lower().find(name.lower().split(' ')[0]) - 20)
                end = min(len(ex), start + 100)
                print(f"    ...{ex[start:end]}...")
    
    print(f"category=CommandAndControl inside INJECTED_FIELD_VALUE: {c2_inside}")
    print(f"category=CommandAndControl outside INJECTED_FIELD_VALUE: {c2_outside}")

def main():
    analyze_alerts('GUIDE_Dataset/processed/guide_sample_500_alerts.json', False)
    analyze_alerts('GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json', True)

if __name__ == '__main__':
    main()
