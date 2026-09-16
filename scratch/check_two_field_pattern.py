import json
from pathlib import Path
import re
import sys

sys.path.insert(0, r"c:\agentsoc")

from risk_assessment.detectors.approval_claim_detector import (
    _TICKET_PATTERN,
    _DISPOSITION_KEYWORDS,
)

kw_patterns = [
    (kw, re.compile((r"\b" if kw[0].isalnum() else "") + re.escape(kw) + (r"\b" if kw[-1].isalnum() else ""), re.IGNORECASE))
    for kw in _DISPOSITION_KEYWORDS
]

candidate_files = [
    Path("GUIDE_Dataset/processed/guide_strongblunt_hardersubtle_scale_42_alerts.json"),
    *Path("GUIDE_Dataset/processed").glob("*fabricated*"),
    *Path("GUIDE_Dataset/processed").glob("*subtle*"),
    *Path("agent").glob("*fabricated*"),
    *Path("agent").glob("*subtle*")
]
seen = sorted(set(p for p in candidate_files if p.exists()))

# Regex for key="value"
field_pat = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"')

two_field_cases = []

for f in seen:
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except Exception as e:
        continue
    items = data if isinstance(data, list) else [data]
    for item in items:
        aid = item.get("alert_id", "unknown")
        # Check relevant fields
        for k, v in item.items():
            if not isinstance(v, str):
                continue
            for line in v.split("\n"):
                if not line.strip():
                    continue
                # check if there's both a ticket and a disposition kw in line
                tickets_in_line = _TICKET_PATTERN.findall(line)
                kws_in_line = [kw for kw, pat in kw_patterns if pat.search(line)]
                if not tickets_in_line or not kws_in_line:
                    continue

                # find all key="value" spans
                f_matches = field_pat.findall(line)
                
                # Check for two separate fields: one with ticket, one with disposition kw
                t_fields = [(fk, fv) for fk, fv in f_matches if _TICKET_PATTERN.search(fv)]
                kw_fields = [(fk, fv) for fk, fv in f_matches if any(pat.search(fv) for _, pat in kw_patterns)]
                
                # Check if there is a ticket in one field and kw in another field
                for tfk, tfv in t_fields:
                    for kwfk, kwfv in kw_fields:
                        if tfk != kwfk or tfv != kwfv:
                            # Also check if they both appear together in either field
                            tf_has_kw = any(pat.search(tfv) for _, pat in kw_patterns)
                            kwf_has_t = bool(_TICKET_PATTERN.search(kwfv))
                            two_field_cases.append({
                                "file": f.name,
                                "alert_id": aid,
                                "line": line,
                                "ticket_field": f'{tfk}="{tfv}"',
                                "kw_field": f'{kwfk}="{kwfv}"',
                                "same_field_also_present": (tf_has_kw or kwf_has_t)
                            })

# Deduplicate
unique_cases = []
seen_pairs = set()
for c in two_field_cases:
    key = (c["file"], c["alert_id"], c["ticket_field"], c["kw_field"])
    if key not in seen_pairs:
        seen_pairs.add(key)
        unique_cases.append(c)

print(f"Total matching two-field cases found: {len(unique_cases)}")
for idx, c in enumerate(unique_cases, 1):
    print(f"\n--- Case {idx} ---")
    print(f"File: {c['file']}, Alert ID: {c['alert_id']}")
    print(f"Ticket field: {c['ticket_field']}")
    print(f"Keyword field: {c['kw_field']}")
    print(f"Is ticket/kw also present together in one field? {c['same_field_also_present']}")
    print(f"Raw line: {c['line']}")

# Also let's inspect all lines where ticket and disposition co-occur to see how they are structured
print("\n" + "="*80)
print("ALL CO-OCCURRENCES OF TICKET + DISPOSITION IN CORPUS:")
print("="*80)
cooccurrences = []
seen_lines = set()
for f in seen:
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        continue
    items = data if isinstance(data, list) else [data]
    for item in items:
        aid = item.get("alert_id", "unknown")
        for k, v in item.items():
            if not isinstance(v, str):
                continue
            for line in v.split("\n"):
                line_s = line.strip()
                if not line_s or line_s in seen_lines:
                    continue
                tickets = _TICKET_PATTERN.findall(line_s)
                kws = [kw for kw, pat in kw_patterns if pat.search(line_s)]
                if tickets and kws:
                    seen_lines.add(line_s)
                    cooccurrences.append((f.name, aid, k, tickets, kws, line_s))

print(f"Total unique lines with ticket + disposition co-occurrence: {len(cooccurrences)}")
for f_name, aid, field_key, tickets, kws, line_s in cooccurrences:
    print(f"\n[File: {f_name} | Alert: {aid} | Field: {field_key}]")
    print(f"Tickets: {tickets}")
    print(f"Keywords: {kws}")
    print(f"Line: {line_s}")
