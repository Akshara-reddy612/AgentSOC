import re
import sys

patterns = ["defense success", "defended", "defends", "structural defense", "defense rate", "immune", "independently validates"]

with open('agentsoc2_paper_corrected.tex', 'r', encoding='utf-8') as f:
    lines = f.readlines()

text = "".join(lines)

for p in patterns:
    for match in re.finditer(re.escape(p), text, re.IGNORECASE):
        start = max(0, match.start() - 100)
        end = min(len(text), match.end() + 100)
        context = text[start:end].replace('\n', ' ')
        
        # Calculate line number
        line_num = text[:match.start()].count('\n') + 1
        print(f"Line {line_num}: ...{context}...")

