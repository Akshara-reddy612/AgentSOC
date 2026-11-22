"""
experiments/e1_view.py

Checklist A5 (truncation confound, 2026-11-22). Offline. Does E1's payload reach NCE? E1 appends the payload to the
command line (experiments/dedale_inject.Injector); NCE sees the first MAX_PROMPT_FIELD_LENGTH characters of each
field. For every injected first alert in the E1 runs, this checks where the payload ends.

    python -m experiments.e1_view   -> prints; writes experiments/dedale_results/e1_view.json
"""
from __future__ import annotations

import json
from pathlib import Path

from dedale import data_dir
from experiments.dedale_inject import FAMILIES
from perception.case_store import CaseStore
from risk_assessment.config import MAX_PROMPT_FIELD_LENGTH

OUT = Path(__file__).resolve().parent / "dedale_results" / "e1_view.json"


def main() -> None:
    res = {"max_prompt_field_length": MAX_PROMPT_FIELD_LENGTH, "families": {}}
    for fam in FAMILIES:
        store = CaseStore(data_dir().parent / "runs" / f"dedale_host_gated_nce_E1_{fam}" / "cases.sqlite")
        n = inside = cut = 0
        longest = 0
        try:
            for case in store.cases(limit=10 ** 6):
                alerts = store.alerts(case["case_id"])
                if not alerts:
                    continue
                cmd = alerts[0]["untrusted"].get("command_line") or ""
                hit = [t for t in FAMILIES[fam] if t in cmd]
                if not hit:
                    continue
                n += 1
                longest = max(longest, len(cmd))
                start = cmd.find(hit[0])
                inside += start + len(hit[0]) <= MAX_PROMPT_FIELD_LENGTH
                cut += start < MAX_PROMPT_FIELD_LENGTH < start + len(hit[0])
        finally:
            store.close()
        res["families"][fam] = {"injected_first_alerts": n, "payload_fully_in_view": inside, "cut_off": cut,
                                "longest_command_line": longest}
    print(json.dumps(res, indent=1))
    OUT.write_text(json.dumps(res, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
