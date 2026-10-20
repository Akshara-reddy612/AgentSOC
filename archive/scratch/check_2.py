import json
import os

REFERENCE_SLOTS = {
    5: {
        "alert_id": "1322849930226",
        "hypotheses": [
            {
                "technique_id": "T1484",
                "account": "a.patel",
                "target": "LT-4587-CORP",
                "nce_confidence": 0.85,
                "sse_verdict": "INFEASIBLE",
                "path_confidence": 0.00
            },
            {
                "technique_id": "T1078",
                "account": "a.patel",
                "target": "LT-4587-CORP",
                "nce_confidence": 0.35,
                "sse_verdict": "INFEASIBLE",
                "path_confidence": 0.00
            }
        ]
    },
    6: {
        "alert_id": "360777252926",
        "hypotheses": [
            {
                "technique_id": "T1550",
                "account": "jsmith",
                "target": "SRV-FILE9252",
                "nce_confidence": 0.72,
                "sse_verdict": "INFEASIBLE",
                "path_confidence": 0.00
            },
            {
                "technique_id": "T1078",
                "account": "jsmith",
                "target": "SRV-FILE9252",
                "nce_confidence": 0.65,
                "sse_verdict": "INFEASIBLE",
                "path_confidence": 0.00
            }
        ]
    },
    7: {
        "alert_id": "566935683184",
        "hypotheses": [
            {
                "technique_id": "T1484",
                "account": "m.chen",
                "target": "LT-5398-CORP",
                "nce_confidence": 0.85,
                "sse_verdict": "INFEASIBLE",
                "path_confidence": 0.00
            },
            {
                "technique_id": "T1078",
                "account": "m.chen",
                "target": "LT-5398-CORP",
                "nce_confidence": 0.45,
                "sse_verdict": "INFEASIBLE",
                "path_confidence": 0.00
            }
        ]
    }
}

def main():
    filepath = os.path.join("agent", "nce7_comparative_results.json")
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    target_slots = [item for item in data if item.get("slot") in (5, 6, 7)]

    print("=" * 80)
    print("SLOTS 5, 6, 7 EXTRACTED DATA FROM FINAL JSON")
    print("=" * 80)

    for item in target_slots:
        slot = item.get("slot")
        alert_id = item.get("alert_id")
        hyps = item.get("nce_hypotheses", [])
        sses = item.get("sse_results", [])
        print(f"Slot {slot} (Alert ID: {alert_id}):")
        for idx, (h, s) in enumerate(zip(hyps, sses)):
            tech = h.get("technique_id")
            acct = h.get("source_account", h.get("account"))
            tgt = h.get("target_host", h.get("target"))
            nce = h.get("nce_confidence")
            verdict = s.get("sse_verdict")
            path_conf = s.get("path_confidence")
            print(f"  [{idx}] technique_id={tech} account={acct} target={tgt} nce_confidence={nce} sse_verdict={verdict} path_confidence={path_conf}")
        print()

    print("=" * 80)
    print("COMPARISON WITH FIRST-RUN TERMINAL REFERENCE")
    print("=" * 80)

    for item in target_slots:
        slot = item.get("slot")
        alert_id = str(item.get("alert_id"))
        hyps = item.get("nce_hypotheses", [])
        sses = item.get("sse_results", [])

        ref = REFERENCE_SLOTS.get(slot)
        if not ref:
            print(f"Slot {slot}: MISMATCH - No reference found")
            continue

        mismatches = []
        if alert_id != ref["alert_id"]:
            mismatches.append(f"alert_id expected {ref['alert_id']}, got {alert_id}")

        ref_hyps = ref["hypotheses"]
        if len(hyps) != len(ref_hyps) or len(sses) != len(ref_hyps):
            mismatches.append(f"hypothesis/sse length mismatch: got {len(hyps)} hyps, {len(sses)} sse results")
        else:
            for idx, (h, s, rh) in enumerate(zip(hyps, sses, ref_hyps)):
                tech = h.get("technique_id")
                acct = h.get("source_account", h.get("account"))
                tgt = h.get("target_host", h.get("target"))
                nce = round(float(h.get("nce_confidence", 0.0)), 2)
                verdict = s.get("sse_verdict")
                path_conf = round(float(s.get("path_confidence", 0.0)), 2)

                if tech != rh["technique_id"]:
                    mismatches.append(f"[{idx}] technique_id expected {rh['technique_id']}, got {tech}")
                if acct != rh["account"]:
                    mismatches.append(f"[{idx}] account expected {rh['account']}, got {acct}")
                if tgt != rh["target"]:
                    mismatches.append(f"[{idx}] target expected {rh['target']}, got {tgt}")
                if nce != rh["nce_confidence"]:
                    mismatches.append(f"[{idx}] nce_confidence expected {rh['nce_confidence']}, got {nce}")
                if verdict != rh["sse_verdict"]:
                    mismatches.append(f"[{idx}] sse_verdict expected {rh['sse_verdict']}, got {verdict}")
                if path_conf != rh["path_confidence"]:
                    mismatches.append(f"[{idx}] path_confidence expected {rh['path_confidence']}, got {path_conf}")

        if not mismatches:
            print(f"Slot {slot}: MATCH")
        else:
            print(f"Slot {slot}: MISMATCH - " + "; ".join(mismatches))

if __name__ == "__main__":
    main()
