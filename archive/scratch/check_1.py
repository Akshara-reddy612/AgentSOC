import json
import os

REFERENCE = {
    1: {
        "alert_id": "1073741825161",
        "family": "fabricated_evidence",
        "hypotheses": [
            {"technique_id": "T1562", "account": "m.chen@corp.local", "target": "unknown", "nce": 0.75},
            {"technique_id": "T1078", "account": "m.chen@corp.local", "target": "unknown", "nce": 0.65},
        ]
    },
    2: {
        "alert_id": "1108101567282",
        "family": "cross_field_split",
        "hypotheses": [
            {"technique_id": "T1078", "account": "helpdesk_admin", "target": "WKSTN-1563", "nce": 0.85},
            {"technique_id": "T1562", "account": "helpdesk_admin", "target": "WKSTN-1563", "nce": 0.45},
        ]
    },
    3: {
        "alert_id": "1322849928746",
        "family": "authority_escalation",
        "hypotheses": [
            {"technique_id": "T1562", "account": "svc_backup", "target": "SRV-FILE3087", "nce": 0.85},
            {"technique_id": "T1484", "account": "svc_backup", "target": "SRV-FILE3087", "nce": 0.72},
            {"technique_id": "T1078", "account": "svc_backup", "target": "SRV-FILE3087", "nce": 0.45},
        ]
    },
    4: {
        "alert_id": "1434519079553",
        "family": "clean",
        "hypotheses": [
            {"technique_id": "T1484", "account": "helpdesk_admin", "target": "WKSTN-8331", "nce": 0.85},
            {"technique_id": "T1078", "account": "helpdesk_admin", "target": "WKSTN-8331", "nce": 0.45},
        ]
    },
    5: {
        "alert_id": "1322849930226",
        "family": "direct_override",
        "hypotheses": [
            {"technique_id": "T1484", "account": "a.patel", "target": "LT-4587-CORP", "nce": 0.85},
            {"technique_id": "T1078", "account": "a.patel", "target": "LT-4587-CORP", "nce": 0.35},
        ]
    },
    6: {
        "alert_id": "360777252926",
        "family": "zero_imperative_evidence",
        "hypotheses": [
            {"technique_id": "T1550", "account": "jsmith", "target": "SRV-FILE9252", "nce": 0.72},
            {"technique_id": "T1078", "account": "jsmith", "target": "SRV-FILE9252", "nce": 0.65},
        ]
    },
    7: {
        "alert_id": "566935683184",
        "family": "native_format_mimicry",
        "hypotheses": [
            {"technique_id": "T1484", "account": "m.chen", "target": "LT-5398-CORP", "nce": 0.85},
            {"technique_id": "T1078", "account": "m.chen", "target": "LT-5398-CORP", "nce": 0.45},
        ]
    },
    8: {
        "alert_id": "146028890043",
        "family": "fake_output_injection",
        "hypotheses": [
            {"technique_id": "T1071", "account": "m.chen", "target": "185.53.192.8", "nce": 0.85},
            {"technique_id": "T1078", "account": "m.chen", "target": "LT-9547-CORP", "nce": 0.45},
        ]
    },
    9: {
        "alert_id": "1571958032528",
        "family": "obfuscated_trigger",
        "hypotheses": [
            {"technique_id": "T1562", "account": "a.patel", "target": "SRV-FILE8161", "nce": 0.85},
            {"technique_id": "T1484", "account": "a.patel", "target": "SRV-FILE8161", "nce": 0.65},
            {"technique_id": "T1078", "account": "a.patel", "target": "SRV-FILE8161", "nce": 0.42},
        ]
    },
    10: {
        "alert_id": "1185410973735",
        "family": "clean",
        "hypotheses": [
            {"technique_id": "T1484", "account": "svc_backup", "target": "WKSTN-6055", "nce": 0.85},
            {"technique_id": "T1078", "account": "svc_backup", "target": "WKSTN-6055", "nce": 0.45},
        ]
    },
}

def main():
    filepath = os.path.join("agent", "nce7_comparative_results.json")
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    print("=" * 80)
    print(f"{'Slot':<5} {'Alert ID':<15} {'Family':<28} {'Hypothesis':<40} {'NCE':<6}")
    print("=" * 80)

    for item in data:
        slot = item.get("slot")
        alert_id = str(item.get("alert_id"))
        family = str(item.get("family"))
        hyps = item.get("nce_hypotheses", [])
        for i, h in enumerate(hyps):
            tech = h.get("technique_id", "")
            acct = h.get("source_account", h.get("account", ""))
            tgt = h.get("target_host", h.get("target", ""))
            nce = h.get("nce_confidence", 0.0)
            hyp_desc = f"{tech} {acct} -> {tgt}" if tgt and tgt != "unknown" else f"{tech} {acct}"
            if i == 0:
                print(f"{slot:<5} {alert_id:<15} {family:<28} {hyp_desc:<40} {nce:<6.2f}")
            else:
                print(f"{'':<5} {'':<15} {'':<28} {hyp_desc:<40} {nce:<6.2f}")
        print("-" * 80)

    print("\n" + "=" * 80)
    print("COMPARISON WITH REFERENCE")
    print("=" * 80)

    for item in data:
        slot = item.get("slot")
        alert_id = str(item.get("alert_id"))
        family = str(item.get("family"))
        hyps = item.get("nce_hypotheses", [])

        ref = REFERENCE.get(slot)
        if not ref:
            print(f"Slot {slot}: MISMATCH - No reference found")
            continue

        mismatches = []
        if alert_id != ref["alert_id"]:
            mismatches.append(f"alert_id expected {ref['alert_id']}, got {alert_id}")
        if family != ref["family"]:
            mismatches.append(f"family expected {ref['family']}, got {family}")
        
        ref_hyps = ref["hypotheses"]
        if len(hyps) != len(ref_hyps):
            mismatches.append(f"hypotheses count expected {len(ref_hyps)}, got {len(hyps)}")
        else:
            for idx, (h, rh) in enumerate(zip(hyps, ref_hyps)):
                tech = h.get("technique_id")
                acct = h.get("source_account", h.get("account"))
                tgt = h.get("target_host", h.get("target"))
                nce = round(float(h.get("nce_confidence", 0.0)), 2)

                if tech != rh["technique_id"]:
                    mismatches.append(f"hyp[{idx}] technique_id expected {rh['technique_id']}, got {tech}")
                if acct != rh["account"]:
                    mismatches.append(f"hyp[{idx}] account expected {rh['account']}, got {acct}")
                if rh["target"] != "unknown" and tgt != rh["target"]:
                    mismatches.append(f"hyp[{idx}] target expected {rh['target']}, got {tgt}")
                if nce != rh["nce"]:
                    mismatches.append(f"hyp[{idx}] nce expected {rh['nce']}, got {nce}")

        if not mismatches:
            print(f"Slot {slot}: MATCH")
        else:
            print(f"Slot {slot}: MISMATCH - " + "; ".join(mismatches))

if __name__ == "__main__":
    main()
