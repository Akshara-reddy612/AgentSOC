"""
experiments/t1071_noise_floor.py
"""
import json
from pathlib import Path
from scipy.stats import binomtest, wilcoxon

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CLEAN_A = PROJECT_ROOT / "experiments" / "paired_clean_results.json"
CLEAN_B = PROJECT_ROOT / "experiments" / "paired_clean_results_B.json"
RUN_A = PROJECT_ROOT / "agent" / "nce_n50_scaleup_results_runA.json"
RUN_B = PROJECT_ROOT / "agent" / "nce_n50_scaleup_results_runB.json"

def _load_file(path):
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return {str(r["alert_id"]): r for r in raw if not r.get("nce_error")}

def _get_t1071_max_conf(record):
    hyps = record.get("nce_hypotheses_orig") or []
    t1071_confs = [float(h.get("nce_confidence", 0)) for h in hyps if h.get("technique_id") == "T1071"]
    if not t1071_confs:
        return None
    return max(t1071_confs)

def main():
    datasets = {
        "Clean A": _load_file(CLEAN_A),
        "Clean B": _load_file(CLEAN_B),
        "Contam A": _load_file(RUN_A),
        "Contam B": _load_file(RUN_B)
    }

    print("Header INFO:")
    for name, ds in datasets.items():
        total = len(ds)
        has_orig = sum(1 for r in ds.values() if r.get("nce_hypotheses_orig") is not None)
        print(f"{name}: {total} records, {has_orig} have nce_hypotheses_orig")

    pairs = [
        ("Clean A", "Clean B"),
        ("Contam A", "Contam B"),
        ("Clean A", "Contam A"),
        ("Clean A", "Contam B"),
        ("Clean B", "Contam A"),
        ("Clean B", "Contam B"),
    ]

    print("\n--- EXPLORATORY T1071 CONFIDENCE NOISE FLOOR (6 pairs tested) ---")
    for name1, name2 in pairs:
        ds1 = datasets[name1]
        ds2 = datasets[name2]
        shared = sorted(set(ds1.keys()) & set(ds2.keys()))
        
        both_have_t1071 = 0
        diffs = []
        zero_diff = 0
        second_less = 0
        second_greater = 0
        
        only_first = 0
        only_second = 0
        
        for aid in shared:
            c1 = _get_t1071_max_conf(ds1[aid])
            c2 = _get_t1071_max_conf(ds2[aid])
            
            if c1 is not None and c2 is not None:
                both_have_t1071 += 1
                diff = c2 - c1
                diffs.append(diff)
                if diff == 0:
                    zero_diff += 1
                elif diff < 0:
                    second_less += 1
                else:
                    second_greater += 1
            elif c1 is not None and c2 is None:
                only_first += 1
            elif c1 is None and c2 is not None:
                only_second += 1

        print(f"\n{name1} vs {name2}")
        print(f"Both have T1071 hypotheses: {both_have_t1071}")
        print(f"  Zero diff: {zero_diff}")
        print(f"  Second < First: {second_less}")
        print(f"  Second > First: {second_greater}")
        
        non_tied = second_less + second_greater
        if non_tied > 0:
            p_sign = binomtest(second_less, non_tied, 0.5, alternative='two-sided').pvalue
            print(f"  Sign-test p-value (non-tied): {p_sign:.4f}")
        else:
            print("  Sign-test p-value (non-tied): N/A")
            
        if both_have_t1071 > 0 and (second_less > 0 or second_greater > 0):
            res_wilcoxon = wilcoxon(diffs, zero_method="wilcox")
            print(f"  Wilcoxon signed-rank p-value (zero_method='wilcox'): {res_wilcoxon.pvalue:.4f}")
        else:
            print("  Wilcoxon signed-rank p-value (zero_method='wilcox'): N/A")
            
        print(f"Only first emitted T1071: {only_first}")
        print(f"Only second emitted T1071: {only_second}")
        asym_total = only_first + only_second
        if asym_total > 0:
            p_asym = binomtest(only_first, asym_total, 0.5, alternative='two-sided').pvalue
            print(f"  Asymmetry binomial p-value: {p_asym:.4f}")
        else:
            print("  Asymmetry binomial p-value: N/A")

if __name__ == "__main__":
    main()
