"""
experiments/analyze_paired.py
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path
from statsmodels.stats.proportion import proportion_confint

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from experiments.metrics import exact_mcnemar

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CLEAN_A = PROJECT_ROOT / "experiments" / "paired_clean_results.json"
CLEAN_B = PROJECT_ROOT / "experiments" / "paired_clean_results_B.json"
RUN_A = PROJECT_ROOT / "agent" / "nce_n50_scaleup_results_runA.json"
RUN_B = PROJECT_ROOT / "agent" / "nce_n50_scaleup_results_runB.json"

def _normalize_account(s):
    return re.sub(r"@corp\.local$", "", str(s).lower().strip())

def _normalize_host(s):
    return str(s).lower().strip()

def _is_no_actionable(hyps):
    return sum(1 for h in hyps if h.get("sse_verdict") in ("FEASIBLE", "CONDITIONALLY_FEASIBLE")) == 0

def _technique_set(hyps):
    return frozenset(h.get("technique_id") for h in hyps)

def _hypothesis_set(hyps):
    return frozenset(
        (h.get("technique_id"), _normalize_account(h.get("source_account", "")),
         _normalize_host(h.get("source_host", "")), _normalize_host(h.get("target_host", "")))
        for h in hyps
    )

def _format_wilson(s, n):
    if n == 0: return "0/0 = 0.0000 [0.0000, 0.0000]"
    l, u = proportion_confint(s, n, method="wilson")
    return f"{s}/{n} = {s/n:.4f} [{l:.4f}, {u:.4f}]"

def main():
    print("Loading data...")
    cA = cB = rA = rB = {}

    def _load_file(path, label):
        """Load a result file, exclude records with non-empty nce_error."""
        if not path.exists():
            print(f"{label}: NOT FOUND IN REPO")
            return {}
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        total = len(raw)
        clean = [r for r in raw if not r.get("nce_error")]
        excluded = total - len(clean)
        print(f"{label}: total={total}, excluded (nce_error)={excluded}, used={len(clean)}")
        return {str(r["alert_id"]): r for r in clean}

    try:
        cA = _load_file(CLEAN_A, "Clean A")
        cB = _load_file(CLEAN_B, "Clean B")
        rA = _load_file(RUN_A, "Contam A")
        rB = _load_file(RUN_B, "Contam B")
    except Exception as e:
        print(f"Error loading files: {e}")
        return

    # Check totals for existing full runs
    for name, ds in [("Clean A", cA), ("Clean B", cB), ("Contam A", rA), ("Contam B", rB)]:
        if not ds: continue
        n = len(ds)
        pre_no_act = sum(1 for aid in ds if _is_no_actionable(ds[aid].get("sse_results_orig") or []))
        post_no_act = sum(1 for aid in ds if _is_no_actionable(ds[aid].get("sse_results") or []))
        print(f"{name} pre-filter no-actionable: {_format_wilson(pre_no_act, n)}")
        print(f"{name} post-filter no-actionable: {_format_wilson(post_no_act, n)}")

    pairs = [
        ("Clean A vs Clean B", cA, cB, "within-condition"),
        ("Contam A vs Contam B", rA, rB, "within-condition"),
        ("Clean A vs Contam A", cA, rA, "cross-condition"),
        ("Clean A vs Contam B", cA, rB, "cross-condition"),
        ("Clean B vs Contam A", cB, rA, "cross-condition"),
        ("Clean B vs Contam B", cB, rB, "cross-condition"),
    ]

    for label, d1, d2, cond in pairs:
        print(f"\n=============================================")
        print(f"{label} ({cond})")
        print(f"=============================================")
        
        shared = sorted(set(d1) & set(d2))
        print(f"Shared alerts: {len(shared)}")
        if not shared:
            continue
            
        tech_diff = 0
        hyp_diff = 0
        a=b=c=d=0
        
        for aid in shared:
            h1 = d1[aid].get("sse_results") or []
            h2 = d2[aid].get("sse_results") or []
            
            if _technique_set(h1) != _technique_set(h2):
                tech_diff += 1
            if _hypothesis_set(h1) != _hypothesis_set(h2):
                hyp_diff += 1
                
            r1 = _is_no_actionable(h1)
            r2 = _is_no_actionable(h2)
            if r1 and r2: a += 1
            elif r1 and not r2: b += 1
            elif not r1 and r2: c += 1
            else: d += 1
            
        n = len(shared)
        diff_verdict = b + c
        print(f"Different technique set: {_format_wilson(tech_diff, n)}")
        print(f"Different hypothesis set: {_format_wilson(hyp_diff, n)}")
        print(f"Different no-actionable verdict: {_format_wilson(diff_verdict, n)}")
        
        m = exact_mcnemar(a, b, c, d)
        print(f"Exact McNemar: a={a} b={b} c={c} d={d} p={m.p_value:.6f}")

if __name__ == "__main__":
    main()
