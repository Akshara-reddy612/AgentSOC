"""
# -*- coding: utf-8 -*-
demo_phase2.py

Phase 2 Demo: Evidence Risk Assessment + Safe Prompt Construction.

Loads sample_data/adversarial_alerts.json, runs each alert through:
  1. Phase 1 pipeline (PerceptionPipeline) → EnrichedIncident
  2. orchestrator.assess(evidence) → RiskAssessmentBundle
  3. integration.attach_risk_metadata(bundle, incident) → populates Evidence.risk_metadata
  4. safe_prompt_builder.build_prompt_package(incident) → PromptPackage
  5. serializers.serialize_xml(pkg) → final safe-prompt string

Prints per-alert:
  - Attack category
  - Field-level risk results (score, level, top matches)
  - Incident-level risk result
  - Serialized safe-prompt string (first 500 chars)

At the end, prints per-detector and per-category metrics table.

Metrics disclaimer
------------------
Detection rates, false-positive rates, precision, and recall reported here
are MEASURED ON A SMALL ILLUSTRATIVE SAMPLE of 9 adversarial alerts (6 attack,
3 benign).  These numbers are NOT statistically powered and do NOT constitute
a rigorous evaluation.  They are intended only to demonstrate that the detectors
function as designed.  A proper evaluation requires a large, labeled dataset
with independently verified ground truth.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from perception.pipeline import PerceptionPipeline
from risk_assessment.integration import attach_risk_metadata
from risk_assessment.orchestrator import assess
from prompt_construction.safe_prompt_builder import build_prompt_package
from prompt_construction.serializers import serialize_xml

# ─────────────────────────────────────────────────────────────────────────────
# ANSI colours
# ─────────────────────────────────────────────────────────────────────────────

BOLD   = "\033[1m"
CYAN   = "\033[36m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RST    = "\033[0m"
SEP    = "─" * 72


def hdr(title: str, color: str = CYAN) -> None:
    print(f"\n{color}{BOLD}{SEP}")
    print(f"  {title}")
    print(f"{SEP}{RST}")


def sub(title: str) -> None:
    print(f"\n  {YELLOW}{BOLD}{title}{RST}")


def kv(key: str, val: object, indent: int = 4, color: str = "") -> None:
    pad = " " * indent
    val_str = str(val)
    if len(val_str) > 100:
        val_str = val_str[:97] + "…"
    print(f"{pad}{BOLD}{key}:{RST} {color}{val_str}{color and RST or ''}")


def risk_color(level: str) -> str:
    return {
        "HIGH": RED,
        "MEDIUM": YELLOW,
        "LOW": GREEN,
    }.get(level, "")


# ─────────────────────────────────────────────────────────────────────────────
# Metrics tracking
# ─────────────────────────────────────────────────────────────────────────────

class MetricsTracker:
    """Track per-detector and per-category detection results."""

    def __init__(self) -> None:
        self.detector_results: dict[str, list[tuple[str, bool, bool]]] = {
            "RegexDetector": [],      # (alert_id, is_attack, detected)
            "SemanticDetector": [],
            "SplitFieldDetector": [],
        }
        self.category_results: dict[str, dict[str, bool]] = {}
        # Maps alert_id → (category, is_attack)
        self.alert_info: dict[str, tuple[str, bool]] = {}

    def record(
        self,
        alert_id: str,
        category: str,
        is_attack: bool,
        bundle,
    ) -> None:
        """Record detection results for one alert."""
        self.alert_info[alert_id] = (category, is_attack)

        # Determine per-detector hits from the BEST field-level result
        # (a detector "detected" the alert if it scored > 0 on any field)
        detector_hits: dict[str, bool] = {
            "RegexDetector": False,
            "SemanticDetector": False,
            "SplitFieldDetector": False,
        }

        # Check field-level results
        for field_result in bundle.field_results.values():
            for dr in field_result.detector_results:
                if dr.detector in detector_hits and dr.score > 0.0:
                    detector_hits[dr.detector] = True

        # SplitFieldDetector is also in incident_result
        if bundle.incident_result:
            for dr in bundle.incident_result.detector_results:
                if dr.detector in detector_hits and dr.score > 0.0:
                    detector_hits[dr.detector] = True

        for det_name, hit in detector_hits.items():
            self.detector_results[det_name].append((alert_id, is_attack, hit))

        # Category-level: did the overall incident_result flag as ≥ MEDIUM?
        overall_detected = False
        if bundle.incident_result:
            overall_detected = bundle.incident_result.risk_level in ("MEDIUM", "HIGH")
        else:
            # Fall back to checking any field
            overall_detected = any(
                r.risk_level in ("MEDIUM", "HIGH")
                for r in bundle.field_results.values()
            )
        self.category_results.setdefault(category, {})[alert_id] = overall_detected

    def print_report(self) -> None:
        hdr("METRICS REPORT  (illustrative — small sample, not statistically powered)", MAGENTA)

        print(f"\n  {BOLD}Disclaimer:{RST} The following metrics are measured on {RED}9 alerts{RST}")
        print("  (6 adversarial, 3 benign). They are ILLUSTRATIVE ONLY and do not")
        print("  constitute a rigorous evaluation. Precision/recall on this sample")
        print("  cannot be extrapolated to production performance.")

        # ── Per-detector metrics ──────────────────────────────────────────────
        sub("Per-Detector Metrics")
        print(f"\n  {'Detector':<22}  {'TP':>4}  {'FP':>4}  {'TN':>4}  {'FN':>4}  "
              f"{'DetRate':>8}  {'FPR':>6}  {'Prec':>6}  {'Recall':>7}")
        print(f"  {'─'*22}  {'─'*4}  {'─'*4}  {'─'*4}  {'─'*4}  "
              f"{'─'*8}  {'─'*6}  {'─'*6}  {'─'*7}")

        for det_name, results in self.detector_results.items():
            tp = sum(1 for _, is_atk, hit in results if is_atk and hit)
            fp = sum(1 for _, is_atk, hit in results if not is_atk and hit)
            tn = sum(1 for _, is_atk, hit in results if not is_atk and not hit)
            fn = sum(1 for _, is_atk, hit in results if is_atk and not hit)

            n_attacks = sum(1 for _, is_atk, _ in results if is_atk)
            n_benign = sum(1 for _, is_atk, _ in results if not is_atk)

            det_rate = tp / n_attacks if n_attacks > 0 else 0.0
            fpr = fp / n_benign if n_benign > 0 else 0.0
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

            print(f"  {det_name:<22}  {tp:>4}  {fp:>4}  {tn:>4}  {fn:>4}  "
                  f"{det_rate:>7.1%}  {fpr:>5.1%}  {prec:>5.1%}  {recall:>6.1%}")

        # ── Per-category metrics ──────────────────────────────────────────────
        sub("Per-Category Detection Rates  (overall pipeline, incident-level)")
        print(f"\n  {'Category':<35}  {'Detected':>8}  {'Total':>5}  {'Rate':>6}")
        print(f"  {'─'*35}  {'─'*8}  {'─'*5}  {'─'*6}")

        # Group by category
        cat_counts: dict[str, dict[str, int]] = {}
        for alert_id, detected in {
            aid: det
            for cat_dict in self.category_results.values()
            for aid, det in cat_dict.items()
        }.items():
            category, is_attack = self.alert_info[alert_id]
            if not is_attack:
                category = "(benign)"
            cat_counts.setdefault(category, {"detected": 0, "total": 0})
            cat_counts[category]["total"] += 1
            if detected:
                cat_counts[category]["detected"] += 1

        for cat, counts in sorted(cat_counts.items()):
            det = counts["detected"]
            tot = counts["total"]
            rate_str = f"{det/tot:.0%}" if tot > 0 else "N/A"
            marker = f"{GREEN}✓{RST}" if det == tot else (f"{RED}✗{RST}" if det == 0 else f"{YELLOW}~{RST}")
            print(f"  {cat:<35}  {marker} {det:>6}  {tot:>5}  {rate_str:>6}")

        print(f"\n  {BOLD}Note:{RST} FP = false positive (benign flagged as risky).")
        print(f"  Honest caveat: these numbers are from a {RED}toy sample{RST}.")
        print(f"  Do not use them as product claims or security guarantees.")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}{'='*72}")
    print("  Phase 2 Demo: Evidence Risk Assessment + Safe Prompt Construction")
    print(f"{'='*72}{RST}")

    sample_path = Path(__file__).parent / "sample_data" / "adversarial_alerts.json"
    print(f"\nLoading adversarial alerts from: {sample_path}")

    with sample_path.open(encoding="utf-8") as fh:
        raw_alerts = json.load(fh)
    print(f"  {len(raw_alerts)} alerts loaded.")

    # Run Phase 1 pipeline to get EnrichedIncidents
    pipeline = PerceptionPipeline(emit_logs=False)
    result = pipeline.run(raw_alerts)

    if result.validation_rejections:
        hdr("VALIDATION REJECTIONS (skipped)", RED)
        for alert_id, vr in result.validation_rejections:
            print(f"  {alert_id}: {[e.code for e in vr.errors]}")

    print(f"\n  Phase 1 produced {len(result.clusters)} valid cluster(s).")

    # Build lookup: alert_id → raw alert metadata (category etc)
    raw_meta: dict[str, dict] = {a["alert_id"]: a for a in raw_alerts}

    metrics = MetricsTracker()

    # Process each cluster through Phase 2
    for cluster in result.clusters:
        incident = cluster.representative
        alert_id = incident.alert_id
        raw = raw_meta.get(alert_id, {})
        category = raw.get("_test_category", "unknown")
        is_attack = not category.startswith("benign")

        hdr(f"Alert: {alert_id}  |  Category: {category}", CYAN if is_attack else GREEN)
        kv("source_user", raw.get("source_user", "?"))
        kv("is_attack", is_attack, color=RED if is_attack else GREEN)

        # ── Phase 2: Risk Assessment ──────────────────────────────────────────
        sub("Risk Assessment")
        bundle = assess(incident.evidence)
        attach_risk_metadata(bundle, incident)

        # Print field-level results
        for field_name, field_result in bundle.field_results.items():
            lvl = field_result.risk_level
            score = field_result.overall_score
            color = risk_color(lvl)
            matches = []
            for dr in field_result.detector_results:
                if dr.matches:
                    matches.extend(dr.matches[:2])  # show top 2 matches
            match_str = f"  matches=[{', '.join(matches[:3])}]" if matches else ""
            print(f"    {BOLD}{field_name}:{RST} "
                  f"{color}{lvl}{RST} (score={score:.3f}){match_str}")

        # Print incident-level result
        if bundle.incident_result:
            ir = bundle.incident_result
            color = risk_color(ir.risk_level)
            print(f"\n  {BOLD}Incident-level:{RST} "
                  f"{color}{ir.risk_level}{RST} (score={ir.overall_score:.3f})")
            # Show top summary sentence
            if ir.summary:
                print(f"    → {ir.summary[0][:100]}")

        # ── Phase 2: Safe Prompt Construction ────────────────────────────────
        sub("Safe Prompt (first 500 chars of XML serialization)")
        pkg = build_prompt_package(incident)
        xml_output = serialize_xml(pkg)
        preview = xml_output[:500]
        if len(xml_output) > 500:
            preview += "\n  … (truncated for display)"
        print(f"\n{CYAN}{preview}{RST}")

        # Truncation note
        if pkg.metadata.get("total_was_truncated"):
            print(f"\n  {YELLOW}[Truncation applied: total included = "
                  f"{pkg.metadata.get('total_included_length')} chars]{RST}")

        # Track metrics
        metrics.record(alert_id, category, is_attack, bundle)

    # ── Final metrics report ──────────────────────────────────────────────────
    metrics.print_report()

    print(f"\n{BOLD}{'='*72}{RST}")
    print(f"  Phase 2 complete.")
    print(f"  {len(result.clusters)} alerts processed | "
          f"ERA + SPC pipeline end-to-end functional.")
    print(f"{'='*72}")


if __name__ == "__main__":
    main()
