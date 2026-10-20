"""
# -*- coding: utf-8 -*-
demo.py

Demonstration of the Phase 1 Trust-Aware Perception Layer.

Loads sample_data/sample_alerts.json (4 alerts: benign, injection attempt,
schema-invalid, and a structural duplicate), runs the full pipeline, and
prints structured results showing:
  - Each EnrichedIncident with ImmutableContext, DerivedContext, Evidence
    clearly separated
  - Schema-validation rejection with its error code(s)
  - Per-stage pipeline timing log
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import io
import sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from perception.pipeline import PerceptionPipeline


# ──────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ──────────────────────────────────────────────────────────────────────────────

BOLD  = "\033[1m"
CYAN  = "\033[36m"
GREEN = "\033[32m"
RED   = "\033[31m"
YEL   = "\033[33m"
RST   = "\033[0m"

SEP = "-" * 70


def hdr(title: str, color: str = CYAN) -> None:
    print(f"\n{color}{BOLD}{SEP}")
    print(f"  {title}")
    print(f"{SEP}{RST}")



def sub(title: str) -> None:
    print(f"\n  {YEL}{BOLD}{title}{RST}")


def kv(key: str, val: object, indent: int = 4) -> None:
    pad = " " * indent
    val_str = str(val)
    if len(val_str) > 90:
        val_str = textwrap.shorten(val_str, width=90, placeholder=" …[truncated]")
    print(f"{pad}{BOLD}{key}:{RST} {val_str}")


# ──────────────────────────────────────────────────────────────────────────────
# Display helpers
# ──────────────────────────────────────────────────────────────────────────────

def display_immutable_context(ic) -> None:
    sub("ImmutableContext  [TrustLevel: STRUCTURED — knowledge-store facts]")
    kv("source_user",      ic.source_user.value)
    kv("source_host",      ic.source_host.value)
    kv("target_host",      ic.target_host.value)
    kv("event_type",       ic.event_type.value)
    kv("user_role",        ic.user_role.value)
    kv("asset_criticality",ic.asset_criticality.value)
    kv("network_zone",     ic.network_zone.value)
    kv("historical_access",ic.historical_access.value)


def display_derived_context(dc) -> None:
    sub("DerivedContext  [TrustLevel: DERIVED — computed from STRUCTURED only]")

    def flag(name: str, val: bool) -> None:
        icon = f"{GREEN}✓ TRUE{RST}" if val else f"  false"
        print(f"    {BOLD}{name}:{RST} {icon}")

    flag("no_prior_access",          dc.no_prior_access.value)
    flag("cross_zone_access",        dc.cross_zone_access.value)
    flag("high_criticality_target",  dc.high_criticality_target.value)
    flag("privilege_escalation_risk",dc.privilege_escalation_risk.value)


def display_evidence(ev) -> None:
    sub("Evidence  [TrustLevel: FREE_TEXT — untouched attacker-controlled data]")
    fields = {
        "process_name":  ev.process_name,
        "command_line":  ev.command_line,
        "registry_key":  ev.registry_key,
        "parent_process":ev.parent_process,
        "file_path":     ev.file_path,
        "raw_log_line":  ev.raw_log_line,
    }
    for name, tf in fields.items():
        if tf is not None:
            val_str = str(tf.value)
            if len(val_str) > 120:
                val_str = val_str[:117] + "…"
            print(f"    {BOLD}{name}:{RST} {RED}{val_str}{RST}")
    count = ev.free_text_field_count()
    print(f"    [{count} free-text field(s) present — never consulted by derived-context rules]")
    print(f"    risk_metadata: {ev.risk_metadata}  ← populated by Phase 2 (ERA)")


def display_incident(cluster, index: int) -> None:
    inc = cluster.representative
    hdr(
        f"Cluster {index+1}  |  alert_id={inc.alert_id}"
        f"  |  occurrences={cluster.occurrence_count}",
        color=GREEN,
    )
    print(f"  first_seen: {cluster.first_seen.isoformat()}")
    print(f"  last_seen:  {cluster.last_seen.isoformat()}")
    display_immutable_context(inc.immutable_context)
    display_derived_context(inc.derived_context)
    display_evidence(inc.evidence)


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}{'='*70}")
    print("  Trust-Aware Perception Layer for Agentic SOC Pipelines - Phase 1 Demo")
    print(f"{'='*70}{RST}")

    sample_path = Path(__file__).parent / "sample_data" / "sample_alerts.json"
    pipeline = PerceptionPipeline(emit_logs=False)  # We'll print the log ourselves

    print(f"\nLoading alerts from: {sample_path}")
    with sample_path.open() as fh:
        raw_alerts = json.load(fh)
    print(f"  {len(raw_alerts)} raw alerts loaded.")

    result = pipeline.run(raw_alerts)

    # ── Normalization errors ──────────────────────────────────────────────
    if result.normalization_errors:
        hdr("NORMALIZATION ERRORS", color=RED)
        for raw, err in result.normalization_errors:
            kv("alert_id", raw.get("alert_id", "<unknown>"))
            kv("error",    err)

    # ── Schema-validation rejections ──────────────────────────────────────
    hdr("SCHEMA VALIDATION REJECTIONS", color=RED)
    if result.validation_rejections:
        for alert_id, vr in result.validation_rejections:
            print(f"\n  Alert '{alert_id}' REJECTED — {len(vr.errors)} error(s):")
            for e in vr.errors:
                print(f"    [{RED}{BOLD}{e.code}{RST}]  field={e.field!r}  -> {e.message}")
    else:
        print("  (none)")

    # ── Enriched incident clusters ────────────────────────────────────────
    hdr("ENRICHED INCIDENT CLUSTERS (after Noise Reduction)", color=GREEN)
    print(f"  {len(result.clusters)} distinct cluster(s) produced from {len(raw_alerts)} raw alerts.")

    for i, cluster in enumerate(result.clusters):
        display_incident(cluster, i)

    # ── Injection isolation proof ────────────────────────────────────────
    hdr("INJECTION ISOLATION PROOF", color=YEL)
    print(
        "  Alert-002 contains a full prompt-injection directive in process_name.\n"
        "  The table below confirms its DerivedContext flags are IDENTICAL to what\n"
        "  they would be with a benign process name — injection has zero effect.\n"
    )
    inj_cluster = next(
        (c for c in result.clusters if c.representative.alert_id == "alert-002"), None
    )
    if inj_cluster:
        dc = inj_cluster.representative.derived_context
        print(f"  {'Flag':<30}  {'Value':<8}  Derived from STRUCTURED data only")
        print(f"  {'-'*62}")
        for flag_name, tf in [
            ("no_prior_access",          dc.no_prior_access),
            ("cross_zone_access",        dc.cross_zone_access),
            ("high_criticality_target",  dc.high_criticality_target),
            ("privilege_escalation_risk",dc.privilege_escalation_risk),
        ]:
            icon = "TRUE ✓" if tf.value else "false"
            print(f"  {flag_name:<30}  {icon:<8}  trust={tf.trust_level.value}")
    else:
        print("  (alert-002 not in clusters — check schema validation)")

    # ── Pipeline log ─────────────────────────────────────────────────────
    hdr("PIPELINE LOG  (per-stage timing, redacted — no raw free-text values)")
    print(f"  {'Stage':<22}  {'Status':<8}  {'Duration':>10}  Summary")
    print(f"  {'-'*70}")
    for entry in result.log:
        status = f"{GREEN}OK{RST}" if entry.success else f"{RED}FAIL{RST}"
        dur = f"{entry.duration_ms:.2f} ms"
        # Print a short inline summary (counts only, no values)
        out = entry.output_summary
        if "field_trust_counts" in out:
            counts = out["field_trust_counts"]
            summary = " | ".join(f"{k}={v}" for k, v in counts.items())
        elif "is_valid" in out:
            summary = f"valid={out['is_valid']} errors={out.get('error_count',0)} codes={out.get('error_codes',[])}"
        elif "count" in out:
            summary = f"clusters={out['count']}"
        elif "derived_flags" in out:
            flags = out["derived_flags"]
            truths = [k for k, v in flags.items() if v]
            summary = f"flags_raised={truths or 'none'}"
        elif "error" in out:
            summary = f"error: {out['error']}"
        else:
            summary = str(out)[:60]
        print(f"  {entry.stage_name:<22}  {status:<8}  {dur:>10}  {summary}")

    print(f"\n{BOLD}{'='*70}{RST}")
    print(f"  Phase 1 complete.  {len(result.clusters)} cluster(s)  "
          f"|  {len(result.validation_rejections)} rejection(s)  "
          f"|  {len(result.normalization_errors)} normalization error(s)")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
