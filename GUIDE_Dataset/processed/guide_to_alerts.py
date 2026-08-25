"""
guide_to_alerts.py
-------------------
Converts our GUIDE-derived contaminated CSVs (Id, EntityType, Category,
IncidentGrade, raw_log_text, synth_* fields, is_contaminated, ...) into the
alert-dict schema the agentsoc PerceptionPipeline (AlertNormalizer /
AlertSchemaValidator) expects:

  required:  alert_id, source_system, event_type, timestamp, source_user,
             source_host, target_host, severity
  optional (free text): process_name, command_line, registry_key,
             parent_process, file_path, raw_log_line

*** VERIFY BEFORE USE ***
Two mappings below (CATEGORY_TO_EVENT_TYPE and GRADE_TO_SEVERITY) are best
guesses. Confirm the actual supported event_type enum and severity values
against perception/schema_validation.py (or wherever AlertSchemaValidator
defines them) and adjust the dicts accordingly -- this script will raise/flag
unmapped categories rather than silently guessing wrong.
"""
import json
import pandas as pd

# ---------------------------------------------------------------------------
# CONFIRM THESE against your actual AlertSchemaValidator enum values
# ---------------------------------------------------------------------------
CATEGORY_TO_EVENT_TYPE = {
    "SuspiciousActivity": "process_create",
    "Exfiltration": "data_exfiltration",
    "Malware": "process_create",
    "InitialAccess": "logon",
    "DefenseEvasion": "process_create",
    "CommandAndControl": "network_connect",
    "Impact": "process_create",
    "LateralMovement": "lateral_movement",
    "Execution": "process_create",
    "Collection": "process_create",
    "Discovery": "process_create",
    "Persistence": "registry_write",
    "UnwantedSoftware": "process_create",
    "CredentialAccess": "process_create",
    "PrivilegeEscalation": "privilege_escalation",
}

GRADE_TO_SEVERITY = {
    "TruePositive": "high",
    "FalsePositive": "low",
    "BenignPositive": "low",
}

# source_system must be one of EDR / SIEM / WINDOWS_EVENT_LOG per the audit.
# GUIDE is a SIEM-aggregated incident dataset, so default to SIEM; process/
# registry-heavy rows plausibly came from EDR telemetry -- adjust if your
# validator cares about this distinction.
def infer_source_system(entity_type):
    if entity_type in ("Process", "RegistryKey", "RegistryValueName", "RegistryValueData", "File"):
        return "EDR"
    return "SIEM"


def convert_row(row) -> dict:
    event_type = CATEGORY_TO_EVENT_TYPE.get(row.get("Category"))
    if event_type is None:
        event_type = "UNKNOWN"  # flagged below for manual review

    severity = GRADE_TO_SEVERITY.get(row.get("IncidentGrade"), "MEDIUM")

    alert = {
        "alert_id": str(row["Id"]),
        "source_system": infer_source_system(row.get("EntityType")),
        "event_type": event_type,
        "timestamp": row.get("Timestamp"),
        "source_user": row.get("synth_account_name"),
        "source_host": row.get("synth_device_name"),
        "target_host": row.get("synth_device_name"),  # GUIDE has no distinct target host; using source as placeholder
        "severity": severity,
        # optional free-text fields -- these are where contamination lives
        "process_name": row.get("synth_process_name"),
        "command_line": row.get("synth_command_line"),
        "registry_key": row.get("synth_registry_key"),
        "parent_process": row.get("synth_parent_process") if "synth_parent_process" in row and pd.notna(row.get("synth_parent_process")) else None,  # GUIDE doesn't capture parent process lineage
        "file_path": row.get("synth_file_path"),
        "raw_log_line": row.get("raw_log_text"),  # contains the injected payload when is_contaminated=True
        # metadata for evaluation -- NOT part of the pipeline schema, strip
        # before feeding to AlertNormalizer if it rejects unknown keys
        "_ground_truth_is_contaminated": bool(row.get("is_contaminated")),
        "_ground_truth_injection_category": row.get("injection_category") if pd.notna(row.get("injection_category")) else None,
        "_source_incident_grade": row.get("IncidentGrade"),
    }
    return alert


def convert_csv(csv_path: str, out_path: str):
    df = pd.read_csv(csv_path)
    alerts = [convert_row(r) for _, r in df.iterrows()]

    unknown = [a["alert_id"] for a in alerts if a["event_type"] == "UNKNOWN"]
    if unknown:
        print(f"WARNING: {len(unknown)} rows had an unmapped Category -> event_type='UNKNOWN'. "
              f"Check CATEGORY_TO_EVENT_TYPE. Example alert_ids: {unknown[:5]}")

    with open(out_path, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"Wrote {len(alerts)} alerts to {out_path} "
          f"({sum(a['_ground_truth_is_contaminated'] for a in alerts)} contaminated)")


if __name__ == "__main__":
    from pathlib import Path
    current_dir = Path(__file__).parent
    convert_csv(
        str(current_dir / "guide_sample_500_contaminated.csv"),
        str(current_dir / "guide_sample_500_alerts.json"),
    )
    convert_csv(
        str(current_dir / "guide_test_500_contaminated.csv"),
        str(current_dir / "guide_test_500_alerts.json"),
    )
