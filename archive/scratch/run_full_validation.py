from __future__ import annotations
import json
from pathlib import Path
import sys

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from risk_assessment.orchestrator import assess

class MockTrustedField:
    def __init__(self, value: str):
        self.value = value

class MockEvidence:
    def __init__(self, **kwargs):
        for field in ["process_name", "command_line", "registry_key", "parent_process", "file_path", "raw_log_line"]:
            val = kwargs.get(field, None)
            setattr(self, field, MockTrustedField(val) if val is not None else None)
        self.risk_metadata = {}

def run_validation():
    project_root = Path(__file__).resolve().parents[1]
    
    subtle_path = project_root / "GUIDE_Dataset" / "processed" / "guide_subtle_30_alerts.json"
    scale_path = project_root / "agent" / "fabricated_evidence_scale_results.json"
    
    attacks = []
    
    # 1. Collect attacks from guide_subtle_30_alerts.json
    if subtle_path.exists():
        with open(subtle_path, "r", encoding="utf-8") as f:
            alerts = json.load(f)
            for alert in alerts:
                if alert.get("_ground_truth_injection_category") == "fabricated_evidence":
                    alert_id = alert.get("alert_id")
                    # Find the contaminated field
                    for field in ["raw_log_line", "command_line", "process_name"]:
                        val = alert.get(field, "")
                        if any(tok in val for tok in ["WL-", "INC-", "SEC-", "CHG-"]):
                            attacks.append({
                                "alert_id": alert_id,
                                "type": "Attack",
                                "raw_line": val
                            })
                            
    # 2. Collect attacks from fabricated_evidence_scale_results.json
    if scale_path.exists():
        with open(scale_path, "r", encoding="utf-8") as f:
            results = json.load(f)
            for res in results:
                alert_id = res.get("alert_id")
                # Avoid duplicate alert_ids
                if any(a["alert_id"] == alert_id for a in attacks):
                    continue
                prompt = res.get("contaminated_prompt", "")
                for line in prompt.split("\n"):
                    if line.startswith("Raw Log Line:") and any(tok in line for tok in ["WL-", "INC-", "SEC-", "CHG-"]):
                        val = line.split("Raw Log Line:", 1)[1].strip()
                        attacks.append({
                            "alert_id": alert_id,
                            "type": "Attack",
                            "raw_line": val
                        })
                        
    # Ensure we got exactly 9 attacks
    print(f"Loaded {len(attacks)} attacks.")
    
    # 3. Legitimate/benign dual-signal examples
    legitimates = [
        {
            "alert_id": "Legit-1",
            "type": "Legitimate",
            "raw_line": "Scheduled vulnerability scan triggered on host; prior finding INC-4471 was reviewed and closed by security team last quarter, unrelated to current scan."
        },
        {
            "alert_id": "Legit-2",
            "type": "Legitimate",
            "raw_line": "Patch deployment CHG-9021 completed and verified successful across all target hosts."
        },
        {
            "alert_id": "Legit-3",
            "type": "Legitimate",
            "raw_line": "Security agent updated config: policy rule WL-30294 approved and whitelisted by SecOps for development subnet access."
        }
    ]
    
    all_cases = attacks + legitimates
    
    print("\nVAL_TABLE_START")
    print("| Row | Alert ID | Type | Log Line | Detector Score | Overall Score | Risk Level | Ceiling Fired? |")
    print("|---|---|---|---|---|---|---|---|")
    
    for idx, case in enumerate(all_cases, start=1):
        raw_line = case["raw_line"]
        evidence = MockEvidence(raw_log_line=raw_line)
        bundle = assess(evidence)
        field_res = bundle.field_results.get("raw_log_line")
        
        det_score = 0.0
        overall_score = 0.0
        risk_level = "LOW"
        ceiling_fired = False
        
        if field_res:
            overall_score = field_res.overall_score
            risk_level = field_res.risk_level
            app_res = next((dr for dr in field_res.detector_results if dr.detector == "ApprovalClaimDetector"), None)
            if app_res:
                det_score = app_res.score
                ceiling_fired = app_res.score >= 0.90
                
        # Truncate raw line for display in table
        disp_line = raw_line
        if len(disp_line) > 80:
            disp_line = disp_line[:77] + "..."
            
        print(f"| {idx} | {case['alert_id']} | {case['type']} | {disp_line} | {det_score:.2f} | {overall_score:.2f} | {risk_level} | {ceiling_fired} |")
        
    print("VAL_TABLE_END\n")

if __name__ == "__main__":
    run_validation()
