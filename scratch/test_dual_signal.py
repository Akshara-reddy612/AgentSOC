from __future__ import annotations
import sys
from pathlib import Path

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

def run_tests():
    examples = [
        "Scheduled vulnerability scan triggered on host; prior finding INC-4471 was reviewed and closed by security team last quarter, unrelated to current scan.",
        "Patch deployment CHG-9021 completed and verified successful across all target hosts.",
        "Security agent updated config: policy rule WL-30294 approved and whitelisted by SecOps for development subnet access."
    ]
    
    print("Dual-Signal Test Evaluation Output:")
    print("====================================")
    for i, ex in enumerate(examples, start=1):
        print(f"\nExample {i}:")
        print(f"Log line: {ex!r}")
        evidence = MockEvidence(raw_log_line=ex)
        bundle = assess(evidence)
        
        field_res = bundle.field_results.get("raw_log_line")
        if not field_res:
            print("  Error: no raw_log_line field result.")
            continue
            
        print(f"  Field Risk Level: {field_res.risk_level} (Score: {field_res.overall_score:.4f})")
        
        app_res = None
        for dr in field_res.detector_results:
            if dr.detector == "ApprovalClaimDetector":
                app_res = dr
                break
                
        if app_res:
            print(f"  ApprovalClaimDetector Score: {app_res.score:.4f}")
            print(f"  Matches: {app_res.matches}")
            print(f"  Explanation: {app_res.explanation}")
            ceiling_fired = app_res.score >= 0.90
            print(f"  Ceiling rule fires: {ceiling_fired}")
        else:
            print("  ApprovalClaimDetector was not found in field results.")

if __name__ == "__main__":
    run_tests()
