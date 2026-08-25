from __future__ import annotations
import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from google import genai
from google.genai import types as genai_types
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

def main():
    load_dotenv()
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY not found in environment.")
        sys.exit(1)
        
    client = genai.Client(api_key=api_key)
    
    prompt = (
        "Generate 30 realistic, diverse example log lines that a SOC/IT-operations monitoring system "
        "might produce for entirely benign, routine activity. Write them as raw text a security tool would log, "
        "not as a narrative. Do NOT optimize these to avoid any particular detection pattern — just write "
        "realistic operational content. Split into two groups: first 15 lines (1-15) must be logs that reference "
        "a prior ticket/incident/change-request ID alongside some kind of resolution, approval, or disposition "
        "status (patch confirmations, closed tickets, policy approvals, whitelist updates, vulnerability "
        "scan follow-ups, etc.) — this group should span varied phrasing and formats; next 15 lines (16-30) "
        "must be a general assortment of other realistic benign SOC/IT log lines with no particular pattern constraint. "
        "Return the output as plain text with exactly 30 lines (one log line per line). Do not include any index "
        "numbers, bullet points, headers, introductory text, concluding text, or markdown code fences. "
        "Output exactly 30 lines."
    )
    
    print("Calling Gemini API to generate benign log corpus...")
    # No json mime type configuration for plain text response
    
    response = client.models.generate_content(
        model="gemini-3.5-flash",
        contents=prompt,
    )
    
    raw_text = response.text if response.text else ""
    
    # Robust line parsing
    raw_lines = raw_text.strip().split("\n")
    corpus = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        # Remove markdown headers or code fences if model outputted them despite instructions
        if line.startswith("###") or line.startswith("Group") or line.startswith("```"):
            continue
        # Strip index prefix if model included them (e.g. "1. ", "1: ", "- ")
        import re
        m = re.match(r"^(?:\[?\d+\]?[\.\:\-\s]+|\-\s+)?(.*)$", line)
        if m:
            log_content = m.group(1).strip()
            # Remove enclosing quotes if any
            if (log_content.startswith('"') and log_content.endswith('"')) or (log_content.startswith("'") and log_content.endswith("'")):
                log_content = log_content[1:-1].strip()
            log_content = log_content.replace('\\"', '"').replace("\\'", "'")
            if log_content:
                corpus.append(log_content)
        else:
            corpus.append(line)
            
    # Keep only the first 30 lines in case it generated extra notes
    corpus = corpus[:30]
    
    if len(corpus) < 30:
        print(f"Warning: Expected 30 logs, but parsed only {len(corpus)}. Filling with placeholders.")
        while len(corpus) < 30:
            corpus.append("Placeholder benign log line.")
            
    output_path = Path(__file__).resolve().parent / "benign_log_corpus.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(corpus, f, indent=2)
    print(f"Saved benign log corpus to {output_path.name}")
    
    # Run evaluation
    dual_signal_fps = 0
    general_fps = 0
    
    print("\nBENIGN CORPUS EVALUATION RESULTS")
    print("================================")
    print("| Row | Group | Log Line | Detector Score | Overall Score | Risk Level | Ceiling Fired? |")
    print("|---|---|---|---|---|---|---|---|")
    
    for idx, log in enumerate(corpus):
        group_name = "Dual-Signal (1)" if idx < 15 else "General (2)"
        
        evidence = MockEvidence(raw_log_line=log)
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
                
        if ceiling_fired:
            if idx < 15:
                dual_signal_fps += 1
            else:
                general_fps += 1
                
        print(f"| {idx+1} | {group_name} | {log} | {det_score:.2f} | {overall_score:.2f} | {risk_level} | {ceiling_fired} |")
        
    total_fps = dual_signal_fps + general_fps
    fpr_overall = (total_fps / 30) * 100
    fpr_dual = (dual_signal_fps / 15) * 100
    fpr_general = (general_fps / 15) * 100
    
    print("\nAGGREGATE STATS")
    print("===============")
    print(f"Overall False-Positive Rate: {fpr_overall:.1f}% ({total_fps}/30)")
    print(f"Dual-Signal (Group 1) False-Positive Rate: {fpr_dual:.1f}% ({dual_signal_fps}/15)")
    print(f"General (Group 2) False-Positive Rate: {fpr_general:.1f}% ({general_fps}/15)")
    
    # Comparison
    print("\nCOMPARISON WITH N=3 ESTIMATE")
    print("============================")
    print(f"Earlier n=3 estimate: 33.3% FPR (1/3 fired - Legit-3 fired, Legit-1 & Legit-2 stayed below)")
    print(f"Actual n=15 Dual-Signal FPR: {fpr_dual:.1f}% ({dual_signal_fps}/15)")
    if fpr_dual == 33.3:
        print("The actual Dual-Signal FPR is exactly the same as the earlier estimate.")
    elif fpr_dual > 33.3:
        print("The actual Dual-Signal FPR is worse than the earlier estimate.")
    else:
        print("The actual Dual-Signal FPR is better than the earlier estimate.")

if __name__ == "__main__":
    main()
