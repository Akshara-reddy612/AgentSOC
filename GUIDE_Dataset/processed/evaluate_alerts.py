"""
evaluate_alerts.py
------------------
Runs the regenerated contaminated GUIDE sample alerts through the 
Perception Layer (AlertNormalizer -> AlertSchemaValidator -> Contextualizer)
and reports how many contaminated alerts were correctly handled vs hijacked.
"""
import sys
import json
import re
from pathlib import Path

# Add project root directory to Python path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from perception.normalizer import AlertNormalizer
from perception.schema_validation import AlertSchemaValidator
from perception.contextualizer import Contextualizer
from perception.knowledge_store import InMemoryKnowledgeStore
from perception.models import TrustLevel

def evaluate():
    current_dir = Path(__file__).parent
    alerts_path = current_dir / "guide_sample_500_alerts.json"
    
    with open(alerts_path, "r", encoding="utf-8") as f:
        raw_alerts = json.load(f)
        
    normalizer = AlertNormalizer()
    validator = AlertSchemaValidator()
    store = InMemoryKnowledgeStore()
    contextualizer = Contextualizer(store=store)
    
    total_contaminated = 0
    correctly_handled = 0
    hijacked = 0
    
    for alert_dict in raw_alerts:
        is_contaminated = alert_dict.get("_ground_truth_is_contaminated", False)
        if not is_contaminated:
            continue
            
        total_contaminated += 1
        
        # Reconstruct clean log line by removing the injected payload pattern
        raw_log_line = alert_dict.get("raw_log_line", "")
        clean_log_line = re.sub(r' \| INJECTED_FIELD_VALUE=".*?"$', '', raw_log_line)
        
        # Contaminated run
        contam_raw = {k: v for k, v in alert_dict.items() if not k.startswith("_ground_truth_") and k != "_source_incident_grade"}
        contam_alert = normalizer.normalize(contam_raw)
        contam_val = validator.validate(contam_alert)
        
        # Clean run
        clean_raw = contam_raw.copy()
        clean_raw["raw_log_line"] = clean_log_line
        clean_alert = normalizer.normalize(clean_raw)
        clean_val = validator.validate(clean_alert)
        
        if not contam_val.is_valid or not clean_val.is_valid:
            # If schema validation fails unexpectedly
            hijacked += 1
            continue
            
        contam_incident = contextualizer.contextualize(contam_alert)
        clean_incident = contextualizer.contextualize(clean_alert)
        
        # Verify Trust Separation invariants:
        # 1. Raw log line has TrustLevel.FREE_TEXT
        is_free_text = contam_incident.evidence.raw_log_line.trust_level == TrustLevel.FREE_TEXT
        
        # 2. Immutable context has TrustLevel.STRUCTURED
        immutable_ok = all(
            getattr(contam_incident.immutable_context, f).trust_level == TrustLevel.STRUCTURED
            for f in contam_incident.immutable_context.__dataclass_fields__
        )
        
        # 3. Derived context has TrustLevel.DERIVED
        derived_ok = all(
            getattr(contam_incident.derived_context, f).trust_level == TrustLevel.DERIVED
            for f in contam_incident.derived_context.__dataclass_fields__
        )
        
        # 4. Derived context values are completely identical between clean and contaminated runs
        derived_values_match = all(
            getattr(contam_incident.derived_context, f).value == getattr(clean_incident.derived_context, f).value
            for f in contam_incident.derived_context.__dataclass_fields__
        )
        
        if is_free_text and immutable_ok and derived_ok and derived_values_match:
            correctly_handled += 1
        else:
            hijacked += 1
            
    print("=" * 60)
    print("Perception Layer Security Evaluation on GUIDE Contaminated Sample")
    print("=" * 60)
    print(f"Total Contaminated Alerts Evaluated: {total_contaminated}")
    print(f"Correctly Handled (Isolated via Trust-Separation): {correctly_handled}")
    print(f"Hijacked (Unexpected behavior / context contamination): {hijacked}")
    print("-" * 60)
    if hijacked == 0:
        print("Success: 100% of contaminated alerts were correctly handled!")
    else:
        print("Warning: Some alerts were hijacked!")
    print("=" * 60)

if __name__ == "__main__":
    evaluate()
