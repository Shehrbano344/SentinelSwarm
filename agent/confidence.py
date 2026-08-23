from typing import Dict, Any

CONFIDENCE_THRESHOLD = 0.6

def apply_guardrails(trace: Dict[str, Any]) -> Dict[str, Any]:
    """
    If the confidence score is below the threshold, override the severity
    to 'Needs Human Review' and append a note to the explanation.
    """
    confidence = trace.get("confidence", 1.0)
    
    if confidence < CONFIDENCE_THRESHOLD:
        trace["severity"] = "Needs Human Review"
        trace["explanation"] += f" (Note: Confidence score {confidence} is below the {CONFIDENCE_THRESHOLD} threshold. Overriding severity for mandatory human review.)"
        
    return trace
