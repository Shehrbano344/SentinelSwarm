import os
from typing import TypedDict, Annotated, List, Dict, Any
from langgraph.graph import StateGraph, END
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import HumanMessage, SystemMessage
from .schemas import ReasoningTrace
from .tools.threat_intel import enrich_ioc
from .confidence import apply_guardrails
import json

class GraphState(TypedDict):
    alert_data: Dict[str, Any]
    enriched_data: List[Dict[str, Any]]
    reasoning_trace: Dict[str, Any]

def _read_prompt():
    prompt_path = os.path.join(os.path.dirname(__file__), "prompts", "triage_system_prompt.md")
    with open(prompt_path, "r") as f:
        return f.read()

def parse_node(state: GraphState):
    # Currently, the input alert_data is already structured by FastAPI.
    # In a real system, this might use LLM to extract IOCs from raw text.
    # For now, we just pass it along.
    return {"alert_data": state["alert_data"], "enriched_data": [], "reasoning_trace": {}}

def enrich_node(state: GraphState):
    alert = state["alert_data"]
    enriched = []
    
    for field in ["ip_address", "domain", "url", "file_hash"]:
        ioc = alert.get(field)
        if ioc:
            ioc_type = field.split("_")[0] if "_" in field else field
            res = enrich_ioc(ioc, ioc_type)
            if res and res.get("malicious"):
                enriched.append(res)
                
    return {"enriched_data": enriched}

def reason_node(state: GraphState):
    alert = state["alert_data"]
    enriched = state["enriched_data"]
    
    sys_prompt = _read_prompt()
    
    # We use a fallback if the API key isn't provided yet
    # Use runtime API key if set, otherwise fall back to environment variable
    try:
        from backend.config import runtime_anthropic_api_key
    except ImportError:
        runtime_anthropic_api_key = None
    api_key = runtime_anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key == "your_anthropic_api_key_here":
        raw_log = alert.get("raw_log", "Unknown").lower()
        
        # Realistic templated responses based on raw_log
        if "login" in raw_log or "brute force" in raw_log or "authentication" in raw_log:
            mock_trace = {
                "severity": "High" if enriched else "Low",
                "confidence": 0.85,
                "explanation": f"Multiple failed login attempts detected. {'Threat intel confirms malicious IP.' if enriched else 'Likely a forgotten password or misconfigured script.'}",
                "evidence_used": ["alert data", "threat intel"] if enriched else ["alert data"],
                "threat_intel_matches": [e.get("ioc") for e in enriched],
                "recommended_action": "Block IP and reset user credentials." if enriched else "Monitor for continued failures."
            }
        elif "malware" in raw_log or "ransomware" in raw_log or "virus" in raw_log or "payload" in raw_log:
            mock_trace = {
                "severity": "Critical",
                "confidence": 0.95,
                "explanation": "Known malware signature or payload execution detected on the endpoint.",
                "evidence_used": ["alert data", "file hash/domain"],
                "threat_intel_matches": [e.get("ioc") for e in enriched],
                "recommended_action": "Isolate host immediately and initiate incident response playbook."
            }
        elif "phishing" in raw_log or "email" in raw_log or "injection" in raw_log:
            mock_trace = {
                "severity": "Medium",
                "confidence": 0.75,
                "explanation": "Suspicious attack vector (e.g. injection or phishing) detected.",
                "evidence_used": ["alert data"],
                "threat_intel_matches": [e.get("ioc") for e in enriched],
                "recommended_action": "Investigate immediately."
            }
        else:
            mock_trace = {
                "severity": "Medium",
                "confidence": 0.6,
                "explanation": f"Mock response for log: {raw_log}. API key is not configured.",
                "evidence_used": ["Mock data"],
                "threat_intel_matches": [e.get("ioc") for e in enriched],
                "recommended_action": "Review manually or configure API key for full reasoning."
            }
            
        return {"reasoning_trace": mock_trace}

    llm = ChatAnthropic(model="claude-3-haiku-20240307", temperature=0.0)
    # Configure structured output using Langchain's with_structured_output
    structured_llm = llm.with_structured_output(ReasoningTrace)
    
    user_content = f"Alert Data:\n{json.dumps(alert, indent=2)}\n\n"
    if enriched:
        user_content += f"Enrichment Data:\n{json.dumps(enriched, indent=2)}"
    else:
        user_content += "Enrichment Data: None or clean."

    messages = [
        SystemMessage(content=sys_prompt),
        HumanMessage(content=user_content)
    ]
    
    try:
        result = structured_llm.invoke(messages)
        # Convert pydantic object to dict
        trace_dict = result.model_dump()
    except Exception as e:
        # Fallback if LLM fails
        trace_dict = {
            "severity": "Needs Human Review",
            "confidence": 0.0,
            "explanation": f"LLM parsing failed or API error: {str(e)}",
            "evidence_used": [],
            "threat_intel_matches": [],
            "recommended_action": "Manually review alert and system logs."
        }
        
    return {"reasoning_trace": trace_dict}

def guardrail_node(state: GraphState):
    trace = state["reasoning_trace"]
    safe_trace = apply_guardrails(trace)
    return {"reasoning_trace": safe_trace}

# Define the graph
workflow = StateGraph(GraphState)

workflow.add_node("parse", parse_node)
workflow.add_node("enrich", enrich_node)
workflow.add_node("reason", reason_node)
workflow.add_node("guardrail", guardrail_node)

workflow.set_entry_point("parse")
workflow.add_edge("parse", "enrich")
workflow.add_edge("enrich", "reason")
workflow.add_edge("reason", "guardrail")
workflow.add_edge("guardrail", END)

triage_app = workflow.compile()

def process_alert(alert_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Entry point to run the LangGraph workflow on an alert."""
    initial_state = {"alert_data": alert_dict, "enriched_data": [], "reasoning_trace": {}}
    final_state = triage_app.invoke(initial_state)
    return final_state["reasoning_trace"]
