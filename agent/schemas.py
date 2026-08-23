from pydantic import BaseModel, Field
from typing import List, Optional, Any
from datetime import datetime

class AlertBase(BaseModel):
    source: str
    timestamp: datetime
    raw_log: str
    ip_address: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    file_hash: Optional[str] = None

class AlertCreate(AlertBase):
    pass

class ReasoningTrace(BaseModel):
    severity: str = Field(description="Low, Medium, High, or Critical")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0", ge=0.0, le=1.0)
    explanation: str = Field(description="Plain-English explanation of the severity classification")
    evidence_used: List[str] = Field(description="Specific evidence extracted from the alert or enrichment data")
    threat_intel_matches: List[str] = Field(description="Matches from threat intelligence (e.g., abuse.ch)")
    recommended_action: str = Field(description="What a human analyst should do next")

class AlertResponse(AlertBase):
    id: int
    status: str = "pending" # pending, approved, rejected
    analyst_note: Optional[str] = None
    reasoning_trace: Optional[dict] = None # Store as JSON

    class Config:
        from_attributes = True
