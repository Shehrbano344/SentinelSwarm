from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from ..db.session import get_db
from ..db.models import AlertModel
from agent.schemas import AlertCreate, AlertResponse
import json

router = APIRouter()

@router.post("/", response_model=AlertResponse)
def ingest_alert(alert: AlertCreate, db: Session = Depends(get_db)):
    db_alert = AlertModel(
        source=alert.source,
        timestamp=alert.timestamp,
        raw_log=alert.raw_log,
        ip_address=alert.ip_address,
        domain=alert.domain,
        url=alert.url,
        file_hash=alert.file_hash
    )
    
    # Note: Phase 6 will wire the LangGraph agent here.
    # For now, it just saves the alert to DB.
    
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    # Run the triage agent to produce a reasoning trace (mocked)
    from agent.triage_agent import process_alert
    # Convert the incoming pydantic model to dict for processing
    alert_dict = alert.dict()
    reasoning = process_alert(alert_dict)
    # Save the reasoning trace as JSON in the DB
    db_alert.reasoning_trace = reasoning
    db.commit()
    db.refresh(db_alert)
    return db_alert

@router.get("/", response_model=List[AlertResponse])
def list_alerts(status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(AlertModel)
    if status:
        query = query.filter(AlertModel.status == status)
    # Return newest first
    alerts = query.order_by(AlertModel.timestamp.desc()).all()
    return alerts

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
