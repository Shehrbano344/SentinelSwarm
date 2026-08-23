from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from ..db.session import get_db
from ..db.models import AlertModel
from agent.schemas import AlertResponse
from pydantic import BaseModel
from typing import Optional

router = APIRouter()

class ReviewRequest(BaseModel):
    analyst_note: Optional[str] = None

@router.post("/{alert_id}/approve", response_model=AlertResponse)
def approve_alert(alert_id: int, req: ReviewRequest = Body(None), db: Session = Depends(get_db)):
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = "approved"
    if req and req.analyst_note:
        alert.analyst_note = req.analyst_note
        
    db.commit()
    db.refresh(alert)
    return alert

@router.post("/{alert_id}/reject", response_model=AlertResponse)
def reject_alert(alert_id: int, req: ReviewRequest = Body(None), db: Session = Depends(get_db)):
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = "rejected"
    if req and req.analyst_note:
        alert.analyst_note = req.analyst_note
        
    db.commit()
    db.refresh(alert)
    return alert
