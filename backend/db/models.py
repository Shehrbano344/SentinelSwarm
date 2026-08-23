from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Float
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()

class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    raw_log = Column(Text)
    
    # IOCs
    ip_address = Column(String, nullable=True)
    domain = Column(String, nullable=True)
    url = Column(String, nullable=True)
    file_hash = Column(String, nullable=True)

    # Workflow
    status = Column(String, default="pending") # pending, approved, rejected
    analyst_note = Column(Text, nullable=True)

    # Agent output
    reasoning_trace = Column(JSON, nullable=True)
