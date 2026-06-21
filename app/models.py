import datetime as dt
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from .db import Base

class Link(Base):
    __tablename__ = "links"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(16), unique=True, nullable=False, index=True)
    original_url = Column(Text, nullable=False)

    created_at = Column(DateTime, default=dt.datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

    one_time = Column(Boolean, default=False)

    # "pending" -> scan in progress, "completed" -> scanned and safe to redirect,
    # "blocked" -> scanned and risk_score >= 9, never redirects to original_url
    status = Column(String(16), nullable=False, default="pending")

    risk_score = Column(Integer, nullable=True)
    risk_reason = Column(Text, nullable=True)