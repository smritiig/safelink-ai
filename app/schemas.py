from pydantic import BaseModel, HttpUrl
from typing import Optional

class ShortenRequest(BaseModel):
    url: HttpUrl
    expires_in_days: Optional[int] = None
    one_time: bool = False

class ShortenResponse(BaseModel):
    code: str
    short_url: str
    status: str  # "pending" — risk fields aren't known yet at creation time

class StatusResponse(BaseModel):
    code: str
    status: str  # "pending" | "completed" | "blocked"
    risk_score: Optional[int] = None
    risk_reason: Optional[str] = None