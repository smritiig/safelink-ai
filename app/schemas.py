from pydantic import BaseModel, HttpUrl
from typing import Optional

class ShortenRequest(BaseModel):
    url: HttpUrl
    expires_in_days: Optional[int] = None
    one_time: bool = False

class ShortenResponse(BaseModel):
    code: str
    short_url: str
    risk_score: int
    risk_reason: str