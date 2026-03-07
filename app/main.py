import secrets
import string
import datetime as dt
from collections import defaultdict
from urllib.parse import urlparse

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from .cache import cache_get_url, cache_set_url, cache_delete
from .risk import analyze_url
from .db import Base, engine, get_db, wait_for_db
from .models import Link
from .schemas import ShortenRequest, ShortenResponse
from .config import settings
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI, Depends, HTTPException, Request

app = FastAPI(title="SafeLink AI")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    wait_for_db(max_seconds=60)
    Base.metadata.create_all(bind=engine)

app.mount("/web", StaticFiles(directory="web"), name="web")

ALPHABET = string.ascii_letters + string.digits

def generate_code(length: int = 6):
    return ''.join(secrets.choice(ALPHABET) for _ in range(length))

@app.get("/", response_class=HTMLResponse)
def home():
    return open("web/index.html", "r").read()

@app.post("/api/shorten", response_model=ShortenResponse)
@limiter.limit("10/minute")
def shorten(request: Request, payload: ShortenRequest, db: Session = Depends(get_db)):
    expires_at = None
    if payload.expires_in_days:
        expires_at = dt.datetime.utcnow() + dt.timedelta(days=payload.expires_in_days)

    for _ in range(10):
        code = generate_code()
        if not db.query(Link).filter(Link.code == code).first():
            break
    else:
        raise HTTPException(status_code=500, detail="Code generation failed")

    risk_score, risk_reason = analyze_url(str(payload.url))
    if risk_score >= 9:
        raise HTTPException(
        status_code=400,
        detail=f"URL blocked: {risk_reason}"
    )

    link = Link(
        code=code,
        original_url=str(payload.url),
        expires_at=expires_at,
        one_time=payload.one_time,
        risk_score=risk_score,
        risk_reason=risk_reason,
    )

    db.add(link)
    db.commit()

    return ShortenResponse(
        code=code,
        short_url=f"{settings.BASE_URL}/{code}",
        risk_score=risk_score,
        risk_reason=risk_reason,
    )

@app.get("/preview/{code}", response_class=HTMLResponse)
def preview(code: str):
    html = open("web/preview.html", "r").read()
    return html.replace("{{CODE}}", code)

@app.get("/{code}")
def redirect(code: str, db: Session = Depends(get_db)):
    cached_url = cache_get_url(code)
    if cached_url:
        return RedirectResponse(url=cached_url)

    link = db.query(Link).filter(Link.code == code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    if link.expires_at and dt.datetime.utcnow() > link.expires_at:
        cache_delete(code)
        raise HTTPException(status_code=410, detail="Link expired")

    if link.risk_score is not None and link.risk_score >= 7:
        return RedirectResponse(url=f"/preview/{code}")

    target = link.original_url
    cache_set_url(code, target, ttl_seconds=3600)

    if link.one_time:
        db.delete(link)
        db.commit()
        cache_delete(code)

    return RedirectResponse(url=target)

@app.get("/api/link/{code}")
def get_link_info(code: str, db: Session = Depends(get_db)):
    link = db.query(Link).filter(Link.code == code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    return {
        "original_url": link.original_url,
        "risk_score": link.risk_score,
        "risk_reason": link.risk_reason
    }

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    all_links = db.query(Link).all()

    total = len(all_links)
    if total == 0:
        return {
            "total_scanned": 0,
            "average_risk_score": 0,
            "safe_count": 0,
            "blocked_count": 0,
            "risk_distribution": {"safe": 0, "suspicious": 0, "high_risk": 0},
            "top_risky_domains": [],
            "recent_links": [],
            "scan_volume_over_time": [],
        }

    scores = [l.risk_score for l in all_links if l.risk_score is not None]
    average_risk = round(sum(scores) / len(scores), 1) if scores else 0
    safe_count = sum(1 for s in scores if s <= 3)
    suspicious_count = sum(1 for s in scores if 4 <= s <= 6)
    high_risk_count = sum(1 for s in scores if s >= 7)
    blocked_count = high_risk_count

    # Top risky domains
    domain_risk = defaultdict(list)
    for link in all_links:
        if link.risk_score and link.risk_score >= 4:
            try:
                domain = urlparse(link.original_url).netloc
                domain_risk[domain].append(link.risk_score)
            except Exception:
                pass

    top_risky_domains = sorted(
        [{"domain": d, "avg_score": round(sum(s)/len(s), 1), "count": len(s)}
         for d, s in domain_risk.items()],
        key=lambda x: x["avg_score"],
        reverse=True
    )[:5]

    # Recent links (last 10)
    recent = db.query(Link).order_by(Link.created_at.desc()).limit(10).all()
    recent_links = [
        {
            "code": l.code,
            "original_url": l.original_url,
            "risk_score": l.risk_score,
            "risk_reason": l.risk_reason,
            "created_at": l.created_at.isoformat() if l.created_at else None,
        }
        for l in recent
    ]

    # Scan volume over last 7 days
    seven_days_ago = dt.datetime.utcnow() - dt.timedelta(days=7)
    recent_all = db.query(Link).filter(Link.created_at >= seven_days_ago).all()
    volume_by_day = defaultdict(int)
    for link in recent_all:
        if link.created_at:
            day = link.created_at.strftime("%Y-%m-%d")
            volume_by_day[day] += 1

    # Fill in missing days with 0
    scan_volume = []
    for i in range(7):
        day = (dt.datetime.utcnow() - dt.timedelta(days=6 - i)).strftime("%Y-%m-%d")
        scan_volume.append({"date": day, "count": volume_by_day.get(day, 0)})

    return {
        "total_scanned": total,
        "average_risk_score": average_risk,
        "safe_count": safe_count,
        "blocked_count": blocked_count,
        "risk_distribution": {
            "safe": safe_count,
            "suspicious": suspicious_count,
            "high_risk": high_risk_count,
        },
        "top_risky_domains": top_risky_domains,
        "recent_links": recent_links,
        "scan_volume_over_time": scan_volume,
    }