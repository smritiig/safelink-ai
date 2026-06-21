"""
Integration tests for GET /{code} — the redirect endpoint.

Async scanning added a `status` field ("pending" | "completed" | "blocked")
to Link. _make_link() defaults to status="completed" so existing
risk_score-based routing tests represent "scan already finished" scenarios,
matching what they tested before async scanning existed. New tests below
cover the "pending" and "blocked" branches specifically.
"""
import datetime as dt
from app.models import Link


def _make_link(db_session, **overrides):
    defaults = dict(
        code="abc123",
        original_url="https://example.com/page",
        created_at=dt.datetime.utcnow(),
        expires_at=None,
        one_time=False,
        status="completed",
        risk_score=2,
        risk_reason="fine",
    )
    defaults.update(overrides)
    link = Link(**defaults)
    db_session.add(link)
    db_session.commit()
    return link


def test_redirect_unknown_code_returns_404(client):
    res = client.get("/zzzzzz", follow_redirects=False)
    assert res.status_code == 404


# ── status: pending / blocked (new with async scanning) ────────────────────

def test_redirect_pending_link_routes_to_scanning_page(client, db_session):
    # A link whose background scan hasn't finished yet must never redirect
    # to the destination OR the preview page — it has no risk_score to
    # decide between them. It goes to a dedicated "still scanning" page.
    _make_link(db_session, code="pend01", status="pending", risk_score=None, risk_reason=None)

    res = client.get("/pend01", follow_redirects=False)

    assert res.status_code in (302, 307)
    assert res.headers["location"] == "/scanning/pend01"


def test_redirect_blocked_link_returns_403_not_the_destination(client, db_session):
    # status="blocked" means the background scan finished and scored >= 9 —
    # this must never redirect to original_url under any circumstance.
    _make_link(
        db_session, code="block1", status="blocked",
        original_url="http://evil.tk/phish", risk_score=10, risk_reason="malicious",
    )

    res = client.get("/block1", follow_redirects=False)

    assert res.status_code == 403
    # Confirm no redirect header pointing at the malicious destination exists
    assert "location" not in res.headers or "evil.tk" not in res.headers.get("location", "")


def test_redirect_completed_safe_link_redirects_to_destination(client, db_session):
    _make_link(db_session, code="safe01", status="completed", risk_score=2)

    res = client.get("/safe01", follow_redirects=False)

    assert res.status_code in (302, 307)
    assert res.headers["location"] == "https://example.com/page"


def test_redirect_completed_high_risk_link_routes_to_preview_not_destination(client, db_session):
    # A "completed" scan with risk_score 7-8 (below the 9+ blocked threshold)
    # still routes to the warning preview page rather than redirecting
    # straight through — this is the core security behavior of the app.
    _make_link(
        db_session, code="risky1", status="completed",
        original_url="http://evil.tk/phish", risk_score=8,
    )

    res = client.get("/risky1", follow_redirects=False)

    assert res.status_code in (302, 307)
    assert res.headers["location"] == "/preview/risky1"
    assert "evil.tk" not in res.headers["location"]


def test_redirect_boundary_score_6_passes_score_7_routes_to_preview(client, db_session):
    _make_link(db_session, code="bound6", status="completed", risk_score=6)
    res = client.get("/bound6", follow_redirects=False)
    assert res.headers["location"] == "https://example.com/page"

    _make_link(db_session, code="bound7", status="completed", risk_score=7)
    res = client.get("/bound7", follow_redirects=False)
    assert res.headers["location"] == "/preview/bound7"


def test_redirect_boundary_score_8_previews_score_9_blocks(client, db_session):
    # The blocked threshold (>=9, set in run_analysis) is distinct from the
    # preview threshold (>=7, checked in redirect()) — pin both boundaries.
    _make_link(db_session, code="bound8", status="completed", risk_score=8)
    res = client.get("/bound8", follow_redirects=False)
    assert res.headers["location"] == "/preview/bound8"

    _make_link(db_session, code="bound9", status="blocked", risk_score=9)
    res = client.get("/bound9", follow_redirects=False)
    assert res.status_code == 403


# ── expiry ───────────────────────────────────────────────────────────────

def test_redirect_expired_link_returns_410_even_with_stale_cache_entry(client, db_session, fake_redis):
    # Expiry is checked before both the pending/blocked status check and the
    # cache lookup, so an expired link can't keep serving redirects just
    # because Redis still has a cached entry within its independent TTL.
    past = dt.datetime.utcnow() - dt.timedelta(days=1)
    _make_link(db_session, code="dead01", status="completed", expires_at=past)
    fake_redis.store["url:dead01"] = "https://example.com/page"  # stale cache entry

    res = client.get("/dead01", follow_redirects=False)

    assert res.status_code == 410
    assert "url:dead01" not in fake_redis.store  # cache_delete() runs in the expired branch


# ── cache behavior ───────────────────────────────────────────────────────

def test_redirect_uses_cache_on_hit_without_touching_risk_score(client, db_session, fake_redis):
    # Documents a real tradeoff: once a URL is cached, the redirect path
    # serves the cached destination without re-checking risk_score from
    # Postgres — even if the row's risk_score was updated since caching.
    # expires_at IS re-checked on every request; risk_score and status are not.
    _make_link(db_session, code="cached1", status="completed", original_url="https://example.com/from-cache", risk_score=9)
    fake_redis.store["url:cached1"] = "https://example.com/from-cache"

    res = client.get("/cached1", follow_redirects=False)

    assert res.status_code in (302, 307)
    assert res.headers["location"] == "https://example.com/from-cache"


def test_redirect_populates_cache_after_db_lookup(client, db_session, fake_redis):
    _make_link(db_session, code="fresh1", status="completed", original_url="https://example.com/new", risk_score=1)
    assert "url:fresh1" not in fake_redis.store

    client.get("/fresh1", follow_redirects=False)

    assert fake_redis.store["url:fresh1"] == "https://example.com/new"


# ── one-time links ───────────────────────────────────────────────────────

def test_redirect_one_time_link_is_deleted_after_use(client, db_session, fake_redis):
    _make_link(db_session, code="once01", status="completed", original_url="https://example.com/secret", one_time=True, risk_score=1)

    res = client.get("/once01", follow_redirects=False)
    assert res.status_code in (302, 307)

    assert db_session.query(Link).filter(Link.code == "once01").first() is None
    assert "url:once01" not in fake_redis.store

    res2 = client.get("/once01", follow_redirects=False)
    assert res2.status_code == 404


def test_redirect_one_time_high_risk_link_goes_to_preview_and_is_not_deleted(client, db_session):
    # one_time deletion only happens in the safe-redirect branch — a flagged
    # one-time link routed to /preview should NOT be consumed yet, since the
    # user hasn't confirmed they want to proceed.
    _make_link(db_session, code="onceX", status="completed", one_time=True, risk_score=9)

    res = client.get("/onceX", follow_redirects=False)

    assert res.headers["location"] == "/preview/onceX"
    assert db_session.query(Link).filter(Link.code == "onceX").first() is not None


# ── /api/link/{code} ─────────────────────────────────────────────────────

def test_get_link_info_returns_status_and_metadata(client, db_session):
    _make_link(
        db_session,
        code="info01",
        status="blocked",
        original_url="http://evil.tk/phish",
        risk_score=8,
        risk_reason="Misspelled brand + suspicious TLD",
    )

    res = client.get("/api/link/info01")

    assert res.status_code == 200
    body = res.json()
    assert body["original_url"] == "http://evil.tk/phish"
    assert body["status"] == "blocked"
    assert body["risk_score"] == 8
    assert body["risk_reason"] == "Misspelled brand + suspicious TLD"


def test_get_link_info_unknown_code_returns_404(client):
    res = client.get("/api/link/doesnotexist")
    assert res.status_code == 404


# ── scanning/preview page routes return HTML ────────────────────────────

def test_scanning_page_renders_for_pending_link(client, db_session):
    _make_link(db_session, code="scan01", status="pending", risk_score=None, risk_reason=None)

    res = client.get("/scanning/scan01")

    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]


def test_preview_page_renders_for_blocked_link(client, db_session):
    _make_link(db_session, code="prev01", status="blocked", risk_score=9)

    res = client.get("/preview/prev01")

    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]