"""
Tests for GET /api/stats — the dashboard aggregation endpoint.

This route does real computation (bucketing, averaging, top-domains ranking,
7-day volume fill), so it's worth testing on its own rather than trusting it
because the dashboard "looked right" in manual testing.
"""
import datetime as dt
from app.models import Link


def _add(db_session, code, risk_score, url="https://example.com/x", days_ago=0):
    db_session.add(Link(
        code=code,
        original_url=url,
        risk_score=risk_score,
        risk_reason="x",
        created_at=dt.datetime.utcnow() - dt.timedelta(days=days_ago),
    ))
    db_session.commit()


def test_stats_on_empty_db_returns_zeroed_shape(client):
    res = client.get("/api/stats")
    assert res.status_code == 200
    body = res.json()

    assert body["total_scanned"] == 0
    assert body["average_risk_score"] == 0
    assert body["risk_distribution"] == {"safe": 0, "suspicious": 0, "high_risk": 0}
    assert body["top_risky_domains"] == []
    assert body["recent_links"] == []
    # Fixed: empty DB now returns the same 7-zeroed-day shape as the populated
    # path, instead of an empty list — a dashboard chart component can rely on
    # a stable 7-element array regardless of scan history.
    assert len(body["scan_volume_over_time"]) == 7
    assert all(day["count"] == 0 for day in body["scan_volume_over_time"])


def test_stats_buckets_risk_distribution_correctly(client, db_session):
    # safe: <=3, suspicious: 4-6, high_risk: >=7 — verify all three boundaries
    _add(db_session, "a", risk_score=3)   # safe
    _add(db_session, "b", risk_score=4)   # suspicious
    _add(db_session, "c", risk_score=6)   # suspicious
    _add(db_session, "d", risk_score=7)   # high risk
    _add(db_session, "e", risk_score=10)  # high risk

    res = client.get("/api/stats")
    body = res.json()

    assert body["total_scanned"] == 5
    assert body["risk_distribution"] == {"safe": 1, "suspicious": 2, "high_risk": 2}
    assert body["blocked_count"] == 2  # blocked_count mirrors high_risk_count


def test_stats_average_risk_score_rounds_to_one_decimal(client, db_session):
    _add(db_session, "a", risk_score=1)
    _add(db_session, "b", risk_score=2)
    _add(db_session, "c", risk_score=2)
    # average = 5/3 = 1.666... -> should round to 1.7

    res = client.get("/api/stats")
    assert res.json()["average_risk_score"] == 1.7


def test_stats_top_risky_domains_excludes_low_risk_and_sorts_by_avg_score(client, db_session):
    _add(db_session, "a", risk_score=2, url="https://safe-site.com/x")       # excluded, score < 4
    _add(db_session, "b", risk_score=9, url="https://evil.tk/phish1")
    _add(db_session, "c", risk_score=7, url="https://evil.tk/phish2")
    _add(db_session, "d", risk_score=5, url="https://medium-risk.com/page")

    res = client.get("/api/stats")
    domains = res.json()["top_risky_domains"]

    assert len(domains) == 2
    assert domains[0]["domain"] == "evil.tk"
    assert domains[0]["avg_score"] == 8.0  # (9+7)/2
    assert domains[0]["count"] == 2
    assert domains[1]["domain"] == "medium-risk.com"


def test_stats_recent_links_returns_at_most_ten_newest_first(client, db_session):
    for i in range(12):
        _add(db_session, f"code{i:02d}", risk_score=1, days_ago=12 - i)

    res = client.get("/api/stats")
    recent = res.json()["recent_links"]

    assert len(recent) == 10
    # newest (smallest days_ago == largest i) should be first
    assert recent[0]["code"] == "code11"


def test_stats_scan_volume_only_counts_last_seven_days(client, db_session):
    _add(db_session, "old", risk_score=1, days_ago=10)   # outside window
    _add(db_session, "recent", risk_score=1, days_ago=2)  # inside window

    res = client.get("/api/stats")
    volume = res.json()["scan_volume_over_time"]

    assert len(volume) == 7
    total_in_window = sum(day["count"] for day in volume)
    assert total_in_window == 1  # only "recent" should be counted