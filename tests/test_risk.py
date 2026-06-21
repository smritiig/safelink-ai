"""
Unit tests for app.risk._heuristic_fallback and app.risk.analyze_url orchestration.

These are pure-logic tests with no network calls — they're what actually run
when AWS credentials are absent, so they double as documentation of the
degraded-mode behavior.
"""
import pytest
from app.risk import _heuristic_fallback, analyze_url


class TestHeuristicFallback:
    @pytest.mark.parametrize("keyword", [
        "free", "login", "verify", "bank", "crypto",
        "password", "update", "secure", "account", "winner",
    ])
    def test_flags_each_suspicious_keyword(self, keyword):
        score, reason = _heuristic_fallback(f"http://example.com/{keyword}-now")
        assert score == 7
        assert keyword in reason

    def test_keyword_match_is_case_insensitive(self):
        score, reason = _heuristic_fallback("http://example.com/LOGIN")
        assert score == 7
        assert "login" in reason

    def test_first_matching_keyword_wins(self):
        # "free" appears before "login" in the keyword list, and the function
        # returns on first match — pin down that ordering behavior explicitly,
        # since it's the kind of implicit contract that silently breaks on refactor.
        score, reason = _heuristic_fallback("http://example.com/free-login-verify")
        assert "free" in reason

    def test_flags_raw_ip_address_url(self):
        score, reason = _heuristic_fallback("http://192.168.1.1/admin")
        assert score == 8
        assert "IP address" in reason

    def test_ip_pattern_does_not_false_positive_on_normal_domain(self):
        score, reason = _heuristic_fallback("http://example.com/page")
        assert score != 8

    @pytest.mark.parametrize("tld", [".xyz", ".tk", ".ml", ".ga", ".cf"])
    def test_flags_suspicious_tld(self, tld):
        score, reason = _heuristic_fallback(f"http://totally-fine-site{tld}")
        assert score == 6
        assert tld in reason

    def test_tld_check_respects_query_string(self):
        # endswith check splits on "?" first — a URL with a suspicious TLD
        # disguised earlier in the query string shouldn't false-positive,
        # and a real .tk domain *with* a query string should still be caught.
        score, reason = _heuristic_fallback("http://safe-site.com?ref=xyz")
        assert score != 6

        score, reason = _heuristic_fallback("http://shady-site.tk?ref=abc")
        assert score == 6

    def test_clean_url_scores_low(self):
        score, reason = _heuristic_fallback("https://docs.python.org/3/library/json.html")
        assert score == 2
        assert "No obvious suspicious patterns" in reason

    def test_keyword_check_takes_priority_over_tld_check(self):
        # A URL that matches both a keyword AND a suspicious TLD should hit
        # the keyword branch first (score 7), not the TLD branch (score 6) —
        # this pins the actual precedence in the code, not assumed precedence.
        score, reason = _heuristic_fallback("http://verify-account.tk")
        assert score == 7


class TestAnalyzeUrlOrchestration:
    """
    analyze_url() combines Bedrock's score with VirusTotal's penalty.
    These tests mock both boundaries to verify the combination logic itself —
    capping at 10, and reason-string concatenation — independent of whether
    the real APIs are reachable.
    """

    def test_combines_ai_score_and_vt_penalty(self, monkeypatch):
        monkeypatch.setattr("app.risk.analyze_with_bedrock", lambda url: (5, "AI: looks shady"))
        monkeypatch.setattr("app.risk.check_virustotal", lambda url: (3, "VT: 2 flags"))

        score, reason = analyze_url("http://example.com")

        assert score == 8  # 5 + 3
        assert reason == "AI: looks shady | VT: 2 flags"

    def test_score_is_capped_at_10(self, monkeypatch):
        monkeypatch.setattr("app.risk.analyze_with_bedrock", lambda url: (9, "AI: very shady"))
        monkeypatch.setattr("app.risk.check_virustotal", lambda url: (5, "VT: flagged"))

        score, reason = analyze_url("http://example.com")

        assert score == 10  # 9 + 5 = 14, capped to 10

    def test_no_vt_reason_omits_separator(self, monkeypatch):
        # When VT has nothing to report, the final reason should be just the
        # AI reason — no dangling " | " left over from string concatenation.
        monkeypatch.setattr("app.risk.analyze_with_bedrock", lambda url: (2, "AI: looks fine"))
        monkeypatch.setattr("app.risk.check_virustotal", lambda url: (0, ""))

        score, reason = analyze_url("http://example.com")

        assert score == 2
        assert reason == "AI: looks fine"
        assert "|" not in reason
