import json
import urllib.request
import urllib.parse
import base64
import boto3
from .config import settings


# ── VirusTotal ────────────────────────────────────────────────────────────────

def check_virustotal(url: str) -> tuple[int, str]:
    """
    Query VirusTotal for known malicious verdicts on a URL.
    Returns (penalty_score 0-5, reason_string).
    penalty_score is added on top of the Bedrock score.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return 0, ""

    try:
        # VirusTotal v3 — encode URL to base64 (no padding) for the ID
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        req = urllib.request.Request(
            api_url,
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())

        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 3:
            return 5, f"VirusTotal: {malicious} engines flagged this URL as malicious"
        if malicious >= 1 or suspicious >= 2:
            return 3, f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections"

        return 0, ""

    except Exception:
        # Never let VT failure break the main flow
        return 0, ""


# ── AWS Bedrock ───────────────────────────────────────────────────────────────

def analyze_with_bedrock(url: str) -> tuple[int, str]:
    """
    Call AWS Bedrock (Claude Haiku) to reason about URL safety.
    Returns (risk_score 1-10, reason).
    Falls back to heuristic if Bedrock is unavailable.
    """
    if not settings.AWS_ACCESS_KEY_ID:
        return _heuristic_fallback(url)

    prompt = f"""You are a cybersecurity expert analyzing URLs for phishing and malware.

Analyze this URL: {url}

Look for these red flags:
- Suspicious keywords (login, verify, bank, crypto, password, free, update, secure, account)
- Misspelled brand names (paypa1, g00gle, arnazon)
- Excessive subdomains or random-looking strings
- Non-standard TLDs (.xyz, .tk, .ml, .ga) combined with financial/brand keywords
- IP addresses used as domain names
- Very long URLs with lots of parameters

Respond with ONLY valid JSON in this exact format (no extra text):
{{
  "risk_score": <integer 1-10>,
  "reason": "<one concise sentence explaining the main risk>"
}}

Where risk_score means:
1-3 = Safe
4-6 = Suspicious  
7-10 = High risk / likely malicious"""

    try:
        client = boto3.client(
            "bedrock-runtime",
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        )

        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 150,
            "messages": [{"role": "user", "content": prompt}],
        })

        response = client.invoke_model(
            modelId=settings.BEDROCK_MODEL_ID,
            body=body,
        )

        raw = json.loads(response["body"].read())
        text = raw["content"][0]["text"].strip()

        # Strip any accidental markdown fences
        text = text.replace("```json", "").replace("```", "").strip()
        result = json.loads(text)

        score = max(1, min(10, int(result["risk_score"])))
        reason = str(result["reason"])
        return score, reason

    except Exception as e:
        print(f"[Bedrock ERROR] {type(e).__name__}: {e}", flush=True)
        return _heuristic_fallback(url)


# ── Heuristic fallback (used when Bedrock creds are missing / error) ──────────

def _heuristic_fallback(url: str) -> tuple[int, str]:
    suspicious_keywords = [
        "free", "login", "verify", "bank", "crypto",
        "password", "update", "secure", "account", "winner",
    ]
    url_lower = url.lower()

    for keyword in suspicious_keywords:
        if keyword in url_lower:
            return 7, f"Contains suspicious keyword: '{keyword}'"

    # Flag IP-based URLs
    import re
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        return 8, "URL uses a raw IP address instead of a domain name"

    # Flag suspicious TLDs
    for tld in [".xyz", ".tk", ".ml", ".ga", ".cf"]:
        if url_lower.split("?")[0].endswith(tld):
            return 6, f"Uncommon TLD '{tld}' associated with free/abused domains"

    return 2, "No obvious suspicious patterns detected"


# ── Public API (called by main.py) ────────────────────────────────────────────

def analyze_url(url: str) -> tuple[int, str]:
    """
    Full analysis pipeline:
    1. AWS Bedrock AI scoring
    2. VirusTotal cross-check
    3. Combine into final score + reason
    """
    ai_score, ai_reason = analyze_with_bedrock(url)
    vt_penalty, vt_reason = check_virustotal(url)

    final_score = min(10, ai_score + vt_penalty)

    if vt_reason:
        final_reason = f"{ai_reason} | {vt_reason}"
    else:
        final_reason = ai_reason

    return final_score, final_reason

