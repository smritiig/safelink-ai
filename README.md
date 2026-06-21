# SafeLink AI

A threat-aware URL shortening platform. Every link is scanned by an LLM and cross-checked against VirusTotal before it's allowed to redirect — combining AI-based reasoning with known-threat intelligence to catch both novel phishing patterns and confirmed malicious domains.

Built with FastAPI, PostgreSQL, Redis, AWS Bedrock (Claude Haiku 4.5), and a React analytics dashboard.

## Why this exists

Most URL shorteners trust the link at creation time and never look at it again. SafeLink AI treats the moment of shortening as a security checkpoint: the destination is analyzed before a short code is ever handed out, and the result of that analysis governs what happens on every future visit.

## How it works

A request to shorten a URL returns immediately with a `pending` status — the actual analysis runs as a background task so the user isn't stuck waiting on two external API calls. The frontend polls a status endpoint until the scan resolves.

1. **Bedrock** (Claude Haiku 4.5) reasons about the URL in natural language — misspelled brand names, suspicious keywords, unusual TLDs, IP-based domains — and returns a 1–10 risk score with an explanation.
2. **VirusTotal** is queried in parallel for known-malicious verdicts, contributing a 0–5 penalty on top of the Bedrock score.
3. The combined score (capped at 10) determines what happens next:
   - **0–6** → link redirects normally, cached in Redis for fast repeat access
   - **7–8** → link routes to a warning page showing the destination and the reasoning, with an explicit confirmation step before proceeding
   - **9–10** → link is blocked outright; the redirect endpoint returns `403` and never serves the destination

If Bedrock or VirusTotal is unavailable, the system degrades to a local heuristic scorer (keyword and TLD pattern matching) rather than failing the request outright.

## Architecture

The diagram above shows the full request lifecycle. A few decisions worth calling out:

- **Async by design, not by accident.** The original implementation blocked the HTTP request on both API calls — every shorten request took 1–3 seconds. Moving analysis to a `BackgroundTask` cut perceived latency to near-zero, at the cost of a more complex state machine (`pending` → `completed`/`blocked`) and losing the ability to reject a URL before it's ever persisted.
- **Redis caches the destination, not the verdict.** Once a link is scored safe, its destination is cached for an hour to avoid repeat database hits. This is a deliberate tradeoff: a link's risk score isn't re-evaluated on every cached hit, only its expiry is.
- **Two frontends, one API.** A static HTML/CSS/JS landing page (served directly by FastAPI) handles shortening and warnings; a separate React dashboard handles analytics and visualization. Both talk to the same REST API independently.

## Tech stack

| Layer | Technology |
|---|---|
| Backend | FastAPI, Python 3.11 |
| Database | PostgreSQL (SQLAlchemy ORM) |
| Cache | Redis |
| AI reasoning | AWS Bedrock — Claude Haiku 4.5 |
| Threat intel | VirusTotal API v3 |
| Frontend | Vanilla JS landing page + React analytics dashboard (Recharts) |
| Rate limiting | slowapi |
| Containerization | Docker, Docker Compose |
| Testing | pytest, FastAPI TestClient, 60 tests |

## Running locally

```bash
git clone https://github.com/smritiig/safelink-ai.git
cd safelink-ai
cp .env.example .env   # add your AWS and VirusTotal credentials
docker compose up --build
```

The API runs at `localhost:8000`, with the landing page at `localhost:8000/web/`. The React dashboard is a separate app:

```bash
cd dashboard
npm install
npm start
```

Without AWS/VirusTotal credentials configured, the app still runs — it falls back to the local heuristic scorer automatically.

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest
```

60 tests covering the heuristic fallback scorer, the score-combination logic, the full async shorten → scan → status lifecycle, redirect branching (safe / warning / blocked / expired / one-time), and the stats aggregation endpoint. Tests run against an isolated SQLite database and mock both external APIs — no network calls, no API costs, sub-2-second runtime.

Two bugs were found and fixed via this test suite during development:
- A cache/expiry race where a link's destination could keep serving from Redis after its database row had expired, until the cache's independent TTL ran out.
- An inconsistent empty-state response shape in the stats endpoint that would have broken a dashboard chart expecting a stable 7-day array.

## API overview

| Endpoint | Description |
|---|---|
| `POST /api/shorten` | Creates a link in `pending` status, queues background analysis, returns immediately |
| `GET /api/status/{code}` | Poll target — returns current status and risk info once available |
| `GET /{code}` | Redirects, shows the warning page, or returns 403, depending on status |
| `GET /api/link/{code}` | Full metadata for a given link |
| `GET /api/stats` | Aggregate dashboard data — risk distribution, top risky domains, 7-day scan volume |

## What's not here yet

This is an active portfolio project, not a finished product. Known gaps:

- No authentication — all links and scans are anonymous and global
- No structured logging or metrics endpoint
- Not yet deployed to a public URL
