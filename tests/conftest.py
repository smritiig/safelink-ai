"""
Shared pytest fixtures.

Design choices (worth defending in an interview):
- Uses an in-memory SQLite DB instead of spinning up Postgres in CI — keeps tests
  fast (<1s) and dependency-free. Schema is simple enough that SQLite/Postgres
  divergence isn't a real risk here.
- Redis is faked with a tiny in-process dict instead of fakeredis/real Redis, so
  tests don't need a running container and stay hermetic.
- Bedrock + VirusTotal are mocked at the boundary (risk.analyze_with_bedrock /
  risk.check_virustotal) rather than mocking boto3/urllib internals — this keeps
  tests resilient to refactors of *how* those calls are made, while still
  proving the orchestration logic in analyze_url() and the FastAPI routes.
"""
import sys
import os
import tempfile

# Must be set before app.config / app.db are imported anywhere, since
# Settings() and create_engine() both run eagerly at import time and would
# otherwise try to connect to the real Postgres container ("db" hostname,
# only resolvable inside Docker).
os.environ.setdefault("DATABASE_URL", "sqlite:///test.db")  # overwritten below anyway
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")  # unused, app.cache.r is monkeypatched

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import db as db_module
from app.db import Base, get_db
from app.models import Link  # noqa: F401  (ensures model is registered on Base)

# Rebuild app.db.engine to point at a real SQLite file in a temp directory,
# rather than ":memory:". A bare ":memory:" database (even with StaticPool
# and a shared-cache URI) is unreliable across platforms once Starlette's
# TestClient gets involved: TestClient dispatches requests through an AnyIO
# portal thread, and BackgroundTasks (run_analysis's SessionLocal()) open
# their own connection — on Windows in particular this reliably produced
# "unable to open database file" / "no such table" errors, because the
# in-memory DB's lifetime and visibility across that thread boundary isn't
# guaranteed the same way on every platform's SQLite build.
#
# A real on-disk file in the OS temp directory sidesteps all of that: every
# connection, on any thread, opens the same physical file. It's still fast
# (local temp disk, dropped each test) and fully isolated per test run.
_tmp_dir = tempfile.mkdtemp(prefix="safelink_test_")
_tmp_db_path = os.path.join(_tmp_dir, "test.db")

# CRITICAL ORDERING: this reassignment must happen BEFORE `app.main` is
# imported. main.py does `from .db import ... SessionLocal` — a value import
# that binds main.SessionLocal to whatever object exists in db.py at import
# time. Importing main first, then reassigning db_module.SessionLocal here,
# would leave main.py (and therefore run_analysis's background-task DB
# session) silently pointing at the original, real-Postgres-configured
# engine instead of this test engine.
db_module.engine = db_module.create_engine(
    f"sqlite:///{_tmp_db_path}",
    connect_args={"check_same_thread": False},
)
db_module.SessionLocal = db_module.sessionmaker(
    autocommit=False, autoflush=False, bind=db_module.engine
)

from app import main as main_module


# ── Shared in-memory SQLite, fresh tables per test ─────────────────────────

@pytest.fixture()
def db_session():
    Base.metadata.create_all(bind=db_module.engine)
    session = db_module.SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=db_module.engine)


# ── Fake Redis: just enough surface area to satisfy cache.py's usage ──────

class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def setex(self, key, ttl, value):
        self.store[key] = value

    def delete(self, key):
        self.store.pop(key, None)


@pytest.fixture()
def fake_redis(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr("app.cache.r", fake)
    return fake


# ── TestClient wired to the in-memory DB + fake Redis ──────────────────────

@pytest.fixture()
def client(db_session, fake_redis, monkeypatch):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    main_module.app.dependency_overrides[get_db] = override_get_db

    # Skip the real DB-readiness probe and table creation on startup;
    # the in-memory schema is already created by the db_session fixture.
    monkeypatch.setattr(main_module, "wait_for_db", lambda max_seconds=60: None)

    with TestClient(main_module.app) as c:
        yield c

    main_module.app.dependency_overrides.clear()