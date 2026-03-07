from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import settings
import time

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def wait_for_db(max_seconds: int = 30):
    """Wait until Postgres is accepting connections."""
    deadline = time.time() + max_seconds
    last_err = None

    while time.time() < deadline:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return  # success
        except Exception as e:
            last_err = e
            time.sleep(1)

    raise RuntimeError(f"Database not ready after {max_seconds}s. Last error: {last_err}")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()