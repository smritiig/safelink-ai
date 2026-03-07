import redis
from .config import settings

r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

def cache_get_url(code: str) -> str | None:
    return r.get(f"url:{code}")

def cache_set_url(code: str, url: str, ttl_seconds: int = 3600) -> None:
    r.setex(f"url:{code}", ttl_seconds, url)

def cache_delete(code: str) -> None:
    r.delete(f"url:{code}")