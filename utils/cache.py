# utils/cache.py
import json
import os
import time
from typing import Any, Optional

CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "cache.json")
DEFAULT_TTL = 24 * 3600  # 1 day

def _load_cache() -> dict:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_cache(cache: dict) -> None:
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass

def get_from_cache(key: str, ttl: int = DEFAULT_TTL) -> Optional[Any]:
    cache = _load_cache()
    if key in cache:
        entry = cache[key]
        ts = entry.get("timestamp", 0)
        if time.time() - ts < ttl:
            return entry.get("value")
    return None

def save_to_cache(key: str, value: Any) -> None:
    cache = _load_cache()
    cache[key] = {"timestamp": time.time(), "value": value}
    _save_cache(cache)
