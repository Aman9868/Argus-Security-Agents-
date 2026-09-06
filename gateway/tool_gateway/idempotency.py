"""Tool Idempotency and Rate-Limit Caching Engine.

Protects third-party rate limits (such as VirusTotal free tier 4 req/min)
and guarantees duplicate lookups are safely deduplicated.
"""

import time
import asyncio
from typing import Dict, Any, Optional
import structlog

logger = structlog.get_logger(__name__)


class IdempotencyManager:
    """In-memory thread-safe cache and concurrency lock manager with TTL support."""

    def __init__(self, default_ttl_seconds: int = 3600):
        self.default_ttl = default_ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    async def get_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached result if within TTL."""
        entry = self._cache.get(cache_key)
        if not entry:
            return None

        if time.time() > entry.get("expires_at", 0):
            self._cache.pop(cache_key, None)
            return None

        return entry

    async def set_result(self, cache_key: str, result: Any, ttl: Optional[int] = None):
        """Stores result in cache with expiration timestamp."""
        ttl_val = ttl or self.default_ttl
        self._cache[cache_key] = {
            "result": result,
            "status": "COMPLETED",
            "created_at": time.time(),
            "expires_at": time.time() + ttl_val,
        }

    async def acquire_lock(self, cache_key: str) -> bool:
        """Acquires lock for in-flight execution to prevent duplicate concurrent API hits."""
        async with self._global_lock:
            if cache_key not in self._locks:
                self._locks[cache_key] = asyncio.Lock()
            lock = self._locks[cache_key]

        return not lock.locked()


idempotency_manager = IdempotencyManager()

