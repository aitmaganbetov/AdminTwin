"""Token-bucket rate limit для Tool Layer (per tenant × agent × tool)."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._buckets: dict[tuple[str, ...], _Bucket] = {}
        self._lock = threading.Lock()  # вызовы инструментов идут из рабочих потоков

    def allow(self, key: tuple[str, ...], per_minute: int) -> bool:
        with self._lock:
            return self._allow(key, per_minute)

    def _allow(self, key: tuple[str, ...], per_minute: int) -> bool:
        now = self._clock()
        capacity = float(per_minute)
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=capacity, updated=now)
            self._buckets[key] = bucket
        bucket.tokens = min(capacity, bucket.tokens + (now - bucket.updated) * capacity / 60.0)
        bucket.updated = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True
        return False
