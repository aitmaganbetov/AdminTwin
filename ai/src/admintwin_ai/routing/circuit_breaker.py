"""Circuit breaker с экспоненциальным backoff (§6.4 п.4, §6.7)."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum


class BreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """Открывается после ``failure_threshold`` подряд ошибок; после backoff —
    half-open (одна пробная попытка). Rate-limit с ``retry_after`` открывает
    цепь на указанное время немедленно."""

    failure_threshold: int = 3
    base_backoff_s: float = 1.0
    max_backoff_s: float = 60.0
    clock: Callable[[], float] = time.monotonic
    _failures: int = field(default=0, init=False)
    _open_count: int = field(default=0, init=False)
    _opened_until: float = field(default=0.0, init=False)
    _state: BreakerState = field(default=BreakerState.CLOSED, init=False)
    last_error: str = field(default="", init=False)

    @property
    def state(self) -> BreakerState:
        if self._state is BreakerState.OPEN and self.clock() >= self._opened_until:
            return BreakerState.HALF_OPEN
        return self._state

    def allow(self) -> bool:
        return self.state is not BreakerState.OPEN

    def record_success(self) -> None:
        self._failures = 0
        self._open_count = 0
        self._state = BreakerState.CLOSED
        self.last_error = ""

    def record_failure(self, error: str = "", retry_after_s: float | None = None) -> None:
        self.last_error = error
        self._failures += 1
        if retry_after_s is not None:
            self._open(retry_after_s)
            return
        if self.state is BreakerState.HALF_OPEN or self._failures >= self.failure_threshold:
            backoff = min(self.max_backoff_s, self.base_backoff_s * (2 ** self._open_count))
            self._open(backoff)

    def _open(self, duration_s: float) -> None:
        self._state = BreakerState.OPEN
        self._opened_until = self.clock() + max(0.0, duration_s)
        self._open_count += 1
        self._failures = 0

    @property
    def retry_at(self) -> float | None:
        return self._opened_until if self._state is BreakerState.OPEN else None


class BreakerBoard:
    """Набор breaker-ов по id профиля; состояние видно в ChatOps (§6.7)."""

    def __init__(self, factory: Callable[[], CircuitBreaker] | None = None) -> None:
        self._factory = factory or CircuitBreaker
        self._breakers: dict[str, CircuitBreaker] = {}

    def get(self, key: str) -> CircuitBreaker:
        if key not in self._breakers:
            self._breakers[key] = self._factory()
        return self._breakers[key]

    def snapshot(self) -> dict[str, str]:
        return {k: b.state.value for k, b in self._breakers.items()}
