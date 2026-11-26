"""A small in-memory cache with expiry, and a rate limiter.

Outside services are slow, sometimes rate-limited, and their answers don't
change minute to minute, so each client keeps recent answers. Both use an
injected clock, so tests can move time forward instead of sleeping.
"""

import asyncio
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import timedelta

from phishlens.services import Clock


@dataclass
class TtlCache[K, V]:
    clock: Clock
    ttl: timedelta
    max_items: int = 1000
    _items: OrderedDict[K, tuple[float, V]] = field(default_factory=OrderedDict)

    def get(self, key: K) -> V | None:
        entry = self._items.get(key)
        if entry is None:
            return None
        expires, value = entry
        if self.clock.now().timestamp() >= expires:
            del self._items[key]
            return None
        self._items.move_to_end(key)
        return value

    def put(self, key: K, value: V) -> None:
        self._items[key] = (self.clock.now().timestamp() + self.ttl.total_seconds(), value)
        self._items.move_to_end(key)
        while len(self._items) > self.max_items:
            self._items.popitem(last=False)


@dataclass
class RateLimiter:
    """At most one call per interval. Callers wait their turn, up to max_wait;
    beyond that they get False and should report "unknown" instead."""

    interval: float
    max_wait: float
    now: Callable[[], float]
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    _next: float = 0.0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def acquire(self) -> bool:
        async with self._lock:
            wait = self._next - self.now()
            if wait > self.max_wait:
                return False
            if wait > 0:
                await self.sleep(wait)
            self._next = max(self.now(), self._next) + self.interval
            return True
