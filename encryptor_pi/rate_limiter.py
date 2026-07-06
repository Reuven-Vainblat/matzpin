"""Small in-memory rate limiter for Pi-side connection attempts."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
import time


class FixedWindowRateLimiter:
    """Track recent events per key and reject keys over a fixed window limit."""

    def __init__(
        self,
        window_seconds: float,
        max_events: int,
        now: Callable[[], float] | None = None,
    ) -> None:
        self.window_seconds = window_seconds
        self.max_events = max_events
        self._now = now or time.monotonic
        self._events: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        """Return true when the key is still within its configured limit."""

        now = self._now()
        cutoff = now - self.window_seconds
        events = self._events.setdefault(key, deque())
        while events and events[0] <= cutoff:
            events.popleft()

        if len(events) >= self.max_events:
            return False

        events.append(now)
        return True
