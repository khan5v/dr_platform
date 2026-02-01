"""Sliding window for per-key event accumulation.

Used by the detection engine to track events per (rule, group_key) pair.
Deque-based: O(1) append, amortized O(1) eviction.  In production this
would be backed by Redis sorted sets for horizontal scaling; in-memory
is fine for a single-process detector.
"""

import time
from collections import deque

# Events with timestamps more than this many seconds in the future are
# dropped — protects against bogus timestamps poisoning the window.
_MAX_DRIFT_SECONDS = 5


class SlidingWindow:
    __slots__ = ("max_age", "_buf")

    def __init__(self, max_age_seconds: int):
        self.max_age = max_age_seconds
        self._buf: deque[tuple[float, dict]] = deque()

    def add(self, timestamp: float, event: dict) -> bool:
        """Append event. Returns False (and drops) if timestamp is bogus or already expired."""
        now = time.time()
        if timestamp > now + _MAX_DRIFT_SECONDS:
            return False  # too far in the future
        if timestamp < now - self.max_age:
            return False  # already outside the window
        self._evict(now)
        self._buf.append((timestamp, event))
        return True

    def events(self, now: float) -> list[dict]:
        """Return all events currently inside the window."""
        self._evict(now)
        return [e for _, e in self._buf]

    def clear(self) -> None:
        """Reset after an alert fires (simple dedup)."""
        self._buf.clear()

    def _evict(self, now: float) -> None:
        cutoff = now - self.max_age
        while self._buf and self._buf[0][0] < cutoff:
            self._buf.popleft()

    def __len__(self) -> int:
        return len(self._buf)
