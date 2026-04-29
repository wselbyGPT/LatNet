from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass


@dataclass
class FixedWindowRateLimiter:
    max_requests: int
    window_seconds: float

    def __post_init__(self) -> None:
        self.max_requests = max(int(self.max_requests), 1)
        self.window_seconds = max(float(self.window_seconds), 0.01)
        self._events: dict[str, deque[float]] = {}

    def allow(self, key: str, *, now: float | None = None) -> tuple[bool, int]:
        ts = time.time() if now is None else float(now)
        window_start = ts - self.window_seconds
        bucket = self._events.setdefault(str(key), deque())
        while bucket and bucket[0] <= window_start:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            retry_after = max(1, int(bucket[0] + self.window_seconds - ts))
            return False, retry_after
        bucket.append(ts)
        return True, 0
