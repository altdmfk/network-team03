import time
from typing import Callable, Optional

from config import BATCH_SIZE, MAX_LOGS_PER_SEC


class TokenBucketRateLimiter:
    """
    Controls downstream shipping rate to Graylog in exact log units.
    With rate_per_sec = MAX_LOGS_PER_SEC (e.g., 500.0 logs/sec) and BATCH_SIZE = 100,
    acquiring `len(batch)` tokens enforces a strict ceiling of 500 logs/sec (5 full
    batches/sec = 1.0s) while proportionally pacing partial micro-batches (e.g., 25
    logs = 0.05s). Also maintains backward compatibility when initialized with custom
    `rate_per_sec` and `capacity=1.0` in unit tests.
    """

    def __init__(
        self,
        rate_per_sec: float = MAX_LOGS_PER_SEC,
        capacity: Optional[float] = None,
        initial_tokens: Optional[float] = None,
        clock_fn: Optional[Callable[[], float]] = None,
        sleep_fn: Optional[Callable[[float], None]] = None,
    ) -> None:
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be > 0")
        self.rate_per_sec = float(rate_per_sec)
        self._clock_fn: Callable[[], float] = clock_fn or (lambda: time.monotonic())
        self._sleep_fn: Callable[[float], None] = sleep_fn or (lambda s: time.sleep(s))

        if capacity is None:
            self.capacity = max(
                float(BATCH_SIZE),
                min(self.rate_per_sec, float(BATCH_SIZE * 2)),
            )
        else:
            self.capacity = max(1.0, float(capacity))

        if initial_tokens is not None:
            self.tokens = max(0.0, min(self.capacity, float(initial_tokens)))
        elif capacity is not None:
            self.tokens = self.capacity
        else:
            self.tokens = min(self.capacity, float(BATCH_SIZE))

        self.last_refill = self._clock_fn()

    def acquire(self, requested_tokens: float = 1.0) -> float:
        """
        Blocks until `requested_tokens` (e.g. `len(batch)` logs) are available in the bucket.
        Returns the duration slept in seconds.
        """
        if requested_tokens <= 0:
            return 0.0

        now = self._clock_fn()
        elapsed = max(0.0, now - self.last_refill)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)
        self.last_refill = now

        if self.tokens >= requested_tokens:
            self.tokens -= requested_tokens
            return 0.0

        deficit = requested_tokens - self.tokens
        sleep_seconds = deficit / self.rate_per_sec
        self._sleep_fn(sleep_seconds)

        self.last_refill = self._clock_fn()
        self.tokens = 0.0
        return sleep_seconds
