import math
import os
import threading
import time
from typing import Dict, Optional, Tuple

from fastapi import HTTPException, status

DEFAULT_INGEST_RATE_PER_SEC: float = 1000.0
DEFAULT_INGEST_BURST_CAPACITY: float = 2000.0


class ClientBucket:
    __slots__ = ("tokens", "last_refill")

    def __init__(self, initial_tokens: float, now: float) -> None:
        self.tokens = initial_tokens
        self.last_refill = now


class PerClientRateLimiter:
    """
    In-memory, thread-safe token bucket rate limiter keyed by API key identity.
    Enforces per-client throughput limits without IP-based cardinality explosion.
    """

    def __init__(
        self,
        rate_per_sec: Optional[float] = None,
        capacity: Optional[float] = None,
        cleanup_interval_seconds: float = 600.0,
        max_idle_seconds: float = 3600.0,
    ) -> None:
        raw_rate = os.environ.get("INGEST_RATE_LIMIT_RPS")
        self.rate_per_sec = (
            float(rate_per_sec)
            if rate_per_sec is not None
            else (float(raw_rate) if raw_rate else DEFAULT_INGEST_RATE_PER_SEC)
        )
        raw_cap = os.environ.get("INGEST_RATE_LIMIT_BURST")
        self.capacity = (
            float(capacity)
            if capacity is not None
            else (float(raw_cap) if raw_cap else max(self.rate_per_sec, DEFAULT_INGEST_BURST_CAPACITY))
        )
        self.cleanup_interval_seconds = cleanup_interval_seconds
        self.max_idle_seconds = max_idle_seconds

        self._buckets: Dict[str, ClientBucket] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

    def check_and_consume(
        self,
        identity: str,
        tokens: float = 1.0,
        now: Optional[float] = None,
        tokens_requested: Optional[float] = None,
    ) -> Tuple[bool, float]:
        """
        Attempts to consume `tokens` tokens for `identity`.
        Returns:
            (True, 0.0) if allowed.
            (False, retry_after_seconds) if rate limit exceeded.
        """
        requested = tokens if tokens_requested is None else tokens_requested
        if self.rate_per_sec <= 0:
            return True, 0.0

        current_time = now if now is not None else time.monotonic()

        with self._lock:
            # Periodic cleanup of idle identities
            if current_time - self._last_cleanup > self.cleanup_interval_seconds:
                self._prune_idle_clients(current_time)

            bucket = self._buckets.get(identity)
            if bucket is None:
                bucket = ClientBucket(self.capacity, current_time)
                self._buckets[identity] = bucket
            else:
                elapsed = max(0.0, current_time - bucket.last_refill)
                bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.rate_per_sec)
                bucket.last_refill = current_time

            if bucket.tokens >= requested:
                bucket.tokens -= requested
                return True, 0.0

            deficit = requested - bucket.tokens
            retry_after = deficit / self.rate_per_sec
            return False, retry_after

    def _prune_idle_clients(self, now: float) -> None:
        idle_cutoff = now - self.max_idle_seconds
        to_delete = [
            k for k, b in self._buckets.items() if b.last_refill < idle_cutoff
        ]
        for k in to_delete:
            del self._buckets[k]
        self._last_cleanup = now

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
            self._last_cleanup = time.monotonic()


ingest_rate_limiter = PerClientRateLimiter()


def check_client_rate_limit(identity: str, tokens: float = 1.0) -> None:
    """
    Checks per-client rate limit for `identity`.
    Raises HTTP 429 with 'Retry-After' header if exhausted.
    """
    allowed, retry_after = ingest_rate_limiter.check_and_consume(identity, tokens)
    if not allowed:
        retry_seconds = max(1, int(math.ceil(retry_after)))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for client identity. Retry after {retry_seconds}s.",
            headers={"Retry-After": str(retry_seconds)},
        )
