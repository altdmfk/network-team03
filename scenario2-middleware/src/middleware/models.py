from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class DeliveryOutcome(Enum):
    """
    Explicit outcome of a Graylog batch delivery attempt:
    - DELIVERED: Graylog accepted the batch (HTTP 2xx) -> commit offset & increment forwarded.
    - DEAD_LETTERED: Retries exhausted and batch persisted to Dead Letter File -> commit offset & increment dropped.
    - ABORTED: Worker shutdown interrupted delivery -> do NOT commit offset so batch replays on restart.
    """

    DELIVERED = "DELIVERED"
    DEAD_LETTERED = "DEAD_LETTERED"
    ABORTED = "ABORTED"


@dataclass(frozen=True)
class RetryPolicy:
    """Configuration for exponential backoff with jitter on downstream HTTP failures."""

    max_retries: int = 8  # 0 = infinite retry until shutdown (requires pause-based backoff)
    base_backoff_seconds: float = 1.0
    max_backoff_seconds: float = 30.0
    max_exponent: int = 6
    jitter_min: float = 0.05
    jitter_max: float = 0.45
    sleep_step_seconds: float = 0.25

    def compute_backoff(self, attempt: int, jitter_value: Optional[float] = None) -> float:
        """Calculates backoff seconds for 1-based attempt number."""
        exponent = min(max(0, attempt - 1), self.max_exponent)
        exp_backoff = min(
            self.max_backoff_seconds,
            self.base_backoff_seconds * (2**exponent),
        )
        jitter = self.jitter_min if jitter_value is None else jitter_value
        return round(exp_backoff + jitter, 2)


@dataclass
class InFlightBatchState:
    """Tracks in-flight micro-batch metadata and confirmation status across rebalances."""

    batch_id: str
    partition_offset_ranges: Dict[int, Tuple[int, int]] = field(default_factory=dict)
    offsets: List[Any] = field(default_factory=list)
    confirmed: bool = False


@dataclass(frozen=True)
class BatchResult:
    """Explicit result metadata for a processed micro-batch."""

    batch_id: str
    outcome: DeliveryOutcome
    message_count: int
    attempts: int = 1
    honeytoken_count: int = 0
    partition_offset_ranges: Dict[int, Tuple[int, int]] = field(default_factory=dict)
    error_reason: Optional[str] = None


@dataclass(frozen=True)
class PartitionLagInfo:
    """Per-partition watermark and consumer committed offset telemetry."""

    partition: int
    low_watermark: int
    high_watermark: int
    committed_offset: int
    lag: int

    def to_dict(self) -> Dict[str, int]:
        return {
            "partition": int(self.partition),
            "low_watermark": int(self.low_watermark),
            "high_watermark": int(self.high_watermark),
            "committed_offset": int(self.committed_offset),
            "lag": int(self.lag),
        }


@dataclass(frozen=True)
class BrokerLagSnapshot:
    """Aggregated broker and consumer group lag telemetry."""

    broker_total_messages: int
    consumer_committed_total: int
    broker_queue_lag: int
    in_flight_producer_queue: int
    partitions: List[PartitionLagInfo] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "broker_total_messages": int(self.broker_total_messages),
            "consumer_committed_total": int(self.consumer_committed_total),
            "broker_queue_lag": int(self.broker_queue_lag),
            "in_flight_producer_queue": int(self.in_flight_producer_queue),
            "partitions": [p.to_dict() for p in self.partitions],
        }
