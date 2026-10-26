from collections import deque
import logging
import time
from typing import Any, Callable, Deque, List, Optional, Tuple

from middleware.lightweight_broker import (
    BrokerError,
    LightweightConsumer as Consumer,
    LightweightMessage as Message,
)

from config import (
    BROKER_PRIORITY_TOPIC,
    BROKER_TOPIC,
    STANDARD_RESERVED_SHARE,
)

logger = logging.getLogger("soar.batch_poller")


class BrokerBatchPoller:
    """
    Micro-batch accumulation poller for broker Consumer supporting dual priority/standard lanes.

    Ordering Trade-Off:
    --------------------
    When high-priority security events (e.g., HONEYTOKEN_ACCESS, severity <= 2) are routed to
    `security-logs.priority` while bulk scan logs remain in `security-logs`, events from the same
    attacker IP address are partitioned across two independent broker topics.

    Per-topic FIFO ordering is strictly preserved because messages within each topic are keyed by
    `client_ip` to land on the same partition and are consumed in sequential offset order.
    However, cross-lane ordering between topics is 'best effort': high-priority events are
    accelerated and delivered ahead of bulk background scan logs so critical deception alerts
    never stall behind a bulk backlog.

    Weighted Draining:
    -------------------
    Priority traffic is drained first, but a configurable reserved share of the batch / token
    bucket (e.g. 30% via `standard_reserved_share`) is guaranteed for standard traffic whenever
    standard messages are present, preventing starvation under continuous high-priority traffic.
    """

    def __init__(
        self,
        batch_size: int = 100,
        batch_linger_ms: int = 100,
        poll_timeout: float = 0.1,
        priority_topic: str = BROKER_PRIORITY_TOPIC,
        standard_topic: str = BROKER_TOPIC,
        standard_reserved_share: float = STANDARD_RESERVED_SHARE,
        clock_fn: Optional[Callable[[], float]] = None,
        linger_ms: Optional[int] = None,
    ) -> None:
        self.batch_size = int(batch_size)
        effective_linger = linger_ms if linger_ms is not None else batch_linger_ms
        self.batch_linger_ms = int(effective_linger)
        self.poll_timeout = float(poll_timeout)
        self.priority_topic = str(priority_topic)
        self.standard_topic = str(standard_topic)
        self.standard_reserved_share = float(standard_reserved_share)
        self._clock_fn: Callable[[], float] = clock_fn or (lambda: time.monotonic())
        self._priority_queue: Deque[Message] = deque()
        self._standard_queue: Deque[Message] = deque()

    @property
    def priority_queue_size(self) -> int:
        return len(self._priority_queue)

    @property
    def standard_queue_size(self) -> int:
        return len(self._standard_queue)

    @property
    def queued_messages_count(self) -> int:
        return len(self._priority_queue) + len(self._standard_queue)

    def clear(self) -> None:
        """Clears internal queues (e.g., on consumer partition revocation)."""
        self._priority_queue.clear()
        self._standard_queue.clear()

    def subscribe(
        self,
        consumer: Consumer,
        topics: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        """Subscribes the consumer to both priority and standard topics."""
        target_topics = (
            topics
            if topics is not None
            else [self.priority_topic, self.standard_topic]
        )
        consumer.subscribe(target_topics, **kwargs)
        logger.info(
            "BrokerBatchPoller subscribed consumer to topics %s (reserved_standard=%.1f%%)",
            target_topics,
            self.standard_reserved_share * 100.0,
        )

    @staticmethod
    def filter_valid_messages(raw_messages: List[Optional[Message]]) -> List[Message]:
        valid_messages: List[Message] = []
        for msg in raw_messages:
            if msg is None:
                continue
            err = msg.error()
            if err is not None:
                if err.code() == BrokerError._PARTITION_EOF:
                    continue
                logger.error("Broker consumer error on poll: %s", err)
                continue
            valid_messages.append(msg)
        return valid_messages

    def _enqueue_messages(self, messages: List[Message]) -> None:
        for msg in messages:
            topic_fn = getattr(msg, "topic", None)
            topic_name = topic_fn() if callable(topic_fn) else None
            if topic_name == self.priority_topic:
                self._priority_queue.append(msg)
            else:
                self._standard_queue.append(msg)

    def compute_weighted_allocation(
        self, target_count: int, available_priority: int, available_standard: int
    ) -> Tuple[int, int]:
        """
        Computes `(num_priority, num_standard)` to take for a batch of `target_count` items:
        - Priority first: critical events are drained with priority.
        - Non-starvation: standard traffic is reserved at least `standard_reserved_share`
          (e.g. 30%) whenever standard messages are present.
        - Slack absorption: if either lane has fewer messages than its share, the other lane
          takes the remaining available capacity up to `target_count`.
        """
        if target_count <= 0:
            return 0, 0
        if available_priority <= 0 and available_standard <= 0:
            return 0, 0
        if available_priority <= 0:
            return 0, min(target_count, available_standard)
        if available_standard <= 0:
            return min(target_count, available_priority), 0

        # Special case: single message batch prefers priority
        if target_count == 1:
            return (1, 0) if available_priority > 0 else (0, 1)

        # Both lanes have messages: allocate with standard reserved share
        reserved_standard = int(round(target_count * self.standard_reserved_share))
        standard_guaranteed = min(available_standard, max(1, reserved_standard))

        # Priority is preferred for the remainder
        max_priority_slots = max(0, target_count - standard_guaranteed)
        num_priority = min(available_priority, max_priority_slots)

        # Standard fills the remaining slots
        num_standard = min(available_standard, target_count - num_priority)

        # Slack absorption: if standard could not fill its share, priority takes the slack
        slack = target_count - num_priority - num_standard
        if slack > 0 and available_priority > num_priority:
            extra_p = min(available_priority - num_priority, slack)
            num_priority += extra_p

        return num_priority, num_standard

    def _fetch_from_consumer(
        self, consumer: Any, needed_count: int, timeout_sec: float
    ) -> List[Message]:
        consume_fn = getattr(consumer, "consume", None)
        if callable(consume_fn):
            return consumer.consume(num_messages=needed_count, timeout=timeout_sec)
        poll_fn = getattr(consumer, "poll", None)
        if callable(poll_fn):
            items = []
            for _ in range(needed_count):
                m = consumer.poll(timeout=timeout_sec)
                if m is not None:
                    items.append(m)
                else:
                    break
            return items
        return []

    def poll_batch(
        self,
        consumer: Any,
        is_running_fn: Optional[Callable[[], bool]] = None,
    ) -> Tuple[List[Message], bool]:
        """
        Polls a micro-batch of messages across priority and standard topics.
        Applies weighted draining: priority first, with standard reserved share.
        Returns `(valid_messages, stop_after_batch)`.
        """
        running_fn = is_running_fn if is_running_fn is not None else (lambda: True)
        stop_after_batch = False

        # 1. Initial poll if queued count is below batch_size
        total_queued = len(self._priority_queue) + len(self._standard_queue)
        if total_queued < self.batch_size:
            needed = self.batch_size - total_queued
            raw_messages = self._fetch_from_consumer(
                consumer, needed_count=needed, timeout_sec=self.poll_timeout
            )
            valid_messages = self.filter_valid_messages(raw_messages)
            if valid_messages:
                self._enqueue_messages(valid_messages)

        total_queued = len(self._priority_queue) + len(self._standard_queue)
        if total_queued == 0:
            return [], False

        # 2. Accumulate up to batch_size across linger window if below batch_size
        if total_queued < self.batch_size and self.batch_linger_ms > 0:
            linger_deadline = self._clock_fn() + (self.batch_linger_ms / 1000.0)

            while running_fn() and (
                len(self._priority_queue) + len(self._standard_queue) < self.batch_size
            ):
                remaining_linger = linger_deadline - self._clock_fn()
                if remaining_linger <= 0:
                    break

                remaining_slots = self.batch_size - (
                    len(self._priority_queue) + len(self._standard_queue)
                )
                slice_timeout = min(self.poll_timeout, max(0.001, remaining_linger))
                was_running = running_fn()
                more_raw = self._fetch_from_consumer(
                    consumer, needed_count=remaining_slots, timeout_sec=slice_timeout
                )
                more_valid = self.filter_valid_messages(more_raw)
                if more_valid:
                    self._enqueue_messages(more_valid)
                else:
                    if was_running and not running_fn():
                        stop_after_batch = True
                    break

        # 3. Assemble batch via weighted allocation
        total_queued = len(self._priority_queue) + len(self._standard_queue)
        if total_queued == 0:
            return [], stop_after_batch

        target_count = min(self.batch_size, total_queued)
        num_priority, num_standard = self.compute_weighted_allocation(
            target_count=target_count,
            available_priority=len(self._priority_queue),
            available_standard=len(self._standard_queue),
        )

        batch: List[Message] = []
        for _ in range(num_priority):
            batch.append(self._priority_queue.popleft())
        for _ in range(num_standard):
            batch.append(self._standard_queue.popleft())

        return batch, stop_after_batch

