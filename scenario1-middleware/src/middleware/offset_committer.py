import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from middleware.lightweight_broker import (
    BrokerError,
    BrokerException,
    LightweightConsumer as Consumer,
    TopicPartition,
)

_BrokerExceptionType: Tuple[type, ...] = (BrokerException,)

from config import BROKER_TOPIC
from middleware.models import InFlightBatchState

logger = logging.getLogger("soar.offset_committer")

_REBALANCE_ERROR_CODES: Set[int] = {
    code
    for code in (
        getattr(BrokerError, "ILLEGAL_GENERATION", None),
        getattr(BrokerError, "REBALANCE_IN_PROGRESS", None),
        getattr(BrokerError, "UNKNOWN_MEMBER_ID", None),
        getattr(BrokerError, "_REVOKED_PARTITIONS", None),
        getattr(BrokerError, "NOT_COORDINATOR_FOR_GROUP", None),
        getattr(BrokerError, "_WAIT_COORD", None),
        getattr(BrokerError, "_IN_PROGRESS", None),
    )
    if isinstance(code, int)
}

_REBALANCE_KEYWORDS: Tuple[str, ...] = (
    "rebalance",
    "illegal_generation",
    "rebalance_in_progress",
    "unknown_member_id",
    "revoked",
    "generation",
    "member_id",
    "unknown member",
)


class ExplicitOffsetCommitter:
    """
    Calculates and commits exact per-partition `max_offset + 1` offsets synchronously
    ONLY after downstream Graylog 2xx acknowledgment or Dead Letter persistence.
    Tracks assigned/revoked/lost partitions and in-flight vs. confirmed batch state
    across cooperative-sticky consumer group rebalances.
    """

    def __init__(self, default_topic: str = BROKER_TOPIC) -> None:
        self.default_topic = default_topic
        self.assigned_partitions: Set[Tuple[str, int]] = set()
        self.revoked_count: int = 0
        self.lost_count: int = 0
        self.in_flight_batch: Optional[InFlightBatchState] = None
        self.in_flight_aborted: bool = False
        self._confirmed_offsets: Dict[Tuple[str, int], TopicPartition] = {}

    def get_assigned_topic_partitions(self) -> List[TopicPartition]:
        """Returns currently assigned partitions as sorted `TopicPartition` instances."""
        return [
            TopicPartition(topic, partition)
            for topic, partition in sorted(self.assigned_partitions)
        ]

    @staticmethod
    def format_offset_ranges(offset_ranges: Dict[int, Tuple[int, int]]) -> str:
        """Formats `{partition: (min_offset, max_offset)}` into a human/log-friendly string."""
        if not offset_ranges:
            return "none"
        return ",".join(
            f"{part}:{low}-{high}"
            for part, (low, high) in sorted(offset_ranges.items())
        )

    def begin_batch(self, batch_id: str, messages: List[Any]) -> InFlightBatchState:
        """Registers an unconfirmed in-flight batch before rate-limiting and delivery."""
        ranges = self.compute_partition_offset_ranges(messages)
        offsets = self.compute_batch_offsets(messages)
        self.in_flight_aborted = False
        self.in_flight_batch = InFlightBatchState(
            batch_id=batch_id,
            partition_offset_ranges=ranges,
            offsets=offsets,
            confirmed=False,
        )
        return self.in_flight_batch

    def mark_batch_confirmed(
        self,
        messages: Optional[List[Any]] = None,
        batch_id: Optional[str] = None,
    ) -> List[TopicPartition]:
        """
        Marks a batch as confirmed (HTTP 2xx or durable DLQ write) so its offsets
        are eligible to be committed on `on_revoke` or `commit_batch_offsets`.
        """
        if messages is not None:
            offsets = self.compute_batch_offsets(messages)
        elif self.in_flight_batch is not None:
            offsets = list(self.in_flight_batch.offsets)
        else:
            offsets = []

        if self.in_flight_batch is not None and (
            batch_id is None or self.in_flight_batch.batch_id == batch_id
        ):
            self.in_flight_batch.confirmed = True

        for tp in offsets:
            key = (tp.topic, int(tp.partition))
            existing = self._confirmed_offsets.get(key)
            if existing is None or int(tp.offset) > int(existing.offset):
                self._confirmed_offsets[key] = tp

        return offsets

    def clear_in_flight_batch(self) -> None:
        """Clears the current in-flight batch tracking state."""
        self.in_flight_batch = None
        self.in_flight_aborted = False

    def on_assign(self, _consumer: Any, partitions: List[TopicPartition]) -> None:
        for tp in partitions:
            self.assigned_partitions.add((tp.topic, int(tp.partition)))
        logger.info(
            "Consumer group partition assignment updated: %s",
            [(tp.topic, tp.partition) for tp in partitions],
        )

    def on_revoke(self, consumer: Any, partitions: List[TopicPartition]) -> None:
        """
        Cooperative-sticky `on_revoke` callback:
        - Never commits offsets for an in-flight batch that was not confirmed 2xx.
        - Commits ONLY offsets of already-confirmed batches for the revoked partitions.
        """
        self.revoked_count += 1
        revoked_keys: Set[Tuple[str, int]] = set()
        for tp in partitions:
            key = (tp.topic, int(tp.partition))
            revoked_keys.add(key)
            self.assigned_partitions.discard(key)

        if self.in_flight_batch is not None and not self.in_flight_batch.confirmed:
            in_flight_keys = {
                (tp.topic, int(tp.partition)) for tp in self.in_flight_batch.offsets
            }
            overlapping = in_flight_keys & revoked_keys
            if overlapping:
                self.in_flight_aborted = True
                offset_range_str = self.format_offset_ranges(
                    self.in_flight_batch.partition_offset_ranges
                )
                primary_partition = next(
                    iter(self.in_flight_batch.partition_offset_ranges.keys()), None
                )
                logger.warning(
                    "Consumer group partitions revoked while batch %s is unconfirmed "
                    "(partitions=%s, offset_range=%s); refusing to commit unconfirmed offsets.",
                    self.in_flight_batch.batch_id,
                    sorted(overlapping),
                    offset_range_str,
                    extra={
                        "batch_id": self.in_flight_batch.batch_id,
                        "partition": primary_partition,
                        "offset_range": offset_range_str,
                    },
                )

        confirmed_to_commit = [
            tp
            for key, tp in sorted(self._confirmed_offsets.items())
            if key in revoked_keys
        ]
        if confirmed_to_commit and consumer is not None:
            try:
                consumer.commit(offsets=confirmed_to_commit, asynchronous=False)
            except _BrokerExceptionType as exc:
                logger.warning(
                    "Failed to commit confirmed offsets during on_revoke: %s", exc
                )
            finally:
                for tp in confirmed_to_commit:
                    self._confirmed_offsets.pop((tp.topic, int(tp.partition)), None)

        logger.warning(
            "Consumer group partitions revoked (rebalance #%d): %s",
            self.revoked_count,
            [(tp.topic, tp.partition) for tp in partitions],
        )

    def on_lost(self, _consumer: Any, partitions: List[TopicPartition]) -> None:
        """
        Cooperative-sticky `on_lost` callback:
        - Drops in-flight batch state without committing.
        - Logs a WARNING with `batch_id` and `offset_range`.
        """
        self.lost_count += 1
        for tp in partitions:
            key = (tp.topic, int(tp.partition))
            self.assigned_partitions.discard(key)
            self._confirmed_offsets.pop(key, None)

        if self.in_flight_batch is not None:
            batch_id = self.in_flight_batch.batch_id
            offset_range_str = self.format_offset_ranges(
                self.in_flight_batch.partition_offset_ranges
            )
            primary_partition = next(
                iter(self.in_flight_batch.partition_offset_ranges.keys()), None
            )
        else:
            batch_id = "none"
            offset_range_str = (
                ",".join(f"{tp.partition}:{tp.offset}" for tp in partitions)
                if partitions
                else "none"
            )
            primary_partition = int(partitions[0].partition) if partitions else None

        self.in_flight_batch = None
        self.in_flight_aborted = True

        logger.warning(
            "Consumer group partitions lost (lost #%d): %s. "
            "Dropped in-flight batch state without committing (batch_id=%s, offset_range=%s).",
            self.lost_count,
            [(tp.topic, tp.partition) for tp in partitions],
            batch_id,
            offset_range_str,
            extra={
                "batch_id": batch_id,
                "partition": primary_partition,
                "offset_range": offset_range_str,
            },
        )

    @staticmethod
    def is_rebalance_error(exc: BaseException) -> bool:
        """Returns True if `exc` represents a consumer-group rebalance commit failure."""
        if exc.args:
            first_arg = exc.args[0]
            code_fn = getattr(first_arg, "code", None)
            if callable(code_fn):
                try:
                    code_val = code_fn()
                    if isinstance(code_val, int) and code_val in _REBALANCE_ERROR_CODES:
                        return True
                except Exception:
                    pass
            name_fn = getattr(first_arg, "name", None)
            if callable(name_fn):
                try:
                    name_val = str(name_fn()).lower()
                    if any(kw in name_val for kw in _REBALANCE_KEYWORDS):
                        return True
                except Exception:
                    pass

        exc_text = str(exc).lower()
        return any(kw in exc_text for kw in _REBALANCE_KEYWORDS)

    @staticmethod
    def compute_partition_offset_ranges(
        messages: List[Any],
    ) -> Dict[int, Tuple[int, int]]:
        """Returns `{partition: (min_offset, max_offset)}` for correlation logging."""
        ranges: Dict[int, Tuple[int, int]] = {}
        for msg in messages:
            part = int(msg.partition())
            off = int(msg.offset())
            if part not in ranges:
                ranges[part] = (off, off)
            else:
                low, high = ranges[part]
                ranges[part] = (min(low, off), max(high, off))
        return ranges

    def compute_batch_offsets(self, messages: List[Any]) -> List[TopicPartition]:
        max_offsets: Dict[Tuple[str, int], int] = {}
        for msg in messages:
            topic_fn = getattr(msg, "topic", None)
            topic_name = (
                topic_fn() if callable(topic_fn) else None
            ) or self.default_topic
            partition = int(msg.partition())
            next_offset = int(msg.offset()) + 1
            key = (topic_name, partition)
            if key not in max_offsets or next_offset > max_offsets[key]:
                max_offsets[key] = next_offset

        return [
            TopicPartition(topic_name, partition, next_offset)
            for (topic_name, partition), next_offset in sorted(max_offsets.items())
        ]

    def commit_batch_offsets(
        self, consumer: Consumer, messages: List[Any]
    ) -> List[TopicPartition]:
        """
        Commits ONLY the highest `offset + 1` per `(topic, partition)` present in `messages`
        synchronously (`asynchronous=False`).
        """
        batch_offsets = self.compute_batch_offsets(messages)
        try:
            if batch_offsets:
                consumer.commit(offsets=batch_offsets, asynchronous=False)
            return batch_offsets
        finally:
            for tp in batch_offsets:
                self._confirmed_offsets.pop((tp.topic, int(tp.partition)), None)
            self.in_flight_batch = None
            self.in_flight_aborted = False

