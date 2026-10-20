import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from middleware.lightweight_broker import (
    LightweightMessage as Message,
    LightweightProducer as Producer,
)

from config import (
    BROKER_DB_PATH,
    BROKER_DLQ_TOPIC,
    BROKER_PARTITIONS,
    BROKER_POISON_TOPIC,
    BROKER_RETRY_1M_TOPIC,
    BROKER_RETRY_10M_TOPIC,
    BROKER_TOPIC,
    SETTINGS,
)
from middleware.exceptions import DeadLetterStoreError

logger = logging.getLogger("soar.dlq_publisher")


def _encode_header(val: Any) -> bytes:
    if isinstance(val, bytes):
        return val
    return str(val).encode("utf-8")


def _decode_header(val: Optional[Union[bytes, str]]) -> str:
    if val is None:
        return ""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val)


def get_header_value(msg: Any, header_name: str) -> Optional[str]:
    """Extracts a named header from a Broker Message or dictionary."""
    headers_fn = getattr(msg, "headers", None)
    if callable(headers_fn):
        raw_headers = headers_fn()
        if raw_headers:
            for k, v in raw_headers:
                if k == header_name or k.lower() == header_name.lower():
                    return _decode_header(v)
    elif isinstance(msg, dict):
        headers_dict = msg.get("headers", {})
        if header_name in headers_dict:
            return str(headers_dict[header_name])
    return None


class _SyntheticMessageWrapper:
    """Wraps a dictionary (such as GELF or decoded record) into a Message-like interface."""

    def __init__(self, record: Dict[str, Any], default_topic: str = BROKER_TOPIC) -> None:
        self._record = record
        self._topic = str(record.get("_broker_topic") or default_topic)
        self._partition = int(record.get("_broker_partition", 0))
        self._offset = int(record.get("_broker_offset", 0))
        client_ip = str(record.get("_client_ip") or record.get("client_ip") or "0.0.0.0")
        self._key = client_ip.encode("utf-8")
        self._value = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def topic(self) -> str:
        return self._topic

    def partition(self) -> int:
        return self._partition

    def offset(self) -> int:
        return self._offset

    def key(self) -> bytes:
        return self._key

    def value(self) -> bytes:
        return self._value

    def headers(self) -> Optional[List[Tuple[str, bytes]]]:
        return None


class DeadLetterSink(ABC):
    """
    Abstract interface for Dead-Letter Sinks (Broker topic or local JSONL file).
    Guarantees durable persistence of failed batches before source offsets are committed.
    """

    @abstractmethod
    def write_dead_letter(
        self,
        *,
        messages: Optional[List[Any]] = None,
        gelf_batch: Optional[List[Dict[str, Any]]] = None,
        reason: str = "Retries exhausted",
        retry_count: int = 0,
        dlq_path: Optional[str] = None,
    ) -> bool:
        """
        Durably persists an undeliverable batch.
        Returns True if write confirmed, False if failed (aborted).
        """
        pass

    def write_batch(self, dlq_path: str, gelf_batch: List[Dict[str, Any]]) -> None:
        """Backward-compatible batch write."""
        success = self.write_dead_letter(gelf_batch=gelf_batch, dlq_path=dlq_path)
        if not success:
            raise DeadLetterStoreError("Failed to write dead letter batch")


class BrokerDeadLetterPublisher(DeadLetterSink):
    """
    Broker-based Dead-Letter and Poison message publisher.
    Publishes exhausted batches to `security-logs.dlq` and unparseable poison messages to
    `security-logs.poison`. Commits source offsets ONLY after the producer delivery report
    confirms the DLQ write (flush + delivery report check).
    """

    def __init__(
        self,
        producer: Optional[Producer] = None,
        bootstrap_servers: Optional[str] = None,
        dlq_topic: str = BROKER_DLQ_TOPIC,
        retry_1m_topic: str = BROKER_RETRY_1M_TOPIC,
        retry_10m_topic: str = BROKER_RETRY_10M_TOPIC,
        poison_topic: str = BROKER_POISON_TOPIC,
        default_source_topic: str = BROKER_TOPIC,
        flush_timeout: float = 10.0,
        broker_db_path: Optional[str] = None,
        num_partitions: int = BROKER_PARTITIONS,
    ) -> None:
        self._producer = producer
        self._bootstrap_servers = bootstrap_servers or "localhost:9094"
        self.dlq_topic = dlq_topic
        self.retry_1m_topic = retry_1m_topic
        self.retry_10m_topic = retry_10m_topic
        self.poison_topic = poison_topic
        self.default_source_topic = default_source_topic
        self.flush_timeout = flush_timeout
        self.broker_db_path = str(broker_db_path or BROKER_DB_PATH)
        self.num_partitions = int(num_partitions)

    @property
    def producer(self) -> Producer:
        if self._producer is None:
            producer_conf = {
                "bootstrap.servers": self._bootstrap_servers,
                "client.id": "soar-dlq-publisher",
                "acks": "all",
                "enable.idempotence": True,
                "retries": 5,
                "delivery.timeout.ms": 30000,
                "broker.db.path": self.broker_db_path,
                "num_partitions": self.num_partitions,
            }
            self._producer = Producer(
                producer_conf,
                db_path=self.broker_db_path,
                num_partitions=self.num_partitions,
            )
        return self._producer

    def _build_headers(
        self,
        msg: Any,
        reason: str,
        retry_count: int,
        first_failed_at: str,
    ) -> List[Tuple[str, bytes]]:
        topic_fn = getattr(msg, "topic", None)
        orig_topic = (
            topic_fn() if callable(topic_fn) else None
        ) or get_header_value(msg, "x-original-topic") or self.default_source_topic

        partition_fn = getattr(msg, "partition", None)
        orig_partition = (
            str(partition_fn()) if callable(partition_fn) else None
        ) or get_header_value(msg, "x-original-partition") or "0"

        offset_fn = getattr(msg, "offset", None)
        orig_offset = (
            str(offset_fn()) if callable(offset_fn) else None
        ) or get_header_value(msg, "x-original-offset") or "0"

        existing_first_failed = get_header_value(msg, "x-first-failed-at")
        effective_first_failed = existing_first_failed or first_failed_at

        return [
            ("x-original-topic", _encode_header(orig_topic)),
            ("x-original-partition", _encode_header(orig_partition)),
            ("x-original-offset", _encode_header(orig_offset)),
            ("x-retry-count", _encode_header(retry_count)),
            ("x-failure-reason", _encode_header(reason)),
            ("x-first-failed-at", _encode_header(effective_first_failed)),
        ]

    def publish_messages(
        self,
        topic: str,
        messages: List[Any],
        reason: str = "Retries exhausted",
        retry_count: int = 1,
        extra_headers: Optional[List[Tuple[str, bytes]]] = None,
    ) -> bool:
        """
        Publishes messages to `topic` and verifies synchronous delivery reports via flush.
        Returns True ONLY if all delivery reports succeed without error.
        If any delivery report reports an error or flush times out, returns False.
        """
        if not messages:
            return True

        delivery_results: Dict[str, Any] = {
            "delivered": 0,
            "failed": 0,
            "errors": [],
        }

        def on_delivery_callback(err: Any, delivered_msg: Any) -> None:
            if err is not None:
                delivery_results["failed"] += 1
                delivery_results["errors"].append(str(err))
                logger.error(
                    "Broker delivery failure for message on topic %s: %s",
                    topic,
                    err,
                )
            else:
                delivery_results["delivered"] += 1

        now_iso = datetime.now(timezone.utc).isoformat()

        for msg in messages:
            headers = self._build_headers(
                msg,
                reason=reason,
                retry_count=retry_count,
                first_failed_at=now_iso,
            )
            if extra_headers:
                headers.extend(extra_headers)

            key_fn = getattr(msg, "key", None)
            key_bytes = key_fn() if callable(key_fn) else None

            val_fn = getattr(msg, "value", None)
            if callable(val_fn):
                val_bytes = val_fn()
            elif isinstance(msg, (bytes, bytearray)):
                val_bytes = bytes(msg)
            elif isinstance(msg, dict):
                val_bytes = json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            else:
                val_bytes = str(msg).encode("utf-8")

            try:
                self.producer.produce(
                    topic=topic,
                    key=key_bytes,
                    value=val_bytes,
                    headers=headers,
                    on_delivery=on_delivery_callback,
                )
            except Exception as exc:
                logger.error("Produce call failed for topic %s: %s", topic, exc)
                delivery_results["failed"] += 1
                delivery_results["errors"].append(str(exc))
                return False

        try:
            remaining = self.producer.flush(timeout=self.flush_timeout)
            if remaining > 0:
                logger.error(
                    "Producer flush timed out on topic %s (%d unacknowledged messages remaining).",
                    topic,
                    remaining,
                )
                return False
        except Exception as exc:
            logger.error("Exception during producer flush on topic %s: %s", topic, exc)
            return False

        if delivery_results["failed"] > 0 or delivery_results["delivered"] != len(messages):
            logger.error(
                "DLQ publish on topic %s failed delivery confirmation: %d delivered, %d failed out of %d total (errors: %s)",
                topic,
                delivery_results["delivered"],
                delivery_results["failed"],
                len(messages),
                delivery_results["errors"],
            )
            return False

        logger.info(
            "Confirmed durable DLQ delivery of %d messages to topic %s",
            len(messages),
            topic,
        )
        return True

    def publish_to_dlq(
        self,
        messages: List[Any],
        reason: str = "Retries exhausted",
        retry_count: int = 1,
    ) -> bool:
        """Publishes exhausted messages to `security-logs.dlq`."""
        return self.publish_messages(
            topic=self.dlq_topic,
            messages=messages,
            reason=reason,
            retry_count=retry_count,
        )

    def publish_poison(
        self,
        message: Any,
        reason: str = "Unparseable poison message",
    ) -> bool:
        """
        Publishes an unparseable poison message to `security-logs.poison` with error headers.
        Returns True if delivery confirmed, False if failed.
        """
        return self.publish_messages(
            topic=self.poison_topic,
            messages=[message],
            reason=reason,
            retry_count=0,
            extra_headers=[("x-poison-error", _encode_header(reason))],
        )

    def publish_retry_tier(
        self,
        messages: List[Any],
        tier_topic: str,
        retry_count: int,
        reason: str = "Retry tier delivery hold",
        due_time: Optional[float] = None,
    ) -> bool:
        """Publishes messages to a delayed retry tier topic with `x-due-time` header."""
        extra: List[Tuple[str, bytes]] = []
        if due_time is not None:
            extra.append(("x-due-time", _encode_header(f"{due_time:.3f}")))
        return self.publish_messages(
            topic=tier_topic,
            messages=messages,
            reason=reason,
            retry_count=retry_count,
            extra_headers=extra,
        )

    def write_dead_letter(
        self,
        *,
        messages: Optional[List[Any]] = None,
        gelf_batch: Optional[List[Dict[str, Any]]] = None,
        reason: str = "Retries exhausted",
        retry_count: int = 0,
        dlq_path: Optional[str] = None,
    ) -> bool:
        """
        Durable dead-letter entry point implementing `DeadLetterSink`.
        Accepts raw broker `Message` objects or GELF dictionaries and routes to `security-logs.dlq`.
        """
        msgs: List[Any] = []
        if messages:
            msgs = list(messages)
        elif gelf_batch:
            msgs = [_SyntheticMessageWrapper(item, default_topic=self.default_source_topic) for item in gelf_batch]

        if not msgs:
            return True

        return self.publish_to_dlq(
            messages=msgs,
            reason=reason,
            retry_count=retry_count or 1,
        )

    def replay(self, *args: Any, **kwargs: Any) -> int:
        """Broker DLQ is replayed via admin API or background retry consumer, not file replay."""
        return 0

    def close(self) -> None:
        if self._producer is not None:
            try:
                self._producer.flush(timeout=3.0)
            except Exception:
                pass


__all__ = [
    "DeadLetterSink",
    "BrokerDeadLetterPublisher",
    "get_header_value",
]
