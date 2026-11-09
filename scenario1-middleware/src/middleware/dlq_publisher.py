import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from middleware.lightweight_broker import (
    LightweightConsumer as Consumer,
    LightweightMessage as Message,
    LightweightProducer as Producer,
)

from config import (
    BROKER_CONSUMER_GROUP,
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
        ) or get_header_value(msg, "x-original-topic") or (
            str(msg.get("_broker_topic")) if isinstance(msg, dict) and msg.get("_broker_topic") else None
        ) or self.default_source_topic

        partition_fn = getattr(msg, "partition", None)
        orig_partition = (
            str(partition_fn()) if callable(partition_fn) else None
        ) or get_header_value(msg, "x-original-partition") or (
            str(msg.get("_broker_partition")) if isinstance(msg, dict) and msg.get("_broker_partition") is not None else None
        ) or "0"

        offset_fn = getattr(msg, "offset", None)
        orig_offset = (
            str(offset_fn()) if callable(offset_fn) else None
        ) or get_header_value(msg, "x-original-offset") or (
            str(msg.get("_broker_offset")) if isinstance(msg, dict) and msg.get("_broker_offset") is not None else None
        ) or "0"

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
            if key_bytes is None and isinstance(msg, dict):
                client_ip = str(msg.get("_client_ip") or msg.get("client_ip") or "")
                if client_ip:
                    key_bytes = client_ip.encode("utf-8")

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
            msgs = list(gelf_batch)

        if not msgs:
            return True

        return self.publish_to_dlq(
            messages=msgs,
            reason=reason,
            retry_count=retry_count or 1,
        )

    def replay(
        self,
        target_topic: Optional[str] = None,
        source_topic: Optional[str] = None,
        limit: int = 100,
        **kwargs: Any,
    ) -> int:
        """
        Replays messages from DLQ topic/storage back to the target ingestion topic.
        Consumes messages from source DLQ topic, preserves deterministic event IDs,
        publishes to target_topic, flushes producer for durable confirmation, and
        commits DLQ offsets to acknowledge and remove replayed messages from DLQ backlog.
        Returns the exact count of replayed messages.
        """
        src_topic = source_topic or kwargs.get("dlq_topic") or kwargs.get("source_topic") or self.dlq_topic
        tgt_topic = target_topic or kwargs.get("target_topic") or self.default_source_topic
        max_msgs = int(kwargs.get("batch_size") or kwargs.get("limit") or limit)

        if max_msgs <= 0:
            return 0

        replay_group = f"{BROKER_CONSUMER_GROUP}-dlq-publisher-replay"
        consumer_conf = {
            "bootstrap.servers": self._bootstrap_servers,
            "group.id": replay_group,
            "client.id": "soar-dlq-replay-consumer",
            "enable.auto.commit": False,
            "auto.offset.reset": "earliest",
            "session.timeout.ms": 10000,
            "broker.db.path": self.broker_db_path,
            "num_partitions": self.num_partitions,
        }
        replay_consumer = Consumer(
            consumer_conf,
            db_path=self.broker_db_path,
            num_partitions=self.num_partitions,
        )
        replay_consumer.subscribe([src_topic])

        replayed_messages: List[Message] = []
        start_time = time.monotonic()
        empty_count = 0
        try:
            while len(replayed_messages) < max_msgs and (time.monotonic() - start_time) < 5.0:
                is_running_fn = kwargs.get("is_running_fn")
                if callable(is_running_fn) and not is_running_fn():
                    break
                msg = replay_consumer.poll(timeout=0.1)
                if msg is None:
                    empty_count += 1
                    if empty_count >= 3:
                        break
                    continue
                if msg.error():
                    continue
                replayed_messages.append(msg)
                empty_count = 0

            if not replayed_messages:
                return 0

            acquire_tokens_fn = kwargs.get("acquire_tokens_fn")
            if callable(acquire_tokens_fn):
                acquire_tokens_fn(float(len(replayed_messages)))

            replay_id = str(uuid.uuid4())

            for msg in replayed_messages:
                key_bytes = msg.key()
                raw_val = msg.value()
                val_bytes = raw_val

                existing_headers: List[Tuple[str, bytes]] = []
                orig_partition = None
                orig_offset = None
                raw_headers = msg.headers()
                if raw_headers:
                    for k, v in raw_headers:
                        v_str = (
                            v.decode("utf-8", errors="replace")
                            if isinstance(v, bytes)
                            else str(v)
                        )
                        if k.lower() == "x-original-partition":
                            orig_partition = v_str
                        elif k.lower() == "x-original-offset":
                            orig_offset = v_str
                        existing_headers.append((k, v))

                if orig_partition is not None and orig_offset is not None:
                    event_id = f"{orig_partition}:{orig_offset}"
                else:
                    event_id = f"{msg.partition()}:{msg.offset()}"

                try:
                    decoded = json.loads(raw_val.decode("utf-8"))
                    if isinstance(decoded, dict):
                        if "_event_id" not in decoded or not decoded["_event_id"]:
                            decoded["_event_id"] = event_id
                        val_bytes = json.dumps(
                            decoded, separators=(",", ":"), ensure_ascii=False
                        ).encode("utf-8")
                except Exception:
                    pass

                out_headers = [
                    (k, v)
                    for k, v in existing_headers
                    if k.lower() not in ("x-replay-id", "x-original-event-id")
                ]
                out_headers.append(("x-replay-id", replay_id.encode("utf-8")))
                out_headers.append(("x-original-event-id", event_id.encode("utf-8")))

                self.producer.produce(
                    topic=tgt_topic,
                    key=key_bytes,
                    value=val_bytes,
                    headers=out_headers,
                )

            flush_remaining = self.producer.flush(timeout=self.flush_timeout)
            if flush_remaining > 0:
                logger.error(
                    "DLQ replay producer flush timed out with %d unconfirmed messages; aborting commit.",
                    flush_remaining,
                )
                return 0

            replay_consumer.commit(asynchronous=False)
            replayed_count = len(replayed_messages)

            on_chunk_replayed = kwargs.get("on_chunk_replayed")
            if callable(on_chunk_replayed):
                try:
                    on_chunk_replayed(replayed_count)
                except Exception as exc:
                    logger.warning("on_chunk_replayed callback error: %s", exc)

            logger.info(
                "Successfully replayed %d messages from DLQ topic '%s' to target topic '%s' (replay_id=%s).",
                replayed_count,
                src_topic,
                tgt_topic,
                replay_id,
            )
            return replayed_count
        finally:
            try:
                replay_consumer.close()
            except Exception:
                pass

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
