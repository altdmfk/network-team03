import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional

import httpx
from middleware.lightweight_broker import (
    BrokerException,
    LightweightConsumer as Consumer,
    LightweightMessage as Message,
    TopicPartition,
)

from config import (
    BROKER_DB_PATH,
    BROKER_DLQ_TOPIC,
    BROKER_PARTITIONS,
    BROKER_POISON_TOPIC,
    BROKER_RETRY_1M_TOPIC,
    BROKER_RETRY_10M_TOPIC,
    GRAYLOG_GELF_URL,
    MAX_RETRY_TOPIC_ATTEMPTS,
    SETTINGS,
)
from metrics_store import SharedMetricsStore
from middleware.dlq_publisher import (
    BrokerDeadLetterPublisher,
    get_header_value,
)
from middleware.gelf_transformer import transform_to_gelf

logger = logging.getLogger("soar.retry_topic_consumer")


class RetryTopicConsumer:
    """
    Consumes from tiered retry topics (`security-logs.retry.1m`, `security-logs.retry.10m`).
    Honors delays by pausing the partition until the message's due time.
    Enforces a max retry count cap so poison or repeatedly failing messages cannot loop forever,
    escalating them durably to `security-logs.dlq` before committing the retry offset.
    """

    def __init__(
        self,
        consumer: Optional[Consumer] = None,
        dlq_publisher: Optional[BrokerDeadLetterPublisher] = None,
        http_client: Optional[httpx.Client] = None,
        metrics_store: Optional[SharedMetricsStore] = None,
        bootstrap_servers: Optional[str] = None,
        group_id: str = "soar-retry-topic-consumer-group",
        retry_topics: Optional[List[str]] = None,
        topic_delays: Optional[Dict[str, float]] = None,
        dlq_topic: str = BROKER_DLQ_TOPIC,
        poison_topic: str = BROKER_POISON_TOPIC,
        max_retries: int = MAX_RETRY_TOPIC_ATTEMPTS,
        gelf_url: str = GRAYLOG_GELF_URL,
        clock_fn: Optional[Callable[[], float]] = None,
        sleep_fn: Optional[Callable[[float], None]] = None,
        broker_db_path: Optional[str] = None,
        num_partitions: int = BROKER_PARTITIONS,
    ) -> None:
        self.running = True
        self._consumer = consumer
        self._bootstrap_servers = bootstrap_servers or "localhost:9094"
        self._group_id = group_id
        self.broker_db_path = str(broker_db_path or BROKER_DB_PATH)
        self.num_partitions = int(num_partitions)
        self.retry_topics = retry_topics or [BROKER_RETRY_1M_TOPIC, BROKER_RETRY_10M_TOPIC]
        self.topic_delays = topic_delays or {
            BROKER_RETRY_1M_TOPIC: 60.0,
            BROKER_RETRY_10M_TOPIC: 600.0,
        }
        self.dlq_topic = dlq_topic
        self.poison_topic = poison_topic
        self.max_retries = max_retries
        self.gelf_url = gelf_url
        self.metrics = metrics_store

        self.clock_fn: Callable[[], float] = clock_fn or (lambda: time.time())
        self.sleep_fn: Callable[[float], None] = sleep_fn or (lambda s: time.sleep(s))

        self.dlq_publisher: BrokerDeadLetterPublisher = dlq_publisher or BrokerDeadLetterPublisher(
            bootstrap_servers=self._bootstrap_servers,
            dlq_topic=self.dlq_topic,
            poison_topic=self.poison_topic,
            broker_db_path=self.broker_db_path,
            num_partitions=self.num_partitions,
        )
        self.http_client: httpx.Client = http_client or httpx.Client(
            timeout=httpx.Timeout(10.0),
            headers={"Content-Type": "application/json"},
        )
        self._owns_http_client = http_client is None
        self._subscribed = False

    @property
    def consumer(self) -> Consumer:
        if self._consumer is None:
            conf = {
                "bootstrap.servers": self._bootstrap_servers,
                "group.id": self._group_id,
                "client.id": "soar-retry-topic-consumer",
                "enable.auto.commit": False,
                "auto.offset.reset": "earliest",
                "session.timeout.ms": 30000,
                "broker.db.path": self.broker_db_path,
                "num_partitions": self.num_partitions,
            }
            self._consumer = Consumer(
                conf,
                db_path=self.broker_db_path,
                num_partitions=self.num_partitions,
            )
        return self._consumer

    def _ensure_subscribed(self) -> None:
        if not self._subscribed and self.consumer is not None:
            subscribe_fn = getattr(self.consumer, "subscribe", None)
            if callable(subscribe_fn):
                self.consumer.subscribe(self.retry_topics)
            self._subscribed = True

    def commit_message_offset(self, msg: Message) -> None:
        """Commits the exact `offset + 1` for this message on its retry topic partition."""
        tp = TopicPartition(msg.topic(), msg.partition(), msg.offset() + 1)
        self.consumer.commit(offsets=[tp], asynchronous=False)

    def extract_retry_count(self, msg: Any) -> int:
        raw = get_header_value(msg, "x-retry-count")
        if raw is not None:
            try:
                return int(raw.strip())
            except ValueError:
                pass
        return 1

    def calculate_due_time(self, msg: Any) -> float:
        raw_due = get_header_value(msg, "x-due-time")
        if raw_due is not None:
            try:
                return float(raw_due.strip())
            except ValueError:
                pass

        topic = msg.topic() if hasattr(msg, "topic") and callable(msg.topic) else BROKER_RETRY_1M_TOPIC
        delay = self.topic_delays.get(topic, 60.0)

        ts_fn = getattr(msg, "timestamp", None)
        if callable(ts_fn):
            ts_type, ts_ms = ts_fn()
            if ts_ms and ts_ms > 0:
                return (ts_ms / 1000.0) + delay

        return self.clock_fn() + delay

    def wait_until_due(self, msg: Message, due_time: float) -> bool:
        """
        Honors retry delay by pausing the partition and seeking back to this message's offset,
        polling with 0 while paused to keep heartbeat alive, then resuming.
        """
        now = self.clock_fn()
        if now >= due_time:
            return True

        delay_needed = due_time - now
        tp = TopicPartition(msg.topic(), msg.partition())
        logger.info(
            "Message at %s:%d offset %d not due for %.2fs. Pausing partition...",
            msg.topic(),
            msg.partition(),
            msg.offset(),
            delay_needed,
        )

        pause_fn = getattr(self.consumer, "pause", None)
        seek_fn = getattr(self.consumer, "seek", None)
        resume_fn = getattr(self.consumer, "resume", None)

        if callable(pause_fn):
            self.consumer.pause([tp])
        if callable(seek_fn):
            self.consumer.seek(TopicPartition(msg.topic(), msg.partition(), msg.offset()))

        slept = 0.0
        step = min(1.0, max(0.05, delay_needed))
        try:
            while slept < delay_needed and self.running:
                poll_fn = getattr(self.consumer, "poll", None)
                if callable(poll_fn):
                    self.consumer.poll(0)
                time_to_sleep = min(step, delay_needed - slept)
                self.sleep_fn(time_to_sleep)
                slept += time_to_sleep
        finally:
            if callable(resume_fn):
                self.consumer.resume([tp])

        return self.running

    def process_single_message(self, msg: Message) -> bool:
        """
        Processes a single message polled from a retry topic:
        1. Checks max retry count cap -> if exceeded, durably escalates to DLQ and commits.
        2. Honors delay by pausing partition until due time.
        3. Attempts delivery to Graylog.
        4. On success: commits offset and increments forwarded metric.
        5. On failure: routes to next tier or DLQ, commits offset upon durable publish.
        """
        retry_count = self.extract_retry_count(msg)
        topic = msg.topic()

        # Enforce retry count cap so poison messages cannot loop forever
        if retry_count >= self.max_retries:
            logger.warning(
                "Retry cap reached (retry_count=%d >= max_retries=%d) for message at %s:%d:%d. Escalating to DLQ.",
                retry_count,
                self.max_retries,
                topic,
                msg.partition(),
                msg.offset(),
            )
            confirmed = self.dlq_publisher.publish_to_dlq(
                [msg],
                reason=f"Exceeded max retry cap ({self.max_retries})",
                retry_count=retry_count,
            )
            if confirmed:
                self.commit_message_offset(msg)
                if self.metrics:
                    self.metrics.increment_dlq_quarantined(1, flush=True)
                return True
            logger.error("Failed to publish to DLQ during retry-cap escalation; offset not committed.")
            return False

        # Honor due time delay
        due_time = self.calculate_due_time(msg)
        if not self.wait_until_due(msg, due_time):
            return False

        # Parse message payload
        raw_val = msg.value()
        try:
            decoded = json.loads(raw_val.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise ValueError("Payload is not a JSON object")
        except Exception as exc:
            logger.error(
                "Unparseable poison message in retry topic %s:%d:%d (%s). Quarantining to poison topic.",
                topic,
                msg.partition(),
                msg.offset(),
                exc,
            )
            confirmed = self.dlq_publisher.publish_poison(msg, reason=f"Unparseable in retry: {exc}")
            if confirmed:
                self.commit_message_offset(msg)
                if self.metrics:
                    self.metrics.increment_poison_messages(1, flush=True)
                return True
            return False

        # Transform to GELF
        gelf_record = transform_to_gelf(
            decoded,
            partition=msg.partition(),
            offset=msg.offset(),
        )

        # Attempt delivery to Graylog
        delivered = False
        error_reason = "Unknown delivery error"
        try:
            payload_bytes = json.dumps(
                gelf_record, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            response = self.http_client.post(self.gelf_url, content=payload_bytes)
            delivered = 200 <= response.status_code < 300
            if not delivered:
                error_reason = f"HTTP {response.status_code}: {response.text[:150]}"
        except httpx.RequestError as exc:
            error_reason = f"Connection error: {exc}"

        if delivered:
            self.commit_message_offset(msg)
            if self.metrics:
                self.metrics.increment_forwarded(1, flush=True)
            logger.info(
                "Successfully delivered retry message from %s:%d:%d to Graylog.",
                topic,
                msg.partition(),
                msg.offset(),
            )
            return True

        # Delivery failed: route to next tier or DLQ
        next_count = retry_count + 1
        if topic == BROKER_RETRY_1M_TOPIC:
            next_topic = BROKER_RETRY_10M_TOPIC
            next_delay = self.topic_delays.get(next_topic, 600.0)
            next_due = self.clock_fn() + next_delay
            logger.warning(
                "Delivery failed on 1m retry topic (reason: %s). Escalating to 10m retry tier.",
                error_reason,
            )
            confirmed = self.dlq_publisher.publish_retry_tier(
                [msg],
                tier_topic=next_topic,
                retry_count=next_count,
                reason=error_reason,
                due_time=next_due,
            )
        else:
            logger.warning(
                "Delivery failed on 10m retry tier (reason: %s). Escalating to DLQ.",
                error_reason,
            )
            confirmed = self.dlq_publisher.publish_to_dlq(
                [msg],
                reason=error_reason,
                retry_count=next_count,
            )
            if confirmed and self.metrics:
                self.metrics.increment_dlq_quarantined(1, flush=True)

        if confirmed:
            self.commit_message_offset(msg)
            return True

        logger.error(
            "Failed to publish retry escalation for message at %s:%d:%d; offset NOT committed.",
            topic,
            msg.partition(),
            msg.offset(),
        )
        return False

    def poll_and_process(self, timeout: float = 0.5) -> int:
        """Polls a single message from retry topics and processes it. Returns count processed (0 or 1)."""
        self._ensure_subscribed()
        msg = self.consumer.poll(timeout)
        if msg is None:
            return 0
        if msg.error():
            logger.debug("Retry topic poll error: %s", msg.error())
            return 0

        success = self.process_single_message(msg)
        return 1 if success else 0

    def run(self, max_iterations: Optional[int] = None) -> int:
        processed_total = 0
        iterations = 0
        while self.running:
            if max_iterations is not None and iterations >= max_iterations:
                break
            iterations += 1
            count = self.poll_and_process(timeout=0.2)
            processed_total += count
        return processed_total

    def stop(self) -> None:
        self.running = False

    def close(self) -> None:
        self.stop()
        if self._owns_http_client:
            try:
                self.http_client.close()
            except Exception:
                pass
        if self._consumer is not None:
            try:
                self._consumer.close()
            except Exception:
                pass
            self._consumer = None


__all__ = ["RetryTopicConsumer"]
