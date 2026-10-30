import logging
import os
import random
import signal
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import httpx
from middleware.lightweight_broker import (
    BrokerException,
    LightweightConsumer as Consumer,
    LightweightMessage as Message,
    LightweightProducer as Producer,
    TopicPartition,
)

_BrokerExceptionType: Tuple[type, ...] = (BrokerException,)

from config import (
    BASE_BACKOFF_SECONDS,
    BATCH_LINGER_MS,
    BATCH_SIZE,
    BROKER_CONSUMER_GROUP,
    BROKER_DB_PATH,
    BROKER_DLQ_TOPIC,
    BROKER_PARTITIONS,
    BROKER_POISON_TOPIC,
    BROKER_PRIORITY_TOPIC,
    BROKER_RETRY_1M_TOPIC,
    BROKER_RETRY_10M_TOPIC,
    BROKER_TOPIC,
    DEAD_LETTER_FILE,
    DLQ_BACKEND,
    DRY_RUN_GRAYLOG_MOCK,
    GELF_HOST,
    GRAYLOG_GELF_URL,
    MAX_BACKOFF_SECONDS,
    MAX_BATCHES_PER_SECOND,
    MAX_DELIVERY_RETRIES,
    MAX_LOGS_PER_SEC,
    METRICS_DB_PATH,
    POLL_TIMEOUT,
    SETTINGS,
    STANDARD_RESERVED_SHARE,
)
from metrics_store import SharedMetricsStore, WorkerMetricsUpdater
from middleware.batch_poller import BrokerBatchPoller
from middleware.delivery_client import GraylogDeliveryClient
from middleware.dlq_publisher import (
    BrokerDeadLetterPublisher,
    DeadLetterSink,
)
from middleware.dlq_store import JsonlDeadLetterStore
from middleware.gelf_transformer import GelfTransformer, transform_to_gelf
from middleware.logging_utils import configure_logging
from middleware.models import BatchResult, DeliveryOutcome, RetryPolicy
from middleware.offset_committer import ExplicitOffsetCommitter
from middleware.rate_limiter import TokenBucketRateLimiter
from middleware.telemetry import (
    PIPELINE_REGISTRY,
    record_dlq_published,
    record_dlq_replayed,
    record_logs_forwarded,
    record_poison_message,
    sync_prometheus_metrics,
)
from prometheus_client import start_http_server

logger = configure_logging("soar.consumer_worker", level=logging.INFO)


class GraylogConsumerWorker:
    """
    Orchestrates the Broker -> Graylog SIEM shipping pipeline by composing:
    - `BrokerBatchPoller`: micro-batch accumulation with linger window
    - `TokenBucketRateLimiter`: exact log-unit backpressure throttling (`MAX_LOGS_PER_SEC`)
    - `GelfTransformer`: GELF 1.1 conversion with deterministic `_event_id = "{partition}:{offset}"`
    - `GraylogDeliveryClient`: HTTP POST delivery with Exponential Backoff + Jitter and pause-based liveness polling
    - `ExplicitOffsetCommitter`: synchronous per-partition `max_offset + 1` commits after 2xx or DLQ and cooperative-sticky rebalance tracking
    - `JsonlDeadLetterStore`: atomic JSONL Dead-Letter Queue persistence and auto-replay
    """

    def __init__(
        self,
        metrics_store: Optional[SharedMetricsStore] = None,
        db_path: Optional[str] = None,
        dead_letter_file: Optional[str] = None,
        max_delivery_retries: Optional[int] = None,
        base_backoff_seconds: Optional[float] = None,
        max_backoff_seconds: Optional[float] = None,
        max_batches_per_second: Optional[float] = None,
        max_logs_per_sec: Optional[float] = None,
        batch_size: Optional[int] = None,
        batch_linger_ms: Optional[int] = None,
        poll_timeout: Optional[float] = None,
        batch_poller: Optional[BrokerBatchPoller] = None,
        gelf_transformer: Optional[GelfTransformer] = None,
        delivery_client: Optional[GraylogDeliveryClient] = None,
        offset_committer: Optional[ExplicitOffsetCommitter] = None,
        dlq_store: Optional[JsonlDeadLetterStore] = None,
        dlq_backend: Optional[str] = None,
        dlq_sink: Optional[DeadLetterSink] = None,
        consumer: Optional[Consumer] = None,
        http_client: Optional[httpx.Client] = None,
        metrics_port: Optional[int] = None,
        enable_metrics_server: bool = True,
        broker_db_path: Optional[str] = None,
    ) -> None:
        self.running = True
        self._stop_after_current_batch = False
        self._shutdown_requested = False
        self._last_signal: Optional[int] = None
        self._prev_sigint_handler: Any = None
        self._prev_sigterm_handler: Any = None
        self._signals_installed = False
        self.broker_db_path: str = str(
            broker_db_path
            or getattr(SETTINGS, "broker_db_path", BROKER_DB_PATH)
        )
        self.metrics_port: int = int(
            metrics_port
            if metrics_port is not None
            else getattr(SETTINGS, "consumer_metrics_port", 9100)
        )
        self.enable_metrics_server: bool = enable_metrics_server
        self._metrics_server: Optional[Any] = None
        self._metrics_thread: Optional[threading.Thread] = None
        self._owns_metrics_store = metrics_store is None
        self.metrics: SharedMetricsStore = (
            metrics_store
            if metrics_store is not None
            else WorkerMetricsUpdater(db_path or METRICS_DB_PATH)
        )
        self._dead_letter_file = dead_letter_file
        self._max_delivery_retries = max_delivery_retries
        self._base_backoff_seconds = base_backoff_seconds
        self._max_backoff_seconds = max_backoff_seconds

        self.batch_size: int = int(batch_size if batch_size is not None else BATCH_SIZE)
        self.batch_linger_ms: int = int(
            batch_linger_ms if batch_linger_ms is not None else BATCH_LINGER_MS
        )
        self.poll_timeout: float = float(
            poll_timeout if poll_timeout is not None else POLL_TIMEOUT
        )

        if max_logs_per_sec is not None:
            effective_logs_per_sec = float(max_logs_per_sec)
        elif max_batches_per_second is not None:
            effective_logs_per_sec = float(max_batches_per_second) * self.batch_size
        else:
            effective_logs_per_sec = float(MAX_LOGS_PER_SEC)

        bucket_capacity = max(
            float(self.batch_size),
            min(effective_logs_per_sec, float(self.batch_size * 2)),
        )
        self.rate_limiter = TokenBucketRateLimiter(
            rate_per_sec=effective_logs_per_sec,
            capacity=bucket_capacity,
            initial_tokens=float(self.batch_size),
            clock_fn=lambda: time.monotonic(),
            sleep_fn=lambda s: time.sleep(s),
        )
        self.batch_poller: BrokerBatchPoller = batch_poller or BrokerBatchPoller(
            batch_size=self.batch_size,
            batch_linger_ms=self.batch_linger_ms,
            poll_timeout=self.poll_timeout,
            priority_topic=BROKER_PRIORITY_TOPIC,
            standard_topic=BROKER_TOPIC,
            standard_reserved_share=STANDARD_RESERVED_SHARE,
            clock_fn=lambda: time.monotonic(),
        )
        self.gelf_transformer: GelfTransformer = gelf_transformer or GelfTransformer(
            host=GELF_HOST
        )
        self.delivery_client: GraylogDeliveryClient = (
            delivery_client
            or GraylogDeliveryClient(
                sleep_fn=lambda s: time.sleep(s),
                jitter_fn=lambda a, b: random.uniform(a, b),
                split_post=getattr(SETTINGS, "gelf_split_post", False),
            )
        )
        self.offset_committer: ExplicitOffsetCommitter = (
            offset_committer or ExplicitOffsetCommitter(default_topic=BROKER_TOPIC)
        )
        self.dlq_backend: str = (
            dlq_backend
            if dlq_backend is not None
            else (
                os.environ.get("DLQ_BACKEND")
                if os.environ.get("DLQ_BACKEND") is not None
                else (
                    "file"
                    if (
                        dead_letter_file is not None
                        or DEAD_LETTER_FILE != SETTINGS.dead_letter_file
                        or dlq_store is not None
                    )
                    else SETTINGS.dlq_backend
                )
            )
        ).lower()

        if dlq_sink is not None:
            self.dlq_sink: DeadLetterSink = dlq_sink
        elif self.dlq_backend == "file":
            self.dlq_sink = dlq_store or JsonlDeadLetterStore()
        else:
            self.dlq_sink = BrokerDeadLetterPublisher(
                dlq_topic=BROKER_DLQ_TOPIC,
                poison_topic=BROKER_POISON_TOPIC,
                retry_1m_topic=BROKER_RETRY_1M_TOPIC,
                retry_10m_topic=BROKER_RETRY_10M_TOPIC,
                broker_db_path=self.broker_db_path,
                num_partitions=BROKER_PARTITIONS,
            )
        self.dlq_store: Any = self.dlq_sink

        self.consumer: Optional[Consumer] = consumer
        self.http_client = (
            http_client
            if http_client is not None
            else httpx.Client(
                timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0),
                limits=httpx.Limits(max_keepalive_connections=30, max_connections=50),
                headers={"Content-Type": "application/json"},
            )
        )
        self._closed = False

    @property
    def dead_letter_file(self) -> str:
        return (
            self._dead_letter_file
            if self._dead_letter_file is not None
            else DEAD_LETTER_FILE
        )

    @dead_letter_file.setter
    def dead_letter_file(self, value: Optional[str]) -> None:
        self._dead_letter_file = value

    def __enter__(self) -> "GraylogConsumerWorker":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def install_signal_handlers(self) -> None:
        """Registers SIGINT and SIGTERM handlers for graceful shutdown when on the main thread."""
        if threading.current_thread() is not threading.main_thread():
            return
        try:
            self._prev_sigint_handler = signal.getsignal(signal.SIGINT)
            self._prev_sigterm_handler = signal.getsignal(signal.SIGTERM)
            signal.signal(signal.SIGINT, self.stop)
            signal.signal(signal.SIGTERM, self.stop)
            self._signals_installed = True
        except (ValueError, OSError):
            pass

    def _restore_signal_handlers(self) -> None:
        if not self._signals_installed:
            return
        try:
            if self._prev_sigint_handler is not None:
                signal.signal(signal.SIGINT, self._prev_sigint_handler)
            if self._prev_sigterm_handler is not None:
                signal.signal(signal.SIGTERM, self._prev_sigterm_handler)
        except (ValueError, OSError):
            pass
        finally:
            self._signals_installed = False

    def start_metrics_server(self, port: Optional[int] = None) -> bool:
        """Starts a daemon thread HTTP server exposing Prometheus metrics on port (default 9100)."""
        if self._metrics_server is not None:
            return True
        effective_port = port if port is not None else self.metrics_port
        try:
            sync_prometheus_metrics(
                self.metrics.read_snapshot(),
                rate_limit=self.rate_limiter.rate_per_sec,
                max_logs_per_sec=self.rate_limiter.rate_per_sec,
            )
            self._metrics_server, self._metrics_thread = start_http_server(
                port=effective_port,
                addr="0.0.0.0",
                registry=PIPELINE_REGISTRY,
            )
            logger.info(
                "Consumer worker Prometheus metrics server started on port %d",
                effective_port,
            )
            return True
        except Exception as exc:
            logger.warning(
                "Could not start consumer metrics server on port %d: %s",
                effective_port,
                exc,
            )
            self._metrics_server = None
            self._metrics_thread = None
            return False

    def stop_metrics_server(self) -> None:
        """Stops the Prometheus metrics server daemon cleanly."""
        if self._metrics_server is not None:
            try:
                self._metrics_server.shutdown()
                self._metrics_server.server_close()
            except Exception as exc:
                logger.warning("Error stopping consumer metrics server: %s", exc)
            finally:
                self._metrics_server = None
                self._metrics_thread = None

    def close(self) -> None:
        """Deterministically releases HTTP client, broker consumer, metrics server, and SQLite connections."""
        if self._closed:
            return
        self._closed = True
        self.running = False
        self.stop_metrics_server()
        self.offset_committer.clear_in_flight_batch()
        logger.info("Closing HTTP client, broker consumer, and metrics store...")
        try:
            self.http_client.close()
        except Exception as exc:
            logger.warning("Error closing HTTP client: %s", exc)

        if self.consumer is not None:
            try:
                self.consumer.close()
            except Exception as exc:
                logger.warning("Error closing broker consumer: %s", exc)
            finally:
                self.consumer = None

        if hasattr(self.dlq_sink, "close"):
            try:
                self.dlq_sink.close()
            except Exception as exc:
                logger.warning("Error closing DLQ sink: %s", exc)

        try:
            if self._owns_metrics_store:
                self.metrics.close()
            else:
                self.metrics.flush()
        except Exception as exc:
            logger.warning("Error closing metrics store: %s", exc)

        logger.info("Graylog Consumer Worker terminated cleanly.")

    def _setup_consumer(self) -> Consumer:
        consumer_conf = {
            "group.id": BROKER_CONSUMER_GROUP,
            "client.id": "soar-graylog-consumer-worker",
            "partition.assignment.strategy": "cooperative-sticky",
            "enable.auto.commit": False,
            "auto.offset.reset": "earliest",
            "session.timeout.ms": 30000,
            "heartbeat.interval.ms": 3000,
            "max.poll.interval.ms": 300000,
            "fetch.min.bytes": 1,
            "broker.db.path": self.broker_db_path,
            "num_partitions": BROKER_PARTITIONS,
        }
        try:
            consumer = Consumer(
                consumer_conf,
                db_path=self.broker_db_path,
                num_partitions=BROKER_PARTITIONS,
            )
        except TypeError:
            consumer = Consumer(consumer_conf)
        self.batch_poller.subscribe(
            consumer,
            on_assign=self.offset_committer.on_assign,
            on_revoke=self.offset_committer.on_revoke,
            on_lost=self.offset_committer.on_lost,
        )
        logger.info(
            "Subscribed to broker topics ['%s', '%s'] (group='%s', strategy='cooperative-sticky', batch_size=%d, max_logs_per_sec=%.1f, batch_linger_ms=%d, dry_run=%s)",
            BROKER_PRIORITY_TOPIC,
            BROKER_TOPIC,
            BROKER_CONSUMER_GROUP,
            self.batch_size,
            self.rate_limiter.rate_per_sec,
            self.batch_linger_ms,
            DRY_RUN_GRAYLOG_MOCK,
        )
        return consumer

    def stop(self, signum: Optional[int] = None, _frame: Any = None) -> None:
        self._shutdown_requested = True
        self._last_signal = signum if isinstance(signum, int) else None
        self.running = False
        sig_name = (
            signal.Signals(signum).name
            if isinstance(signum, int) and signum in signal.Signals._value2member_map_
            else str(signum or "STOP")
        )
        logger.info(
            "Shutdown signal (%s) received. Stopping Graylog Consumer Worker...",
            sig_name,
        )

    def _get_assigned_partitions(self) -> List[TopicPartition]:
        committer_partitions = self.offset_committer.get_assigned_topic_partitions()
        if committer_partitions:
            return committer_partitions
        if self.consumer is not None:
            assignment_fn = getattr(self.consumer, "assignment", None)
            if callable(assignment_fn):
                raw_assignment = assignment_fn()
                if isinstance(raw_assignment, (list, tuple, set)):
                    return list(raw_assignment)
        return []

    @staticmethod
    def _filter_valid_messages(raw_messages: List[Optional[Message]]) -> List[Message]:
        return BrokerBatchPoller.filter_valid_messages(raw_messages)

    def _poll_batch(self) -> List[Message]:
        assert self.consumer is not None
        self.batch_poller.batch_size = self.batch_size
        self.batch_poller.batch_linger_ms = self.batch_linger_ms
        self.batch_poller.poll_timeout = self.poll_timeout
        messages, stop_after_batch = self.batch_poller.poll_batch(
            consumer=self.consumer,
            is_running_fn=lambda: self.running,
        )
        if stop_after_batch and not self._shutdown_requested:
            self._stop_after_current_batch = True
            self.running = True
        return messages

    def _commit_batch_offsets(self, messages: List[Message]) -> List[TopicPartition]:
        assert self.consumer is not None
        self.offset_committer.default_topic = BROKER_TOPIC
        return self.offset_committer.commit_batch_offsets(self.consumer, messages)

    def _build_gelf_batch(self, messages: List[Message]) -> List[Dict[str, Any]]:
        self.gelf_transformer.host = GELF_HOST
        return self.gelf_transformer.transform_batch(messages)

    def _write_dead_letter_batch(
        self,
        gelf_batch: List[Dict[str, Any]],
        messages: Optional[List[Any]] = None,
        reason: str = "Retries exhausted",
    ) -> bool:
        if hasattr(self.dlq_sink, "write_dead_letter"):
            return self.dlq_sink.write_dead_letter(
                messages=messages,
                gelf_batch=gelf_batch,
                reason=reason,
                dlq_path=self.dead_letter_file,
            )
        self.dlq_store.write_batch(self.dead_letter_file, gelf_batch)
        return True

    def _rewrite_dead_letter_remaining(
        self, dlq_path: str, remaining_records: List[Dict[str, Any]]
    ) -> None:
        self.dlq_store.rewrite_remaining(dlq_path, remaining_records)

    def _replay_dead_letter_file(self) -> int:
        if not hasattr(self.dlq_store, "replay") or not callable(self.dlq_store.replay):
            return 0

        def _on_chunk_replayed(count: int, **kwargs: Any) -> None:
            self.metrics.reconcile_dlq_replay(count, **kwargs)
            record_dlq_replayed(count)

        return self.dlq_store.replay(
            dlq_path=self.dead_letter_file,
            batch_size=self.batch_size,
            acquire_tokens_fn=self.rate_limiter.acquire,
            http_client=self.http_client,
            gelf_url=GRAYLOG_GELF_URL,
            dry_run=DRY_RUN_GRAYLOG_MOCK,
            is_running_fn=lambda: self.running,
            on_chunk_replayed=_on_chunk_replayed,
        )

    def _build_retry_policy(self) -> RetryPolicy:
        max_retries = (
            self._max_delivery_retries
            if self._max_delivery_retries is not None
            else MAX_DELIVERY_RETRIES
        )
        base_backoff = (
            self._base_backoff_seconds
            if self._base_backoff_seconds is not None
            else BASE_BACKOFF_SECONDS
        )
        max_backoff = (
            self._max_backoff_seconds
            if self._max_backoff_seconds is not None
            else MAX_BACKOFF_SECONDS
        )
        return RetryPolicy(
            max_retries=max_retries,
            base_backoff_seconds=base_backoff,
            max_backoff_seconds=max_backoff,
        )

    def _deliver_batch_with_backoff(
        self,
        gelf_batch: List[Dict[str, Any]],
        batch_id: Optional[str] = None,
        messages: Optional[List[Message]] = None,
    ) -> DeliveryOutcome:
        def _on_dead_letter(batch: List[Dict[str, Any]], **kwargs: Any) -> bool:
            msgs = kwargs.get("messages") or messages
            reason = kwargs.get("reason", "Retries exhausted")
            return self._write_dead_letter_batch(batch, messages=msgs, reason=reason)

        return self.delivery_client.deliver_batch(
            gelf_batch=gelf_batch,
            http_client=self.http_client,
            gelf_url=GRAYLOG_GELF_URL,
            retry_policy=self._build_retry_policy(),
            dry_run=DRY_RUN_GRAYLOG_MOCK,
            is_running_fn=lambda: self.running,
            on_dead_letter=_on_dead_letter,
            batch_id=batch_id,
            consumer=self.consumer,
            get_assigned_partitions_fn=self._get_assigned_partitions,
            should_abort_fn=lambda: self.offset_committer.in_flight_aborted,
            messages=messages,
        )

    def process_single_batch(self, messages: List[Message]) -> BatchResult:
        """
        Processes a single polled micro-batch end-to-end:
        1. Checks for unparseable poison messages: publishes to poison topic and commits past them
        2. Registers unconfirmed in-flight batch state in `ExplicitOffsetCommitter`
        3. Acquires `len(messages)` tokens from `TokenBucketRateLimiter`
        4. Transforms messages to GELF 1.1 with `_event_id`
        5. Delivers batch to Graylog with pause-based backoff or DLQ fallback
        6. Marks batch confirmed and synchronously commits exact per-partition `max_offset + 1` offsets (unless ABORTED)
        7. Updates cross-process SQLite metrics and triggers DLQ auto-replay on healthy delivery
        """
        # Poison message detection
        valid_messages: List[Message] = []
        poison_messages: List[Tuple[Message, str]] = []
        for msg in messages:
            is_poison, reason = self.gelf_transformer.is_poison(msg)
            if is_poison:
                poison_messages.append((msg, reason or "Malformed message"))
            else:
                valid_messages.append(msg)

        if poison_messages:
            for p_msg, p_reason in poison_messages:
                p_topic = (
                    p_msg.topic()
                    if hasattr(p_msg, "topic") and callable(p_msg.topic)
                    else BROKER_TOPIC
                )
                p_part = (
                    int(p_msg.partition())
                    if hasattr(p_msg, "partition") and callable(p_msg.partition)
                    else 0
                )
                p_off = (
                    int(p_msg.offset())
                    if hasattr(p_msg, "offset") and callable(p_msg.offset)
                    else 0
                )
                logger.error(
                    "Poison message at %s:%d:%d (%s). Publishing to poison topic and committing past.",
                    p_topic,
                    p_part,
                    p_off,
                    p_reason,
                )
                if hasattr(self.dlq_sink, "publish_poison"):
                    self.dlq_sink.publish_poison(p_msg, reason=p_reason)
                else:
                    self.dlq_sink.write_dead_letter(
                        messages=[p_msg],
                        reason=f"Poison: {p_reason}",
                        dlq_path=self.dead_letter_file,
                    )

                if self.consumer is not None:
                    try:
                        self.consumer.commit(
                            offsets=[TopicPartition(p_topic, p_part, p_off + 1)],
                            asynchronous=False,
                        )
                    except Exception as exc:
                        logger.warning("Failed to commit offset for poison message: %s", exc)

                self.metrics.increment_poison_messages(1, flush=True)
                record_poison_message(1)

            if not valid_messages:
                return BatchResult(
                    batch_id=uuid.uuid4().hex[:8],
                    outcome=DeliveryOutcome.DELIVERED,
                    message_count=len(messages),
                )
            messages = valid_messages

        batch_len = len(messages)
        batch_id = uuid.uuid4().hex[:8]
        self.offset_committer.default_topic = BROKER_TOPIC
        in_flight = self.offset_committer.begin_batch(batch_id, messages)
        offset_ranges = in_flight.partition_offset_ranges
        offset_range_str = self.offset_committer.format_offset_ranges(offset_ranges)
        primary_partition = next(iter(offset_ranges.keys()), None)

        self.rate_limiter.acquire(float(batch_len))
        gelf_batch = self._build_gelf_batch(messages)
        outcome = self._deliver_batch_with_backoff(
            gelf_batch, batch_id=batch_id, messages=messages
        )

        honeytokens = sum(
            1 for item in gelf_batch if item.get("_honeytoken_alert") is True
        )

        if outcome is DeliveryOutcome.ABORTED:
            self.offset_committer.clear_in_flight_batch()
            logger.info(
                "Stopping before batch delivery completed; offsets remain uncommitted for replay "
                "(batch_id=%s, offset_range=%s).",
                batch_id,
                offset_range_str,
                extra={
                    "batch_id": batch_id,
                    "partition": primary_partition,
                    "offset_range": offset_range_str,
                    "message_count": batch_len,
                },
            )
            return BatchResult(
                batch_id=batch_id,
                outcome=outcome,
                message_count=batch_len,
                honeytoken_count=honeytokens,
                partition_offset_ranges=offset_ranges,
            )

        self.offset_committer.mark_batch_confirmed(messages, batch_id=batch_id)

        try:
            self._commit_batch_offsets(messages)
        except _BrokerExceptionType as exc:
            self.offset_committer.clear_in_flight_batch()
            if self.offset_committer.is_rebalance_error(exc):
                logger.warning(
                    "Offset commit failed after confirmed delivery due to consumer group rebalance "
                    "(expected at-least-once duplicate; downstream deduplicates via _event_id, "
                    "batch_id=%s, offset_range=%s): %s",
                    batch_id,
                    offset_range_str,
                    exc,
                    extra={
                        "batch_id": batch_id,
                        "partition": primary_partition,
                        "offset_range": offset_range_str,
                        "message_count": batch_len,
                    },
                )
            else:
                logger.error(
                    "Synchronous offset commit warning (will retry on next poll, batch_id=%s, offset_range=%s): %s",
                    batch_id,
                    offset_range_str,
                    exc,
                    extra={
                        "batch_id": batch_id,
                        "partition": primary_partition,
                        "offset_range": offset_range_str,
                        "message_count": batch_len,
                    },
                )
            return BatchResult(
                batch_id=batch_id,
                outcome=outcome,
                message_count=batch_len,
                honeytoken_count=honeytokens,
                partition_offset_ranges=offset_ranges,
                error_reason=str(exc),
            )

        priority_topic = getattr(
            self.batch_poller, "priority_topic", BROKER_PRIORITY_TOPIC
        )
        priority_count = sum(
            1
            for m in messages
            if (getattr(m, "topic", lambda: None)() or BROKER_TOPIC)
            == priority_topic
        )
        standard_count = batch_len - priority_count

        if outcome is DeliveryOutcome.DELIVERED:
            self.metrics.increment_forwarded(
                batch_len,
                flush=True,
                priority_count=priority_count,
                standard_count=standard_count,
            )
            record_logs_forwarded(batch_len)
            if honeytokens > 0:
                logger.warning(
                    "Shipped & committed batch of %d GELF logs (includes %d HONEYTOKEN_ACCESS alert!).",
                    batch_len,
                    honeytokens,
                    extra={"batch_id": batch_id, "message_count": batch_len},
                )
            else:
                logger.info(
                    "Shipped & committed batch of %d GELF logs to Graylog.",
                    batch_len,
                    extra={"batch_id": batch_id, "message_count": batch_len},
                )
            self._replay_dead_letter_file()
        elif outcome is DeliveryOutcome.DEAD_LETTERED:
            self.metrics.increment_dlq_quarantined(batch_len, flush=True)
            record_dlq_published(batch_len)
            logger.error(
                "Dead-lettered & committed offset for %d undeliverable logs (dlq_quarantined_logs incremented).",
                batch_len,
                extra={"batch_id": batch_id, "message_count": batch_len},
            )

        sync_prometheus_metrics(
            self.metrics.read_snapshot(),
            rate_limit=self.rate_limiter.rate_per_sec,
            max_logs_per_sec=self.rate_limiter.rate_per_sec,
        )

        return BatchResult(
            batch_id=batch_id,
            outcome=outcome,
            message_count=batch_len,
            honeytoken_count=honeytokens,
            partition_offset_ranges=offset_ranges,
        )

    def run(self) -> None:
        self.install_signal_handlers()
        if self.enable_metrics_server:
            self.start_metrics_server()
        if self.consumer is None:
            self.consumer = self._setup_consumer()
        try:
            while self.running:
                messages = self._poll_batch()
                if not messages:
                    if not self.running:
                        break
                    self._replay_dead_letter_file()
                    continue

                result = self.process_single_batch(messages)
                if result.outcome is DeliveryOutcome.ABORTED:
                    if not self.running:
                        break
                    continue

                if self._stop_after_current_batch:
                    self.running = False
        finally:
            self._restore_signal_handlers()
            self.close()


__all__ = [
    "BatchResult",
    "DeliveryOutcome",
    "GraylogConsumerWorker",
    "TokenBucketRateLimiter",
    "transform_to_gelf",
]


if __name__ == "__main__":
    with GraylogConsumerWorker() as worker:
        worker.install_signal_handlers()
        worker.run()

