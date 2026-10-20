import asyncio
import copy
import json
import logging
import math
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from middleware.lightweight_broker import (
    OFFSET_INVALID,
    BrokerError,
    BrokerException,
    ConfigResource,
    ConsumerGroupTopicPartitions,
    LightweightAdminClient as AdminClient,
    LightweightConsumer as Consumer,
    LightweightMessage as Message,
    LightweightProducer as Producer,
    NewTopic,
    ResourceType,
    SQLiteBrokerStorage,
    TopicPartition,
)
from fastapi import APIRouter, Body, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from config import (
    BROKER_CONSUMER_GROUP,
    BROKER_DB_PATH,
    BROKER_DLQ_TOPIC,
    BROKER_PARTITIONS,
    BROKER_POISON_TOPIC,
    BROKER_PRIORITY_TOPIC,
    BROKER_RETENTION_MS,
    BROKER_RETRY_1M_TOPIC,
    BROKER_RETRY_10M_TOPIC,
    BROKER_TOPIC,
    DLQ_BACKEND,
    INGESTOR_HOST,
    INGESTOR_PORT,
    MAX_BROKER_BUFFER_MESSAGES,
    MAX_LOGS_PER_SEC,
    METRICS_DB_PATH,
    OTEL_ENABLED,
    PRIORITY_EVENT_TYPES,
    PRIORITY_MAX_SEVERITY,
    PRODUCER_BUFFER_RETRIES,
    PRODUCER_BUFFER_RETRY_SLEEP,
    REDACTION_PATTERNS,
    SETTINGS,
)
from metrics_store import SharedMetricsStore
from middleware.auth import require_admin_auth, require_ingest_auth
from middleware.errors import register_problem_handlers
from middleware.ingest_rate_limiter import (
    check_client_rate_limit,
    ingest_rate_limiter,
)
from middleware.logging_utils import configure_logging
from middleware.models import (
    BrokerLagSnapshot,
    PartitionLagInfo,
)
from middleware.redaction import redact_sensitive_data
from middleware.telemetry import (
    CONTENT_TYPE_LATEST,
    PIPELINE_REGISTRY,
    generate_latest,
    inject_traceparent_to_broker_headers,
    record_logs_received,
    reset_prometheus_metrics,
    sync_prometheus_metrics,
)

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logger = configure_logging("soar.ingestor", level=logging.INFO)


# ---------------------------------------------------------------------------
# Standard JSON Log Schema (Pydantic v2 Validation)
# ---------------------------------------------------------------------------
class SecurityLogEvent(BaseModel):
    """
    Standardized security event schema for Main Flask API & ESP32 IoT nodes.
    Enforces millisecond-precision Unix epoch timestamps and strict field types.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(
        default="1.0",
        description="Event schema version (e.g. '1.0'). Missing values default to '1.0'. Unknown major versions are rejected.",
    )
    timestamp: Union[float, int, str] = Field(
        default_factory=lambda: round(time.time(), 3),
        description="Event timestamp as Unix epoch float (seconds.ms) or ISO-8601 string.",
    )
    client_ip: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Source IP address of the actor/client (used as broker partition key).",
    )
    event_type: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Security scenario event identifier (e.g., HONEYTOKEN_ACCESS, PORT_SCAN, BRUTE_FORCE, IDOR_ATTEMPT, IOT_CONTROL).",
    )
    target_resource: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Target URI, endpoint, hardware pin, or resource accessed.",
    )
    status_code: int = Field(
        ...,
        ge=0,
        le=999,
        description="HTTP status code (e.g., 200, 401, 403) or protocol status code.",
    )
    severity: int = Field(
        ...,
        ge=0,
        le=7,
        description="Syslog severity level 0 (Emergency) through 7 (Debug). E.g., 1=Alert, 4=Warning, 6=Info.",
    )
    raw_payload: Union[Dict[str, Any], str] = Field(
        ...,
        description="Original contextual event data, request parameters, or raw log line.",
    )

    @field_validator("schema_version", mode="before")
    @classmethod
    def validate_schema_version(cls, value: Any) -> str:
        if value is None:
            return "1.0"
        if not isinstance(value, str):
            raise ValueError(
                f"schema_version must be a string, got {type(value).__name__}"
            )
        cleaned = value.strip()
        if not cleaned:
            return "1.0"
        parts = cleaned.split(".")
        if not parts or parts[0] != "1":
            raise ValueError(
                f"Unsupported schema major version '{parts[0]}' in '{cleaned}'. Only major version 1 is supported."
            )
        return cleaned

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp_to_epoch_ms(cls, value: Any) -> float:
        if value is None:
            return round(time.time(), 3)

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            ts = float(value)
            # If caller supplied epoch milliseconds (e.g., 1760843980123), convert to seconds
            if ts > 1e11:
                ts = ts / 1000.0
            return round(ts, 3)

        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return round(time.time(), 3)
            # Check if numeric string first
            try:
                ts = float(raw)
                if ts > 1e11:
                    ts = ts / 1000.0
                return round(ts, 3)
            except ValueError:
                pass

            # Parse ISO-8601 string (supporting trailing 'Z' and timezone offsets)
            iso_candidate = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
            try:
                dt = datetime.fromisoformat(iso_candidate)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return round(dt.timestamp(), 3)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid timestamp '{value}'. Expected Unix epoch float or ISO-8601 string."
                ) from exc

        raise ValueError(f"Unsupported timestamp type: {type(value).__name__}")

    @field_validator("client_ip")
    @classmethod
    def sanitize_client_ip(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("client_ip must not be empty.")
        return cleaned

    @field_validator("event_type")
    @classmethod
    def normalize_event_type(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if not cleaned:
            raise ValueError("event_type must not be empty.")
        return cleaned

    @field_validator("target_resource")
    @classmethod
    def sanitize_target_resource(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("target_resource must not be empty.")
        return cleaned


class BatchIngestRequest(BaseModel):
    """Wrapper schema when submitting a batch via {'logs': [...]}."""

    logs: List[SecurityLogEvent] = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="List of standardized security log events.",
    )


# ---------------------------------------------------------------------------
# Priority Event Routing Logic
# ---------------------------------------------------------------------------
def is_priority_event(
    event: Union[SecurityLogEvent, Dict[str, Any]],
    priority_event_types: Optional[List[str]] = None,
    priority_max_severity: Optional[int] = None,
    priority_types: Optional[List[str]] = None,
    max_severity: Optional[int] = None,
) -> bool:
    """
    Evaluates whether an event qualifies for the high-priority queue:
    1. Event type matches configured priority types (default: HONEYTOKEN_ACCESS).
    2. Syslog severity <= priority_max_severity (default: <= 2: Emergency, Alert, Critical).
    """
    types_arg = priority_event_types if priority_event_types is not None else priority_types
    types = (
        types_arg
        if types_arg is not None
        else PRIORITY_EVENT_TYPES
    )
    max_sev_arg = priority_max_severity if priority_max_severity is not None else max_severity
    max_sev = (
        max_sev_arg
        if max_sev_arg is not None
        else PRIORITY_MAX_SEVERITY
    )
    if isinstance(event, dict):
        raw_type = event.get("event_type")
        raw_sev = event.get("severity")
    else:
        raw_type = getattr(event, "event_type", None)
        raw_sev = getattr(event, "severity", None)

    ev_type = (str(raw_type) if raw_type is not None else "").strip().upper()
    if ev_type and ev_type in [t.strip().upper() for t in types]:
        return True
    try:
        if raw_sev is not None:
            sev = int(raw_sev)
            if sev <= int(max_sev):
                return True
    except (TypeError, ValueError):
        pass
    return False


def route_event_topic(
    event: Union[SecurityLogEvent, Dict[str, Any]],
    priority_topic: str = BROKER_PRIORITY_TOPIC,
    standard_topic: str = BROKER_TOPIC,
    priority_event_types: Optional[List[str]] = None,
    priority_max_severity: Optional[int] = None,
    priority_types: Optional[List[str]] = None,
    max_severity: Optional[int] = None,
) -> str:
    """
    Routes high-priority security alerts (HONEYTOKEN_ACCESS, severity <= 2) to the
    priority topic and standard events to the standard topic, preserving client_ip
    partition keying within each lane.
    """
    if is_priority_event(
        event,
        priority_event_types=priority_event_types,
        priority_max_severity=priority_max_severity,
        priority_types=priority_types,
        max_severity=max_severity,
    ):
        return priority_topic
    return standard_topic


# ---------------------------------------------------------------------------
# Non-Blocking WAL Broker Producer & Native Offset Lag Inspector
# ---------------------------------------------------------------------------
class WalLogBufferingMiddleware:
    """
    Manages the non-blocking WAL broker Producer, topic initialization,
    background delivery report polling loop, and native broker watermark/offset
    inspection for real-time lag calculation.
    """

    def __init__(
        self,
        metrics_store: SharedMetricsStore,
        max_buffer_retries: int = PRODUCER_BUFFER_RETRIES,
        buffer_retry_sleep: float = PRODUCER_BUFFER_RETRY_SLEEP,
        lag_cache_ttl: float = 1.0,
    ) -> None:
        self.metrics_store = metrics_store
        self.max_buffer_retries = max_buffer_retries
        self.buffer_retry_sleep = buffer_retry_sleep
        self.lag_cache_ttl = lag_cache_ttl
        self.producer: Optional[Producer] = None
        self.admin_client: Optional[AdminClient] = None
        self._watermark_consumer: Optional[Consumer] = None
        self._watermark_lock = threading.Lock()
        self._lag_cache_lock = threading.Lock()
        self._lag_cache_value: Optional[Dict[str, Any]] = None
        self._lag_cache_timestamp: float = 0.0
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._acked_batch_pending = 0
        self._acked_batch_lock = threading.Lock()
        self.reset_broker_baseline = 0
        self.reset_committed_baseline = 0

    def __enter__(self) -> "WalLogBufferingMiddleware":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()

    def start(self) -> None:
        logger.info(
            "Initializing Lightweight WAL Broker at %s (topic=%s, partitions=%d)",
            BROKER_DB_PATH,
            BROKER_TOPIC,
            BROKER_PARTITIONS,
        )
        admin_conf = {
            "broker.db.path": BROKER_DB_PATH,
        }
        self.admin_client = AdminClient(admin_conf, db_path=BROKER_DB_PATH)
        self._ensure_topic_exists()

        # Zero-loss Producer configuration
        producer_conf = {
            "client.id": "soar-http-ingestor-producer",
            "acks": "all",
            "enable.idempotence": True,
            "retries": 5,
            "max.in.flight.requests.per.connection": 5,
            "linger.ms": 10,
            "batch.size": 65536,
            "queue.buffering.max.messages": MAX_BROKER_BUFFER_MESSAGES,
            "broker.db.path": BROKER_DB_PATH,
            "num_partitions": BROKER_PARTITIONS,
        }
        self.producer = Producer(
            producer_conf,
            db_path=BROKER_DB_PATH,
            max_queue_size=MAX_BROKER_BUFFER_MESSAGES,
            num_partitions=BROKER_PARTITIONS,
        )

        # Lightweight metadata consumer used solely for querying partition watermarks
        watermark_conf = {
            "group.id": f"{BROKER_CONSUMER_GROUP}-metrics-inspector",
            "enable.auto.commit": False,
            "session.timeout.ms": 10000,
            "broker.db.path": BROKER_DB_PATH,
            "num_partitions": BROKER_PARTITIONS,
        }
        self._watermark_consumer = Consumer(
            watermark_conf,
            db_path=BROKER_DB_PATH,
            num_partitions=BROKER_PARTITIONS,
        )

        self._stop_event.clear()
        self._poll_thread = threading.Thread(
            target=self._delivery_poll_loop,
            name="broker-producer-poller",
            daemon=True,
        )
        self._poll_thread.start()
        logger.info("Lightweight WAL Broker Producer and background poller started.")

    def stop(self) -> None:
        logger.info("Stopping Broker Producer and flushing in-flight messages...")
        self._stop_event.set()
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=5.0)

        if self.producer is not None:
            remaining = self.producer.flush(timeout=15.0)
            self._flush_acked_counter()
            if remaining > 0:
                logger.error(
                    "Producer flush timed out with %d unacknowledged messages!",
                    remaining,
                )
                self.metrics_store.increment_permanently_dropped(remaining)
        else:
            self._flush_acked_counter()

        self.metrics_store.flush()
        self.invalidate_lag_cache()

        with self._watermark_lock:
            if self._watermark_consumer is not None:
                try:
                    self._watermark_consumer.close()
                except Exception as exc:
                    logger.warning("Error closing watermark consumer: %s", exc)
                self._watermark_consumer = None

        logger.info("Broker middleware shutdown complete.")

    def _ensure_topic_exists(self) -> None:
        """
        Explicitly initializes the `security-logs` topic with 3 partitions and
        retention.ms=86400000 (24 hours), retrying during container warm-up.
        """
        assert self.admin_client is not None
        max_attempts = 15
        required_topics = [
            BROKER_TOPIC,
            BROKER_PRIORITY_TOPIC,
            BROKER_DLQ_TOPIC,
            BROKER_RETRY_1M_TOPIC,
            BROKER_RETRY_10M_TOPIC,
            BROKER_POISON_TOPIC,
        ]
        for attempt in range(1, max_attempts + 1):
            try:
                metadata = self.admin_client.list_topics(timeout=5.0)
                topics_to_create = [
                    NewTopic(
                        topic=t,
                        num_partitions=BROKER_PARTITIONS,
                        replication_factor=1,
                        config={
                            "retention.ms": str(BROKER_RETENTION_MS),
                            "min.insync.replicas": "1",
                        },
                    )
                    for t in required_topics
                    if t not in metadata.topics
                ]
                if topics_to_create:
                    futures = self.admin_client.create_topics(
                        topics_to_create, operation_timeout=10.0
                    )
                    for topic_name, future in futures.items():
                        try:
                            future.result(timeout=10.0)
                            logger.info("Topic '%s' created successfully.", topic_name)
                        except BrokerException as kexc:
                            err = kexc.args[0]
                            if err.code() == BrokerError.TOPIC_ALREADY_EXISTS:
                                logger.info("Topic '%s' already exists.", topic_name)
                            else:
                                raise

                for t_name in (BROKER_TOPIC, BROKER_PRIORITY_TOPIC):
                    if t_name in metadata.topics:
                        resource = ConfigResource(
                            ResourceType.TOPIC,
                            t_name,
                            set_config={"retention.ms": str(BROKER_RETENTION_MS)},
                        )
                        futures = self.admin_client.alter_configs([resource])
                        for _, future in futures.items():
                            future.result(timeout=10.0)
                return
            except Exception as exc:
                logger.warning(
                    "Broker topic init attempt %d/%d failed: %s",
                    attempt,
                    max_attempts,
                    exc,
                )
                if attempt == max_attempts:
                    logger.error(
                        "Proceeding after max topic initialization attempts; broker auto-creation will fallback."
                    )
                    return
                time.sleep(1.5)

    def _delivery_callback(self, err: Optional[BrokerError], msg: Any) -> None:
        if err is not None:
            logger.error(
                "Permanent broker delivery failure for key=%s: %s",
                msg.key(),
                err,
            )
            self.metrics_store.increment_permanently_dropped(1)
        else:
            with self._acked_batch_lock:
                self._acked_batch_pending += 1

    def _flush_acked_counter(self) -> None:
        with self._acked_batch_lock:
            pending = self._acked_batch_pending
            self._acked_batch_pending = 0
        if pending > 0:
            self.metrics_store.increment_broker_acked(pending)

    def flush_metrics(self) -> None:
        """Flushes pending broker acknowledgment counts and in-memory metric deltas to SQLite."""
        self._flush_acked_counter()
        self.metrics_store.flush()

    def _delivery_poll_loop(self) -> None:
        """
        Dedicated background thread that services broker delivery callbacks
        and periodically flushes batched acknowledgment and ingest deltas to SQLite WAL.
        """
        while not self._stop_event.is_set():
            if self.producer is not None:
                try:
                    self.producer.poll(0.02)
                except Exception as exc:
                    logger.warning("Error during producer.poll: %s", exc)
            self.flush_metrics()

    @staticmethod
    def _serialize_event(event: SecurityLogEvent) -> Tuple[bytes, bytes, int]:
        redacted_raw = redact_sensitive_data(
            event.raw_payload, patterns=REDACTION_PATTERNS
        )
        try:
            event.raw_payload = redacted_raw
        except Exception:
            pass
        payload_dict = {
            "schema_version": event.schema_version,
            "timestamp": event.timestamp,
            "client_ip": event.client_ip,
            "event_type": event.event_type,
            "target_resource": event.target_resource,
            "status_code": event.status_code,
            "severity": event.severity,
            "raw_payload": redacted_raw,
        }
        key_bytes = event.client_ip.encode("utf-8")
        value_bytes = json.dumps(
            payload_dict, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        event_timestamp_ms = int(round(event.timestamp * 1000))
        return key_bytes, value_bytes, event_timestamp_ms

    def _produce_once(
        self,
        key_bytes: bytes,
        value_bytes: bytes,
        event_timestamp_ms: int,
        topic: str = BROKER_TOPIC,
        headers: Optional[List[Tuple[str, bytes]]] = None,
    ) -> None:
        assert self.producer is not None
        produce_kwargs: Dict[str, Any] = {
            "topic": topic,
            "key": key_bytes,
            "value": value_bytes,
            "timestamp": event_timestamp_ms,
            "on_delivery": self._delivery_callback,
        }
        if headers is not None:
            produce_kwargs["headers"] = headers
        self.producer.produce(**produce_kwargs)
        self.producer.poll(0)

    def _handle_buffer_exhausted(self) -> None:
        self.metrics_store.increment_permanently_dropped(1)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Broker producer local buffer saturated under extreme backpressure.",
            headers={"Retry-After": "1"},
        )

    def _handle_broker_exception(self, exc: BrokerException) -> None:
        self.metrics_store.increment_permanently_dropped(1)
        logger.error("Broker produce exception: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to enqueue log to broker: {exc}",
        ) from exc

    def enqueue_event(
        self,
        event: SecurityLogEvent,
        parent_traceparent: Optional[str] = None,
    ) -> None:
        """
        Serializes a validated SecurityLogEvent and enqueues it to Broker using
        `client_ip` (bytes) as the partition key to guarantee strict per-attacker
        chronological ordering across kill-chain stages. Routes high-priority
        events (HONEYTOKEN_ACCESS or severity <= 2) to `security-logs.priority`.
        Injects W3C traceparent into message headers if OTEL is enabled.
        """
        if self.producer is None:
            raise RuntimeError("Broker producer is not initialized.")

        target_topic = route_event_topic(event)
        key_bytes, value_bytes, event_timestamp_ms = self._serialize_event(event)

        headers: Optional[List[Tuple[str, bytes]]] = None
        if OTEL_ENABLED or parent_traceparent:
            is_prio = is_priority_event(event)
            headers = inject_traceparent_to_broker_headers(
                headers=None,
                is_priority=is_prio,
                parent_traceparent=parent_traceparent,
            )

        for attempt in range(self.max_buffer_retries):
            try:
                self._produce_once(
                    key_bytes,
                    value_bytes,
                    event_timestamp_ms,
                    topic=target_topic,
                    headers=headers,
                )
                return
            except BufferError:
                self.producer.poll(0)
                if attempt == self.max_buffer_retries - 1:
                    self._handle_buffer_exhausted()
                if self.buffer_retry_sleep > 0:
                    time.sleep(self.buffer_retry_sleep)
            except BrokerException as exc:
                self._handle_broker_exception(exc)

    async def enqueue_event_async(
        self,
        event: SecurityLogEvent,
        parent_traceparent: Optional[str] = None,
    ) -> None:
        """
        Non-blocking async helper for FastAPI endpoints that yields to the asyncio
        event loop (`await asyncio.sleep(0.02)`) if broker producer raises BufferError.
        """
        if getattr(self.enqueue_event, "__func__", None) is not WalLogBufferingMiddleware.enqueue_event:
            self.enqueue_event(event, parent_traceparent=parent_traceparent)
            return

        if self.producer is None:
            raise RuntimeError("Broker producer is not initialized.")

        target_topic = route_event_topic(event)
        key_bytes, value_bytes, event_timestamp_ms = self._serialize_event(event)

        headers: Optional[List[Tuple[str, bytes]]] = None
        if OTEL_ENABLED or parent_traceparent:
            is_prio = is_priority_event(event)
            headers = inject_traceparent_to_broker_headers(
                headers=None,
                is_priority=is_prio,
                parent_traceparent=parent_traceparent,
            )

        for attempt in range(self.max_buffer_retries):
            try:
                self._produce_once(
                    key_bytes,
                    value_bytes,
                    event_timestamp_ms,
                    topic=target_topic,
                    headers=headers,
                )
                return
            except BufferError:
                self.producer.poll(0)
                if attempt == self.max_buffer_retries - 1:
                    self._handle_buffer_exhausted()
                await asyncio.sleep(self.buffer_retry_sleep)
            except BrokerException as exc:
                self._handle_broker_exception(exc)

    def invalidate_lag_cache(self) -> None:
        """Clears the cached broker native lag snapshot."""
        with self._lag_cache_lock:
            self._lag_cache_value = None
            self._lag_cache_timestamp = 0.0

    def _fetch_broker_native_lag(self) -> Dict[str, Any]:
        """
        Performs live broker RPCs to query broker partition high-watermarks and
        committed consumer group offsets across all partitions of `security-logs`.
        """
        if self.admin_client is None or self._watermark_consumer is None:
            raise RuntimeError("Broker clients are not initialized.")

        standard_partitions = [
            TopicPartition(BROKER_TOPIC, pid) for pid in range(BROKER_PARTITIONS)
        ]
        priority_partitions = [
            TopicPartition(BROKER_PRIORITY_TOPIC, pid)
            for pid in range(BROKER_PARTITIONS)
        ]
        all_topic_partitions = standard_partitions + priority_partitions

        # 1. Fetch committed offsets for the Graylog Consumer Worker group across both topics
        committed_map: Dict[Tuple[str, int], int] = {}
        has_priority_in_group = True
        try:
            group_req = [
                ConsumerGroupTopicPartitions(
                    BROKER_CONSUMER_GROUP, all_topic_partitions
                )
            ]
            futures = self.admin_client.list_consumer_group_offsets(group_req)
            for _, future in futures.items():
                group_result = future.result(timeout=2.5)
                if group_result.topic_partitions:
                    has_priority_in_group = any(
                        tp.topic == BROKER_PRIORITY_TOPIC
                        for tp in group_result.topic_partitions
                    )
                for tp in group_result.topic_partitions:
                    if (
                        tp.offset is not None
                        and tp.offset >= 0
                        and tp.offset != OFFSET_INVALID
                    ):
                        committed_map[(tp.topic, tp.partition)] = int(tp.offset)
                    else:
                        committed_map[(tp.topic, tp.partition)] = 0
        except Exception as exc:
            logger.debug(
                "Consumer group offset lookup note (group may not have committed yet): %s",
                exc,
            )
            for tp in all_topic_partitions:
                committed_map[(tp.topic, tp.partition)] = 0

        # 2. Fetch live (low, high) watermark offsets per partition from the broker
        total_high_watermark = 0
        total_committed = 0
        total_broker_lag = 0
        standard_broker_lag = 0
        priority_broker_lag = 0
        partition_details: List[PartitionLagInfo] = []
        priority_partition_details: List[PartitionLagInfo] = []

        with self._watermark_lock:
            for tp in standard_partitions:
                low_offset, high_offset = (
                    self._watermark_consumer.get_watermark_offsets(
                        tp, timeout=2.0, cached=False
                    )
                )
                raw_committed = committed_map.get((tp.topic, tp.partition), 0)
                effective_committed = max(low_offset, min(raw_committed, high_offset))
                partition_lag = max(0, high_offset - effective_committed)
                partition_consumed = max(0, effective_committed - low_offset)

                total_high_watermark += max(0, high_offset - low_offset)
                total_committed += partition_consumed
                total_broker_lag += partition_lag
                standard_broker_lag += partition_lag

                partition_details.append(
                    PartitionLagInfo(
                        partition=int(tp.partition),
                        low_watermark=int(low_offset),
                        high_watermark=int(high_offset),
                        committed_offset=int(effective_committed),
                        lag=int(partition_lag),
                    )
                )

            if has_priority_in_group:
                for tp in priority_partitions:
                    try:
                        low_offset, high_offset = (
                            self._watermark_consumer.get_watermark_offsets(
                                tp, timeout=2.0, cached=False
                            )
                        )
                    except Exception:
                        low_offset, high_offset = 0, 0
                    raw_committed = committed_map.get((tp.topic, tp.partition), 0)
                    effective_committed = max(low_offset, min(raw_committed, high_offset))
                    partition_lag = max(0, high_offset - effective_committed)
                    partition_consumed = max(0, effective_committed - low_offset)

                    total_high_watermark += max(0, high_offset - low_offset)
                    total_committed += partition_consumed
                    total_broker_lag += partition_lag
                    priority_broker_lag += partition_lag

                    priority_partition_details.append(
                        PartitionLagInfo(
                            partition=int(tp.partition),
                            low_watermark=int(low_offset),
                            high_watermark=int(high_offset),
                            committed_offset=int(effective_committed),
                            lag=int(partition_lag),
                        )
                    )
            else:
                for tp in priority_partitions:
                    priority_partition_details.append(
                        PartitionLagInfo(
                            partition=int(tp.partition),
                            low_watermark=0,
                            high_watermark=0,
                            committed_offset=0,
                            lag=0,
                        )
                    )

        in_flight_producer = len(self.producer) if self.producer is not None else 0

        res = BrokerLagSnapshot(
            broker_total_messages=total_high_watermark,
            consumer_committed_total=total_committed,
            broker_queue_lag=total_broker_lag,
            in_flight_producer_queue=in_flight_producer,
            partitions=partition_details,
        ).to_dict()
        res["standard_queue_lag"] = standard_broker_lag
        res["priority_queue_lag"] = priority_broker_lag
        res["priority_partitions"] = [
            p.to_dict() for p in priority_partition_details
        ]
        res["lanes"] = {
            "standard": {
                "topic": BROKER_TOPIC,
                "lag": standard_broker_lag,
                "partitions": [p.to_dict() for p in partition_details],
            },
            "priority": {
                "topic": BROKER_PRIORITY_TOPIC,
                "lag": priority_broker_lag,
                "partitions": [p.to_dict() for p in priority_partition_details],
            },
        }
        return res

    def query_broker_native_lag(self) -> Dict[str, Any]:
        """
        Queries broker partition high-watermarks and committed consumer group offsets
        across all partitions of `security-logs` to compute exact queue lag.
        Caches results in a thread-safe manner with a 1-second TTL (`self.lag_cache_ttl`).
        """
        with self._lag_cache_lock:
            now = time.monotonic()
            if (
                self.lag_cache_ttl > 0
                and self._lag_cache_value is not None
                and (now - self._lag_cache_timestamp) < self.lag_cache_ttl
            ):
                return copy.deepcopy(self._lag_cache_value)

            snapshot = self._fetch_broker_native_lag()
            self._lag_cache_value = copy.deepcopy(snapshot)
            self._lag_cache_timestamp = time.monotonic()
            return snapshot

    _query_broker_lag_snapshot = query_broker_native_lag
    query_broker_lag_snapshot = query_broker_native_lag

    def reset_broker_storage(self) -> None:
        """
        Resets and truncates all messages and committed offsets in the lightweight broker
        SQLite storage, purges in-flight producer queues, and clears lag caches.
        """
        with self._watermark_lock:
            if self.producer is not None:
                self.producer.purge()
            storage = SQLiteBrokerStorage(BROKER_DB_PATH, default_partitions=BROKER_PARTITIONS)
            storage.reset_all()
            storage.close()
            self.reset_broker_baseline = 0
            self.reset_committed_baseline = 0
            self.invalidate_lag_cache()


    def query_topic_stats(
        self, topic_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Inspects partition watermarks and calculates message count and oldest message age
        per topic across DLQ, retry tiers, and poison topics.
        """
        topics = topic_names or [
            BROKER_DLQ_TOPIC,
            BROKER_RETRY_1M_TOPIC,
            BROKER_RETRY_10M_TOPIC,
            BROKER_POISON_TOPIC,
        ]
        result: Dict[str, Any] = {}
        total_dlq = 0
        now = time.time()

        with self._watermark_lock:
            for topic in topics:
                topic_count = 0
                oldest_ts: Optional[float] = None
                partition_details = []

                if self._watermark_consumer is not None:
                    for pid in range(BROKER_PARTITIONS):
                        tp = TopicPartition(topic, pid)
                        try:
                            low, high = self._watermark_consumer.get_watermark_offsets(
                                tp, timeout=2.0, cached=False
                            )
                            p_count = max(0, high - low)
                            topic_count += p_count
                            partition_details.append(
                                {
                                    "partition": pid,
                                    "low_watermark": int(low),
                                    "high_watermark": int(high),
                                    "count": int(p_count),
                                }
                            )
                            if high > low:
                                try:
                                    self._watermark_consumer.assign([tp])
                                    self._watermark_consumer.seek(
                                        TopicPartition(topic, pid, low)
                                    )
                                    sample_msg = self._watermark_consumer.poll(
                                        timeout=0.3
                                    )
                                    if sample_msg is not None and not sample_msg.error():
                                        ts_tuple = sample_msg.timestamp()
                                        if ts_tuple and ts_tuple[1] > 0:
                                            msg_sec = ts_tuple[1] / 1000.0
                                            if oldest_ts is None or msg_sec < oldest_ts:
                                                oldest_ts = msg_sec
                                except Exception:
                                    pass
                        except Exception as exc:
                            logger.debug(
                                "Watermark query note for topic %s partition %d: %s",
                                topic,
                                pid,
                                exc,
                            )
                            partition_details.append(
                                {
                                    "partition": pid,
                                    "low_watermark": 0,
                                    "high_watermark": 0,
                                    "count": 0,
                                }
                            )

                oldest_age = (
                    round(now - oldest_ts, 2) if oldest_ts is not None else None
                )
                if topic == BROKER_DLQ_TOPIC:
                    total_dlq = topic_count

                result[topic] = {
                    "count": topic_count,
                    "oldest_message_age_seconds": oldest_age,
                    "partitions": partition_details,
                }

        return {
            "topics": result,
            "total_dlq_count": total_dlq,
        }

    def replay_from_dlq(
        self,
        source_topic: str = BROKER_DLQ_TOPIC,
        target_topic: str = BROKER_TOPIC,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Replays up to `limit` messages from `source_topic` to `target_topic`.
        Preserves deterministic `_event_id` and injects `x-replay-id` header.
        Commits source DLQ offsets and updates `dlq_quarantined_logs` and `dlq_replayed_logs`.
        """
        replay_id = str(uuid.uuid4())
        if self.producer is None:
            raise RuntimeError("Broker producer is not initialized.")

        consumer_conf = {
            "group.id": f"{BROKER_CONSUMER_GROUP}-admin-replay",
            "enable.auto.commit": False,
            "auto.offset.reset": "earliest",
            "session.timeout.ms": 10000,
            "broker.db.path": BROKER_DB_PATH,
            "num_partitions": BROKER_PARTITIONS,
        }
        replay_consumer = Consumer(
            consumer_conf,
            db_path=BROKER_DB_PATH,
            num_partitions=BROKER_PARTITIONS,
        )
        replay_consumer.subscribe([source_topic])

        replayed_messages: List[Message] = []
        try:
            start_poll = time.time()
            empty_count = 0
            while len(replayed_messages) < limit and (time.time() - start_poll) < 5.0:
                msg = replay_consumer.poll(timeout=0.2)
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
                return {
                    "replayed_count": 0,
                    "replay_id": replay_id,
                }

            for msg in replayed_messages:
                key_bytes = msg.key()
                raw_val = msg.value()
                val_bytes = raw_val

                existing_headers = []
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
                    topic=target_topic,
                    key=key_bytes,
                    value=val_bytes,
                    headers=out_headers,
                )

            self.producer.flush(timeout=10.0)
            replay_consumer.commit(asynchronous=False)

            replayed_count = len(replayed_messages)
            self.metrics_store.reconcile_dlq_replay(
                replayed_count, increment_forwarded=False
            )
            self.flush_metrics()

            return {
                "replayed_count": replayed_count,
                "replay_id": replay_id,
            }
        finally:
            try:
                replay_consumer.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# FastAPI Application & Lifespan Management
# ---------------------------------------------------------------------------
metrics_store = SharedMetricsStore(METRICS_DB_PATH)
_DEFAULT_MIDDLEWARE = WalLogBufferingMiddleware(metrics_store)
wal_middleware = _DEFAULT_MIDDLEWARE


def _active_middleware() -> WalLogBufferingMiddleware:
    """Returns active middleware instance, respecting test monkeypatching of wal_middleware."""
    return wal_middleware


@asynccontextmanager
async def lifespan(_app: FastAPI):
    mw = _active_middleware()
    mw.start()
    yield
    mw.stop()


app = FastAPI(
    title="SOAR Lightweight Broker Log Buffering Ingestor",
    description=(
        "High-throughput, non-blocking HTTP Log Ingestor & Lightweight Broker Producer "
        "guaranteeing Zero Log Loss (At-Least-Once Delivery) and strict per-IP "
        "Kill-Chain chronological ordering for Graylog SIEM."
    ),
    version="1.1.0",
    lifespan=lifespan,
)

# Register RFC 7807 Problem Details global exception handlers
register_problem_handlers(app)


@app.middleware("http")
async def deprecation_header_middleware(request: Request, call_next: Any) -> Response:
    """
    Emits 'Deprecation: true' on legacy unversioned routes (e.g. /ingest, /metrics, /admin/*)
    while keeping new versioned routes (/v1/...) clean.
    """
    response: Response = await call_next(request)
    path = request.url.path
    if not path.startswith("/v1") and path not in (
        "/docs",
        "/openapi.json",
        "/redoc",
        "/metrics/prometheus",
    ):
        response.headers["Deprecation"] = "true"
    return response


v1_router = APIRouter(prefix="/v1")


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------
@v1_router.get("/health", status_code=status.HTTP_200_OK)
@app.get("/health", status_code=status.HTTP_200_OK, deprecated=True)
async def health_check() -> Dict[str, Any]:
    """Liveness and readiness probe for Docker Compose and load balancers."""
    mw = _active_middleware()
    in_flight = len(mw.producer) if mw.producer else 0
    return {
        "status": "healthy",
        "topic": BROKER_TOPIC,
        "partitions": BROKER_PARTITIONS,
        "in_flight_producer_messages": in_flight,
    }


@v1_router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
@app.post("/ingest", status_code=status.HTTP_202_ACCEPTED, deprecated=True)
async def ingest_single_log(
    event: SecurityLogEvent,
    request: Request = None,
    identity: str = Depends(require_ingest_auth),
) -> Dict[str, Any]:
    """
    Ingests a single security event from Main Flask API or ESP32 IoT board,
    validates schema, and asynchronously buffers into Broker partitioned by `client_ip`.
    """
    client_identity = identity if isinstance(identity, str) else "anonymous"
    allowed, retry_after = ingest_rate_limiter.check_and_consume(client_identity, tokens=1.0)
    if not allowed:
        retry_seconds = max(1, int(math.ceil(retry_after)))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for client identity. Retry after {retry_seconds}s.",
            headers={"Retry-After": str(retry_seconds)},
        )

    mw = _active_middleware()
    parent_traceparent = request.headers.get("traceparent") if request is not None else None
    if parent_traceparent is not None:
        try:
            await mw.enqueue_event_async(
                event, parent_traceparent=parent_traceparent
            )
        except TypeError:
            await mw.enqueue_event_async(event)
    else:
        await mw.enqueue_event_async(event)

    record_logs_received(1)
    total_received = metrics_store.increment_received(1)
    return {
        "status": "queued",
        "accepted": 1,
        "partition_key": event.client_ip,
        "normalized_timestamp": event.timestamp,
        "total_received": total_received,
    }


@v1_router.post("/ingest/batch", status_code=status.HTTP_202_ACCEPTED)
@app.post("/ingest/batch", status_code=status.HTTP_202_ACCEPTED, deprecated=True)
async def ingest_batch_logs(
    payload: Union[BatchIngestRequest, List[SecurityLogEvent]] = Body(...),
    request: Request = None,
    identity: str = Depends(require_ingest_auth),
) -> Dict[str, Any]:
    """
    Ingests a batch of security events in a single HTTP request to minimize HTTP
    overhead during high-velocity attack spikes (e.g., Nmap scan or Hydra brute-force).
    Accepts either `{"logs": [...]}` or a raw JSON list `[...]`.
    """
    events: List[SecurityLogEvent] = (
        payload.logs if isinstance(payload, BatchIngestRequest) else payload
    )
    if not events:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Batch payload must contain at least one log event.",
        )

    client_identity = identity if isinstance(identity, str) else "anonymous"
    allowed, retry_after = ingest_rate_limiter.check_and_consume(
        client_identity, tokens=float(len(events))
    )
    if not allowed:
        retry_seconds = max(1, int(math.ceil(retry_after)))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for client identity. Retry after {retry_seconds}s.",
            headers={"Retry-After": str(retry_seconds)},
        )

    mw = _active_middleware()
    parent_traceparent = request.headers.get("traceparent") if request is not None else None
    enqueued_count = 0
    try:
        for event in events:
            if parent_traceparent is not None:
                try:
                    await mw.enqueue_event_async(
                        event, parent_traceparent=parent_traceparent
                    )
                except TypeError:
                    await mw.enqueue_event_async(event)
            else:
                await mw.enqueue_event_async(event)
            enqueued_count += 1
    except Exception:
        if enqueued_count > 0:
            metrics_store.increment_received(enqueued_count)
            record_logs_received(enqueued_count)
        raise

    record_logs_received(enqueued_count)
    total_received = metrics_store.increment_received(enqueued_count)
    return {
        "status": "queued",
        "accepted": enqueued_count,
        "total_received": total_received,
    }


@v1_router.get("/metrics", status_code=status.HTTP_200_OK)
@app.get("/metrics", status_code=status.HTTP_200_OK, deprecated=True)
async def get_pipeline_metrics() -> JSONResponse:
    """
    Real-Time Observability & Demo Metrics endpoint.
    Flushes pending producer deltas to SQLite, then combines atomic counters with
    live broker partition watermark and consumer-group offset inspection to report
    exact queue lag, peak queue lag, sliding-window EPS, and zero log loss.
    """
    mw = _active_middleware()
    mw.flush_metrics()
    db_snapshot = metrics_store.read_snapshot()

    throughput_telemetry = {
        "inbound_eps": float(db_snapshot.get("inbound_eps", 0.0)),
        "peak_inbound_eps": float(db_snapshot.get("peak_inbound_eps", 0.0)),
        "outbound_eps": float(db_snapshot.get("outbound_eps", 0.0)),
        "peak_outbound_eps": float(db_snapshot.get("peak_outbound_eps", 0.0)),
        "priority_outbound_eps": float(
            db_snapshot.get("priority_outbound_eps", 0.0)
        ),
        "standard_outbound_eps": float(
            db_snapshot.get("standard_outbound_eps", 0.0)
        ),
        "configured_max_logs_per_sec": float(MAX_LOGS_PER_SEC),
    }

    try:
        broker_stats = await asyncio.to_thread(mw.query_broker_native_lag)
        broker_total = int(broker_stats["broker_total_messages"])
        committed_total = int(broker_stats["consumer_committed_total"])
        in_flight = int(broker_stats["in_flight_producer_queue"])

        run_broker_total = max(
            0, broker_total - mw.reset_broker_baseline
        )

        total_received = int(
            max(
                int(db_snapshot["total_received"]),
                run_broker_total + in_flight,
            )
        )
        # Only count logs confirmed delivered with HTTP 2xx (or replayed from DLQ).
        # Committed broker offsets include dead-lettered batches and are exposed separately.
        total_forwarded_to_graylog = int(db_snapshot["total_forwarded_to_graylog"])
        permanently_dropped_logs = int(db_snapshot["permanently_dropped_logs"])
        dlq_quarantined_logs = int(db_snapshot["dlq_quarantined_logs"])
        dropped_logs = permanently_dropped_logs + dlq_quarantined_logs
        dlq_replayed_logs = int(db_snapshot.get("dlq_replayed_logs", 0))
        invariant_violations = int(db_snapshot.get("invariant_violations", 0))
        total_broker_acked = int(
            max(
                int(db_snapshot["total_broker_acked"]),
                run_broker_total,
            )
        )

        # Exact number of logs currently buffered in the pipeline waiting for Graylog
        # = broker partition lag + any messages still in producer buffer
        current_queue_lag = int(
            max(
                0,
                int(broker_stats["broker_queue_lag"]) + in_flight,
                total_received - total_forwarded_to_graylog - dropped_logs,
            )
        )
        peak_queue_lag = metrics_store.update_peak_lag(current_queue_lag)
        priority_queue_lag = int(broker_stats.get("priority_queue_lag", 0))
        standard_queue_lag = int(
            broker_stats.get("standard_queue_lag", current_queue_lag)
        )

        poison_messages = int(db_snapshot.get("poison_messages", 0))

        broker_telemetry = {
            "topic": BROKER_TOPIC,
            "priority_topic": BROKER_PRIORITY_TOPIC,
            "consumer_group": BROKER_CONSUMER_GROUP,
            "total_broker_acked": total_broker_acked,
            "in_flight_producer_queue": in_flight,
            "broker_high_watermark_total": broker_total,
            "consumer_committed_offset_total": committed_total,
            "partitions": broker_stats["partitions"],
            "lanes": broker_stats.get("lanes", {}),
        }

        response_payload = {
            "total_received": total_received,
            "current_queue_lag": current_queue_lag,
            "peak_queue_lag": peak_queue_lag,
            "priority_queue_lag": priority_queue_lag,
            "standard_queue_lag": standard_queue_lag,
            "total_forwarded_to_graylog": total_forwarded_to_graylog,
            "consumer_committed_offset_total": committed_total,
            "permanently_dropped_logs": permanently_dropped_logs,
            "dlq_quarantined_logs": dlq_quarantined_logs,
            "dropped_logs": dropped_logs,
            "dlq_replayed_logs": dlq_replayed_logs,
            "poison_messages": poison_messages,
            "invariant_violations": invariant_violations,
            "throughput_telemetry": throughput_telemetry,
            "broker_telemetry": broker_telemetry,
        }
    except Exception as exc:
        logger.warning("Broker watermark query fallback to SQLite WAL counters: %s", exc)
        total_received = int(db_snapshot["total_received"])
        total_forwarded_to_graylog = int(db_snapshot["total_forwarded_to_graylog"])
        permanently_dropped_logs = int(db_snapshot["permanently_dropped_logs"])
        dlq_quarantined_logs = int(db_snapshot["dlq_quarantined_logs"])
        dropped_logs = permanently_dropped_logs + dlq_quarantined_logs
        dlq_replayed_logs = int(db_snapshot.get("dlq_replayed_logs", 0))
        poison_messages = int(db_snapshot.get("poison_messages", 0))
        invariant_violations = int(db_snapshot.get("invariant_violations", 0))
        committed_fallback = total_forwarded_to_graylog + dlq_quarantined_logs
        in_flight = (
            len(mw.producer)
            if mw.producer is not None
            else 0
        )
        current_queue_lag = max(
            0, total_received - total_forwarded_to_graylog - dropped_logs
        )
        peak_queue_lag = metrics_store.update_peak_lag(current_queue_lag)
        broker_telemetry_fallback = {
            "topic": BROKER_TOPIC,
            "priority_topic": BROKER_PRIORITY_TOPIC,
            "consumer_group": BROKER_CONSUMER_GROUP,
            "total_broker_acked": int(db_snapshot["total_broker_acked"]),
            "in_flight_producer_queue": in_flight,
            "broker_high_watermark_total": int(db_snapshot["total_broker_acked"]),
            "consumer_committed_offset_total": committed_fallback,
            "partitions": [],
            "lanes": {},
        }
        response_payload = {
            "total_received": total_received,
            "current_queue_lag": current_queue_lag,
            "peak_queue_lag": peak_queue_lag,
            "priority_queue_lag": 0,
            "standard_queue_lag": current_queue_lag,
            "total_forwarded_to_graylog": total_forwarded_to_graylog,
            "consumer_committed_offset_total": committed_fallback,
            "permanently_dropped_logs": permanently_dropped_logs,
            "dlq_quarantined_logs": dlq_quarantined_logs,
            "dropped_logs": dropped_logs,
            "dlq_replayed_logs": dlq_replayed_logs,
            "poison_messages": poison_messages,
            "invariant_violations": invariant_violations,
            "throughput_telemetry": throughput_telemetry,
            "broker_telemetry": broker_telemetry_fallback,
        }

    return JSONResponse(content=response_payload)


@v1_router.get("/metrics/prometheus", status_code=status.HTTP_200_OK)
@app.get("/metrics/prometheus", status_code=status.HTTP_200_OK)
async def get_prometheus_metrics() -> Response:
    """
    Standard Prometheus exposition endpoint exposing pipeline counters, gauges,
    and latency histograms.
    """
    mw = _active_middleware()
    mw.flush_metrics()
    db_snapshot = metrics_store.read_snapshot()
    try:
        broker_stats = await asyncio.to_thread(mw.query_broker_native_lag)
    except Exception:
        broker_stats = None
    try:
        topic_stats = await asyncio.to_thread(mw.query_topic_stats)
    except Exception:
        topic_stats = None

    sync_prometheus_metrics(
        snapshot=db_snapshot,
        lag_snapshot=broker_stats,
        topic_stats=topic_stats,
        rate_limit=float(MAX_LOGS_PER_SEC),
        max_logs_per_sec=float(MAX_LOGS_PER_SEC),
    )
    return Response(
        content=generate_latest(PIPELINE_REGISTRY),
        media_type=CONTENT_TYPE_LATEST,
    )


class DlqReplayRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    limit: int = Field(
        default=100, ge=1, le=10000, description="Max messages to replay."
    )
    source_topic: str = Field(
        default=BROKER_DLQ_TOPIC, description="Source DLQ topic to replay from."
    )
    target_topic: str = Field(
        default=BROKER_TOPIC, description="Target topic to replay to."
    )


@v1_router.get("/admin/dlq", status_code=status.HTTP_200_OK)
@app.get("/admin/dlq", status_code=status.HTTP_200_OK, deprecated=True)
async def get_dlq_status(
    identity: str = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """
    Returns message counts and oldest message age per topic across DLQ, retry tiers,
    and poison topics.
    """
    mw = _active_middleware()
    stats = await asyncio.to_thread(mw.query_topic_stats)
    response = dict(stats)
    response["dlq_backend"] = DLQ_BACKEND
    return response


@v1_router.post("/admin/dlq/replay", status_code=status.HTTP_200_OK)
@app.post("/admin/dlq/replay", status_code=status.HTTP_200_OK, deprecated=True)
async def replay_dlq_records(
    payload: Optional[DlqReplayRequest] = Body(default=None),
    identity: str = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """
    Replays up to N messages from the DLQ topic back to the main topic with a new
    x-replay-id header. Idempotency is preserved through deterministic _event_id.
    """
    req = payload or DlqReplayRequest()
    mw = _active_middleware()
    result = await asyncio.to_thread(
        mw.replay_from_dlq,
        source_topic=req.source_topic,
        target_topic=req.target_topic,
        limit=req.limit,
    )
    return {
        "status": "replayed",
        "replayed_count": result["replayed_count"],
        "source_topic": req.source_topic,
        "target_topic": req.target_topic,
        "replay_id": result["replay_id"],
    }


@v1_router.post("/metrics/reset", status_code=status.HTTP_200_OK)
@app.post("/metrics/reset", status_code=status.HTTP_200_OK, deprecated=True)
async def reset_pipeline_metrics(
    identity: str = Depends(require_admin_auth),
) -> Dict[str, str]:
    """
    Resets all pipeline counters and sliding-window throughput telemetry in SQLite WAL
    so demo runs start from a clean slate.
    """
    mw = _active_middleware()
    mw.flush_metrics()
    mw.invalidate_lag_cache()
    try:
        await asyncio.to_thread(mw.reset_broker_storage)
    except Exception as exc:
        logger.warning("Error resetting broker storage: %s", exc)

    try:
        broker_stats = await asyncio.to_thread(mw.query_broker_native_lag)
        mw.reset_broker_baseline = int(
            broker_stats["broker_total_messages"]
        )
        mw.reset_committed_baseline = int(
            broker_stats["consumer_committed_total"]
        )
    except Exception:
        mw.reset_broker_baseline = 0
        mw.reset_committed_baseline = 0

    metrics_store.reset_all()
    reset_prometheus_metrics()
    wal_middleware.invalidate_lag_cache()
    return {"status": "reset"}


# Include v1 router in FastAPI application
app.include_router(v1_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("ingestor:app", host=INGESTOR_HOST, port=INGESTOR_PORT, reload=False)
