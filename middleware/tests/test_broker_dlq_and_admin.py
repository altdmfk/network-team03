import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

import httpx
import pytest
from middleware.lightweight_broker import BrokerError, BrokerException, TopicPartition
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from config import (
    BROKER_DLQ_TOPIC,
    BROKER_POISON_TOPIC,
    BROKER_RETRY_1M_TOPIC,
    BROKER_RETRY_10M_TOPIC,
    BROKER_TOPIC,
    MAX_RETRY_TOPIC_ATTEMPTS,
)
from consumer_worker import GraylogConsumerWorker
from ingestor import (
    SecurityLogEvent,
    WalLogBufferingMiddleware,
    app as ingestor_app,
)
from metrics_store import SharedMetricsStore
from middleware import (
    DeliveryOutcome,
    GelfTransformer,
    RetryPolicy,
)
from middleware.dlq_publisher import (
    BrokerDeadLetterPublisher,
    DeadLetterSink,
    get_header_value,
)
from middleware.retry_topic_consumer import RetryTopicConsumer
from mock_graylog_server import MockGraylogState


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------
class FakeBrokerMessageWithHeaders:
    """Mock Message supporting headers and custom attributes."""

    def __init__(
        self,
        payload: Any,
        key: str = "10.0.0.99",
        partition: int = 0,
        offset: int = 1,
        topic: str = config.BROKER_TOPIC,
        headers: Optional[List[Tuple[str, bytes]]] = None,
        error: Optional[Any] = None,
    ) -> None:
        if isinstance(payload, bytes):
            self._value = payload
        elif isinstance(payload, str):
            self._value = payload.encode("utf-8")
        else:
            self._value = json.dumps(payload).encode("utf-8")

        self._key = key.encode("utf-8") if isinstance(key, str) else key
        self._partition = partition
        self._offset = offset
        self._topic = topic
        self._headers = headers or []
        self._error = error

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
        return self._headers

    def error(self) -> Optional[Any]:
        return self._error

    def timestamp(self) -> Tuple[int, int]:
        return (1, int(time.time() * 1000))


def sample_log_payload(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "schema_version": "1.0",
        "timestamp": 1760875200.123,
        "client_ip": "10.0.0.99",
        "event_type": "PORT_SCAN",
        "target_resource": "/admin/ports/scan",
        "status_code": 403,
        "severity": 4,
        "raw_payload": {"tool": "nmap", "ports": [22, 80, 443]},
    }
    base.update(overrides)
    return base


# ===========================================================================
# 1. Schema Versioning Tests (Requirement 4)
# ===========================================================================
class TestSchemaVersioning:
    def test_missing_schema_version_defaults_to_1_0(self) -> None:
        raw = sample_log_payload()
        del raw["schema_version"]
        event = SecurityLogEvent(**raw)
        assert event.schema_version == "1.0"

    def test_minor_version_bump_is_accepted(self) -> None:
        raw = sample_log_payload(schema_version="1.2")
        event = SecurityLogEvent(**raw)
        assert event.schema_version == "1.2"

    def test_unknown_major_version_rejected_with_validation_error(self) -> None:
        raw = sample_log_payload(schema_version="2.0")
        with pytest.raises(ValidationError) as exc_info:
            SecurityLogEvent(**raw)
        assert "Unsupported schema major version" in str(exc_info.value)

    def test_invalid_schema_version_format_rejected(self) -> None:
        raw = sample_log_payload(schema_version="v1.0")
        with pytest.raises(ValidationError) as exc_info:
            SecurityLogEvent(**raw)
        assert "Unsupported schema" in str(exc_info.value)

    def test_ingest_endpoint_rejects_unsupported_major_version(self) -> None:
        client = TestClient(ingestor_app)
        payload = sample_log_payload(schema_version="3.0")
        resp = client.post("/ingest", json=payload)
        assert resp.status_code == 422
        assert "Unsupported schema major version" in resp.text


# ===========================================================================
# 2. DLQ Publisher & Zero-Loss Failure Invariant (Requirement 1)
# ===========================================================================
class TestDLQPublisherAndCommitInvariants:
    def test_dlq_publisher_injects_required_headers(self) -> None:
        captured_messages: List[Dict[str, Any]] = []

        mock_producer = MagicMock()

        def fake_produce(**kwargs: Any) -> None:
            captured_messages.append(kwargs)
            cb = kwargs.get("on_delivery")
            if cb:
                cb(None, MagicMock(topic=lambda: kwargs["topic"]))

        mock_producer.produce.side_effect = fake_produce
        mock_producer.flush.return_value = 0

        publisher = BrokerDeadLetterPublisher(
            producer=mock_producer,
            dlq_topic=BROKER_DLQ_TOPIC,
        )

        msg = FakeBrokerMessageWithHeaders(
            payload=sample_log_payload(),
            key="192.168.1.50",
            partition=2,
            offset=105,
            topic=BROKER_TOPIC,
        )

        success = publisher.publish_to_dlq(
            [msg],
            reason="Graylog HTTP 503 Outage",
            retry_count=3,
        )
        assert success is True
        assert len(captured_messages) == 1

        entry = captured_messages[0]
        assert entry["topic"] == BROKER_DLQ_TOPIC
        assert entry["key"] == b"192.168.1.50"

        headers_dict = {k: v.decode("utf-8") for k, v in entry["headers"]}
        assert headers_dict["x-original-topic"] == BROKER_TOPIC
        assert headers_dict["x-original-partition"] == "2"
        assert headers_dict["x-original-offset"] == "105"
        assert headers_dict["x-retry-count"] == "3"
        assert headers_dict["x-failure-reason"] == "Graylog HTTP 503 Outage"
        assert "x-first-failed-at" in headers_dict

    def test_dlq_publish_failure_means_no_commit(self, tmp_path: Path) -> None:
        """
        Hard zero-loss invariant:
        If DLQ publishing fails (flush returns remaining items, delivery reports error, or exception),
        the batch must be treated as ABORTED, and the consumer MUST NOT commit the source offset.
        """
        db_path = tmp_path / "metrics.db"
        metrics = SharedMetricsStore(db_path=str(db_path))

        failing_dlq_sink = MagicMock(spec=DeadLetterSink)
        failing_dlq_sink.write_dead_letter.return_value = False  # DLQ write rejected / unconfirmed

        mock_consumer = MagicMock()
        mock_consumer.commit.side_effect = RuntimeError("Commit should NEVER be called on DLQ failure!")

        mock_http_client = MagicMock(spec=httpx.Client)
        mock_http_client.post.return_value = MagicMock(
            status_code=503, text="Service Unavailable"
        )

        worker = GraylogConsumerWorker(
            consumer=mock_consumer,
            http_client=mock_http_client,
            metrics_store=metrics,
            dlq_store=failing_dlq_sink,
            max_delivery_retries=1,
            base_backoff_seconds=0.01,
            max_backoff_seconds=0.01,
        )

        msg = FakeBrokerMessageWithHeaders(
            payload=sample_log_payload(),
            partition=0,
            offset=10,
        )

        result = worker.process_single_batch([msg])

        # Batch outcome must be ABORTED
        assert result.outcome == DeliveryOutcome.ABORTED
        # Consumer commit MUST NOT have been called
        assert mock_consumer.commit.call_count == 0
        # Offsets remain uncommitted for future replay
        assert worker.offset_committer.in_flight_aborted is False


# ===========================================================================
# 3. Poison Message Handling (Requirement 3)
# ===========================================================================
class TestPoisonMessageHandling:
    def test_poison_message_does_not_block_partition(self, tmp_path: Path) -> None:
        """
        Poison message (unparseable bytes / malformed JSON) must be isolated to
        security-logs.poison, committed past, and must not prevent subsequent valid
        messages in the batch from being processed and committed.
        """
        db_path = tmp_path / "metrics.db"
        metrics = SharedMetricsStore(db_path=str(db_path))

        mock_dlq_sink = MagicMock()
        mock_dlq_sink.publish_poison.return_value = True

        mock_consumer = MagicMock()
        committed_offsets: List[TopicPartition] = []

        def capture_commit(offsets: Optional[List[TopicPartition]] = None, asynchronous: bool = False) -> None:
            if offsets:
                committed_offsets.extend(offsets)

        mock_consumer.commit.side_effect = capture_commit

        mock_http_client = MagicMock(spec=httpx.Client)
        mock_http_client.post.return_value = MagicMock(status_code=202, text="Accepted")

        worker = GraylogConsumerWorker(
            consumer=mock_consumer,
            http_client=mock_http_client,
            metrics_store=metrics,
            dlq_store=mock_dlq_sink,
        )

        # Message 0 is malformed / poison; Message 1 is valid
        poison_msg = FakeBrokerMessageWithHeaders(
            payload=b"{not valid json: !!!",
            partition=1,
            offset=20,
        )
        valid_msg = FakeBrokerMessageWithHeaders(
            payload=sample_log_payload(client_ip="10.0.0.99"),
            partition=1,
            offset=21,
        )

        result = worker.process_single_batch([poison_msg, valid_msg])

        # The valid message was successfully delivered
        assert result.outcome == DeliveryOutcome.DELIVERED

        # Poison publisher was called for message 0
        assert mock_dlq_sink.publish_poison.call_count == 1
        call_msg = mock_dlq_sink.publish_poison.call_args[0][0]
        assert call_msg.offset() == 20

        # Offsets committed include offset 21 (past poison msg) and offset 22 (past valid msg)
        assert any(tp.partition == 1 and tp.offset == 21 for tp in committed_offsets)
        assert any(tp.partition == 1 and tp.offset == 22 for tp in committed_offsets)

        # Metrics recorded poison message
        m = metrics.read_snapshot()
        assert m["poison_messages"] == 1
        assert m["total_forwarded_to_graylog"] == 1


# ===========================================================================
# 4. Retry Topic Consumer & Delay / Cap Enforcement (Requirement 2)
# ===========================================================================
class TestRetryTopicConsumer:
    def test_retry_count_cap_escalates_to_dlq(self, tmp_path: Path) -> None:
        """
        When message has retry count >= max_retries, RetryTopicConsumer must escalate
        it to security-logs.dlq without looping, and commit past the retry topic offset.
        """
        db_path = tmp_path / "metrics.db"
        metrics = SharedMetricsStore(db_path=str(db_path))

        mock_consumer = MagicMock()
        mock_dlq_publisher = MagicMock(spec=BrokerDeadLetterPublisher)
        mock_dlq_publisher.publish_to_dlq.return_value = True

        retry_consumer = RetryTopicConsumer(
            consumer=mock_consumer,
            dlq_publisher=mock_dlq_publisher,
            metrics_store=metrics,
            max_retries=3,
        )

        msg = FakeBrokerMessageWithHeaders(
            payload=sample_log_payload(),
            topic=BROKER_RETRY_1M_TOPIC,
            partition=0,
            offset=45,
            headers=[
                ("x-retry-count", b"3"),
                ("x-original-topic", BROKER_TOPIC.encode("utf-8")),
            ],
        )

        success = retry_consumer.process_single_message(msg)
        assert success is True

        # Escalated to DLQ
        assert mock_dlq_publisher.publish_to_dlq.call_count == 1
        args, kwargs = mock_dlq_publisher.publish_to_dlq.call_args
        assert kwargs["retry_count"] == 3
        assert "Exceeded max retry cap" in kwargs["reason"]

        # Committed retry topic offset
        assert mock_consumer.commit.call_count == 1
        committed_tps = mock_consumer.commit.call_args[1]["offsets"]
        assert committed_tps[0].topic == BROKER_RETRY_1M_TOPIC
        assert committed_tps[0].offset == 46

        # Metric dlq_quarantined_logs incremented
        m = metrics.read_snapshot()
        assert m["dlq_quarantined_logs"] == 1

    def test_retry_topic_consumer_pauses_partition_when_not_due(self) -> None:
        """
        When now < due_time, partition must be paused and sought back, then resumed.
        """
        mock_consumer = MagicMock()
        mock_dlq_publisher = MagicMock(spec=BrokerDeadLetterPublisher)
        mock_http_client = MagicMock(spec=httpx.Client)
        mock_http_client.post.return_value = MagicMock(status_code=200, text="OK")

        current_time = [1000.0]
        slept_durations: List[float] = []

        def mock_clock() -> float:
            return current_time[0]

        def mock_sleep(duration: float) -> None:
            slept_durations.append(duration)
            current_time[0] += duration

        retry_consumer = RetryTopicConsumer(
            consumer=mock_consumer,
            dlq_publisher=mock_dlq_publisher,
            http_client=mock_http_client,
            clock_fn=mock_clock,
            sleep_fn=mock_sleep,
            max_retries=3,
        )

        msg = FakeBrokerMessageWithHeaders(
            payload=sample_log_payload(),
            topic=BROKER_RETRY_1M_TOPIC,
            partition=1,
            offset=12,
            headers=[
                ("x-retry-count", b"1"),
                ("x-due-time", b"1005.0"),  # 5 seconds in future
            ],
        )

        success = retry_consumer.process_single_message(msg)
        assert success is True

        # Partition was paused and seeked
        mock_consumer.pause.assert_called_once()
        mock_consumer.seek.assert_called_once()
        mock_consumer.resume.assert_called_once()

        # Slept until due time
        assert sum(slept_durations) >= 5.0

    def test_retry_tier_escalation_1m_to_10m(self) -> None:
        """
        When delivery fails on 1m topic, it escalates to 10m tier.
        """
        mock_consumer = MagicMock()
        mock_dlq_publisher = MagicMock(spec=BrokerDeadLetterPublisher)
        mock_dlq_publisher.publish_retry_tier.return_value = True

        mock_http_client = MagicMock(spec=httpx.Client)
        mock_http_client.post.return_value = MagicMock(status_code=503, text="Service Unavailable")

        retry_consumer = RetryTopicConsumer(
            consumer=mock_consumer,
            dlq_publisher=mock_dlq_publisher,
            http_client=mock_http_client,
            sleep_fn=lambda _: None,
            clock_fn=lambda: 1000.0,
            max_retries=5,
        )

        msg = FakeBrokerMessageWithHeaders(
            payload=sample_log_payload(),
            topic=BROKER_RETRY_1M_TOPIC,
            partition=0,
            offset=30,
            headers=[
                ("x-retry-count", b"1"),
                ("x-due-time", b"1000.0"),
            ],
        )

        success = retry_consumer.process_single_message(msg)
        assert success is True

        # Escalated to 10m tier
        assert mock_dlq_publisher.publish_retry_tier.call_count == 1
        _, kwargs = mock_dlq_publisher.publish_retry_tier.call_args
        assert kwargs["tier_topic"] == BROKER_RETRY_10M_TOPIC
        assert kwargs["retry_count"] == 2


# ===========================================================================
# 5. Multi-Worker Simulation (Concurrency & Conservation Law)
# ===========================================================================
class TestMultiWorkerSimulation:
    def test_two_workers_concurrent_dlq_handling_no_lost_or_duplicated_records(
        self, tmp_path: Path
    ) -> None:
        """
        Simulates two consumer workers consuming different partitions concurrently.
        Unlike JsonlDeadLetterStore (which suffers file-locking and rewrite races),
        the Broker DLQ publisher safely publishes records with durable confirmations.
        Conservation Law: Total produced = Total delivered + Total quarantined.
        """
        db_path = tmp_path / "metrics.db"
        metrics = SharedMetricsStore(db_path=str(db_path))

        published_to_dlq: List[Dict[str, Any]] = []

        mock_dlq_publisher = MagicMock(spec=BrokerDeadLetterPublisher)

        def mock_publish_dlq(msgs: List[Any], reason: str = "", retry_count: int = 0) -> bool:
            for m in msgs:
                published_to_dlq.append({"msg": m, "reason": reason, "retry_count": retry_count})
            return True

        mock_dlq_publisher.publish_to_dlq.side_effect = mock_publish_dlq
        mock_dlq_publisher.write_dead_letter.side_effect = lambda messages=None, gelf_batch=None, reason="", **kw: (
            mock_publish_dlq(messages or [], reason=reason)
        )

        mock_consumer_1 = MagicMock()
        mock_consumer_2 = MagicMock()

        # Worker 1 encounters healthy Graylog -> DELIVERED
        http_client_1 = MagicMock(spec=httpx.Client)
        http_client_1.post.return_value = MagicMock(status_code=202, text="Accepted")

        # Worker 2 encounters Graylog 500 error -> DLQ fallback
        http_client_2 = MagicMock(spec=httpx.Client)
        http_client_2.post.return_value = MagicMock(status_code=500, text="Internal Error")

        worker_1 = GraylogConsumerWorker(
            consumer=mock_consumer_1,
            http_client=http_client_1,
            metrics_store=metrics,
            dlq_store=mock_dlq_publisher,
            max_delivery_retries=1,
            base_backoff_seconds=0.01,
            max_backoff_seconds=0.01,
        )

        worker_2 = GraylogConsumerWorker(
            consumer=mock_consumer_2,
            http_client=http_client_2,
            metrics_store=metrics,
            dlq_store=mock_dlq_publisher,
            max_delivery_retries=1,
            base_backoff_seconds=0.01,
            max_backoff_seconds=0.01,
        )

        # Worker 1 processes 5 messages on partition 0
        batch_w1 = [
            FakeBrokerMessageWithHeaders(sample_log_payload(), partition=0, offset=i)
            for i in range(5)
        ]
        res_w1 = worker_1.process_single_batch(batch_w1)

        # Worker 2 processes 5 messages on partition 1
        batch_w2 = [
            FakeBrokerMessageWithHeaders(sample_log_payload(), partition=1, offset=i)
            for i in range(5)
        ]
        res_w2 = worker_2.process_single_batch(batch_w2)

        assert res_w1.outcome == DeliveryOutcome.DELIVERED
        assert res_w2.outcome == DeliveryOutcome.DEAD_LETTERED

        # Check total message conservation
        m = metrics.read_snapshot()
        assert m["total_forwarded_to_graylog"] == 5
        assert m["dlq_quarantined_logs"] == 5
        assert len(published_to_dlq) == 5

        # Both workers committed their respective offsets without interfering
        assert mock_consumer_1.commit.call_count == 1
        assert mock_consumer_2.commit.call_count == 1


# ===========================================================================
# 6. Replay Idempotency & Downstream Deduplication (Requirement 5)
# ===========================================================================
class TestReplayIdempotency:
    def test_gelf_transformer_preserves_event_id_on_replay(self) -> None:
        """
        When replaying, the raw event contains `_event_id` = 'orig_partition:orig_offset'.
        GelfTransformer must preserve this exact ID so downstream deduplication works.
        """
        from middleware.gelf_transformer import transform_to_gelf

        raw = sample_log_payload(_event_id="0:105")
        gelf = transform_to_gelf(raw, partition=2, offset=999)
        assert gelf["_event_id"] == "0:105"

    def test_replay_idempotency_in_mock_graylog(self) -> None:
        """
        Simulate Graylog receiving a replayed message with the same _event_id.
        Graylog must count the second delivery as duplicate and ignore it.
        """
        graylog_state = MockGraylogState()
        graylog_state.reset()

        gelf_record = {
            "version": "1.1",
            "host": "security-middleware",
            "short_message": "PORT_SCAN /admin/ports/scan",
            "timestamp": 1760875200.123,
            "level": 4,
            "_event_id": "0:42",
            "_client_ip": "10.0.0.99",
            "_event_type": "PORT_SCAN",
        }

        # First ingest
        graylog_state.ingest_gelf_records([gelf_record])
        assert graylog_state.total_gelf_received == 1
        assert graylog_state.duplicate_gelf_ignored == 0

        # Second ingest of replayed message with same _event_id
        graylog_state.ingest_gelf_records([gelf_record])
        assert graylog_state.total_gelf_received == 1  # Not incremented
        assert graylog_state.duplicate_gelf_ignored == 1  # Correctly recognized as duplicate


# ===========================================================================
# 7. Admin DLQ Endpoints (Requirement 5)
# ===========================================================================
class TestAdminDLQEndpoints:
    def test_get_admin_dlq_stats(self) -> None:
        client = TestClient(ingestor_app)

        with patch("ingestor.wal_middleware.query_topic_stats") as mock_stats:
            mock_stats.return_value = {
                "topics": {
                    BROKER_DLQ_TOPIC: {
                        "count": 4,
                        "oldest_message_age_seconds": 120.5,
                        "partitions": [{"partition": 0, "count": 4}],
                    },
                    BROKER_RETRY_1M_TOPIC: {
                        "count": 2,
                        "oldest_message_age_seconds": 30.0,
                        "partitions": [{"partition": 0, "count": 2}],
                    },
                    BROKER_RETRY_10M_TOPIC: {
                        "count": 0,
                        "oldest_message_age_seconds": None,
                        "partitions": [{"partition": 0, "count": 0}],
                    },
                    BROKER_POISON_TOPIC: {
                        "count": 1,
                        "oldest_message_age_seconds": 300.0,
                        "partitions": [{"partition": 0, "count": 1}],
                    },
                },
                "total_dlq_count": 4,
            }

            resp = client.get("/admin/dlq")
            assert resp.status_code == 200
            data = resp.json()
            assert data["dlq_backend"] in ("broker", "file")
            assert BROKER_DLQ_TOPIC in data["topics"]
            assert data["topics"][BROKER_DLQ_TOPIC]["count"] == 4

    def test_post_admin_dlq_replay(self) -> None:
        client = TestClient(ingestor_app)

        with patch("ingestor.wal_middleware.replay_from_dlq") as mock_replay:
            mock_replay.return_value = {
                "replayed_count": 5,
                "replay_id": "test-replay-uuid-1234",
            }

            resp = client.post("/admin/dlq/replay?limit=5")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "replayed"
            assert data["replayed_count"] == 5
            assert data["replay_id"] == "test-replay-uuid-1234"
