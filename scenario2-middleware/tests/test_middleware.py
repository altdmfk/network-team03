import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import httpx
import pytest
from middleware.lightweight_broker import TopicPartition
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
import consumer_worker
import ingestor
import mock_graylog_server
from consumer_worker import (
    DeliveryOutcome,
    GraylogConsumerWorker,
    GraylogDeliveryClient,
    RetryPolicy,
    TokenBucketRateLimiter,
    transform_to_gelf,
)
from ingestor import WalLogBufferingMiddleware, SecurityLogEvent
from metrics_store import SharedMetricsStore


# ---------------------------------------------------------------------------
# Helpers & Mock Factories
# ---------------------------------------------------------------------------
class FakeBrokerMessage:
    """Lightweight mock of Broker Message for deterministic unit tests."""

    def __init__(
        self,
        payload: Dict[str, Any],
        key: str = "10.0.0.99",
        partition: int = 0,
        offset: int = 1,
        error: Optional[Any] = None,
        topic: str = config.BROKER_TOPIC,
    ) -> None:
        self._value = json.dumps(payload).encode("utf-8")
        self._key = key.encode("utf-8")
        self._partition = partition
        self._offset = offset
        self._error = error
        self._topic = topic

    def topic(self) -> str:
        return self._topic

    def value(self) -> bytes:
        return self._value

    def key(self) -> bytes:
        return self._key

    def partition(self) -> int:
        return self._partition

    def offset(self) -> int:
        return self._offset

    def error(self) -> Optional[Any]:
        return self._error


def sample_event_dict(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
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
# 1. Schema & Timestamp Normalization Tests (`SecurityLogEvent`)
# ===========================================================================
class TestSecurityLogEventSchema:
    def test_timestamp_normalization_epoch_seconds(self) -> None:
        ev = SecurityLogEvent(**sample_event_dict(timestamp=1760875200.1239))
        assert isinstance(ev.timestamp, float)
        assert ev.timestamp == 1760875200.124

    def test_timestamp_normalization_epoch_milliseconds(self) -> None:
        # > 1e11 is treated as epoch milliseconds and converted to seconds.ms
        ev = SecurityLogEvent(**sample_event_dict(timestamp=1760875200123))
        assert isinstance(ev.timestamp, float)
        assert ev.timestamp == 1760875200.123

        ev_str_ms = SecurityLogEvent(**sample_event_dict(timestamp="1760875200456"))
        assert ev_str_ms.timestamp == 1760875200.456

    def test_timestamp_normalization_iso8601_and_timezone_offsets(self) -> None:
        expected_epoch = datetime(
            2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc
        ).timestamp()

        ev_utc_z = SecurityLogEvent(
            **sample_event_dict(timestamp="2026-10-19T12:00:00Z")
        )
        assert ev_utc_z.timestamp == round(expected_epoch, 3)

        # +09:00 offset corresponding to the exact same UTC instant (2026-10-19T21:00:00+09:00)
        ev_kst = SecurityLogEvent(
            **sample_event_dict(timestamp="2026-10-19T21:00:00.250+09:00")
        )
        assert ev_kst.timestamp == round(expected_epoch + 0.250, 3)

    def test_event_type_uppercased_and_stripped(self) -> None:
        ev = SecurityLogEvent(
            **sample_event_dict(
                client_ip="  192.168.1.50  ",
                event_type="  honeytoken_access \n",
                target_resource="  /api/v1/secrets  ",
            )
        )
        assert ev.event_type == "HONEYTOKEN_ACCESS"
        assert ev.client_ip == "192.168.1.50"
        assert ev.target_resource == "/api/v1/secrets"

    @pytest.mark.parametrize("bad_severity", [-1, 8, 99])
    def test_invalid_severity_raises_validation_error(self, bad_severity: int) -> None:
        with pytest.raises(ValidationError):
            SecurityLogEvent(**sample_event_dict(severity=bad_severity))

    @pytest.mark.parametrize("bad_status", [-1, 1000, 5000])
    def test_invalid_status_code_raises_validation_error(self, bad_status: int) -> None:
        with pytest.raises(ValidationError):
            SecurityLogEvent(**sample_event_dict(status_code=bad_status))

    @pytest.mark.parametrize("bad_ip", ["", "   ", "1"])
    def test_empty_or_short_client_ip_raises_validation_error(
        self, bad_ip: str
    ) -> None:
        with pytest.raises(ValidationError):
            SecurityLogEvent(**sample_event_dict(client_ip=bad_ip))

    def test_extra_forbidden_fields_and_invalid_timestamp_raise_validation_error(
        self,
    ) -> None:
        with pytest.raises(ValidationError):
            SecurityLogEvent(**sample_event_dict(unexpected_field="malicious"))

        with pytest.raises(ValidationError):
            SecurityLogEvent(**sample_event_dict(timestamp="not-a-timestamp"))


# ===========================================================================
# 2. Partition Key & Producer Backpressure Tests (`WalLogBufferingMiddleware`)
# ===========================================================================
class TestWalLogBufferingMiddleware:
    def test_enqueue_event_partition_key_and_timestamp_ms(
        self, tmp_path: Path
    ) -> None:
        db_file = str(tmp_path / "metrics.db")
        with SharedMetricsStore(db_file) as store:
            middleware = WalLogBufferingMiddleware(
                store, max_buffer_retries=5, buffer_retry_sleep=0.0
            )
            mock_producer = MagicMock()
            middleware.producer = mock_producer

            event = SecurityLogEvent(
                **sample_event_dict(
                    timestamp=1760875200.123,
                    client_ip="10.0.0.99",
                    event_type="BRUTE_FORCE",
                    raw_payload={
                        "api_key": "leaked_secret_key_12345",
                        "session_token": "sess_abcdef123456",
                        "user": "attacker",
                    },
                )
            )
            middleware.enqueue_event(event)

            mock_producer.produce.assert_called_once()
            call_kwargs = mock_producer.produce.call_args.kwargs
            assert call_kwargs["topic"] == config.BROKER_TOPIC
            assert call_kwargs["key"] == b"10.0.0.99"
            assert call_kwargs["timestamp"] == int(round(event.timestamp * 1000))
            assert call_kwargs["on_delivery"] == middleware._delivery_callback
            mock_producer.poll.assert_called_once_with(0)

            # Assert PII/secret redaction before publishing to Broker
            sent_val = json.loads(call_kwargs["value"].decode("utf-8"))
            assert sent_val["raw_payload"]["api_key"] == "[REDACTED]"
            assert sent_val["raw_payload"]["session_token"] == "[REDACTED]"
            assert sent_val["raw_payload"]["user"] == "attacker"

    def test_enqueue_event_recovers_from_transient_buffer_error(
        self, tmp_path: Path
    ) -> None:
        db_file = str(tmp_path / "metrics.db")
        with SharedMetricsStore(db_file) as store:
            middleware = WalLogBufferingMiddleware(
                store, max_buffer_retries=5, buffer_retry_sleep=0.0
            )
            mock_producer = MagicMock()
            # Fail twice with BufferError, succeed on 3rd attempt
            mock_producer.produce.side_effect = [
                BufferError("Local queue full #1"),
                BufferError("Local queue full #2"),
                None,
            ]
            middleware.producer = mock_producer

            event = SecurityLogEvent(**sample_event_dict())
            middleware.enqueue_event(event)

            assert mock_producer.produce.call_count == 3
            snapshot = store.read_snapshot()
            assert snapshot["dropped_logs"] == 0

    def test_enqueue_event_exhausts_buffer_error_and_raises_503(
        self, tmp_path: Path
    ) -> None:
        db_file = str(tmp_path / "metrics.db")
        with SharedMetricsStore(db_file) as store:
            middleware = WalLogBufferingMiddleware(
                store, max_buffer_retries=4, buffer_retry_sleep=0.0
            )
            mock_producer = MagicMock()
            mock_producer.produce.side_effect = BufferError(
                "Permanent local buffer saturation"
            )
            middleware.producer = mock_producer

            event = SecurityLogEvent(**sample_event_dict())
            with pytest.raises(HTTPException) as exc_info:
                middleware.enqueue_event(event)

            assert exc_info.value.status_code == 503
            assert mock_producer.produce.call_count == 4
            snapshot = store.read_snapshot()
            assert snapshot["dropped_logs"] == 1

    @pytest.mark.asyncio
    async def test_enqueue_event_async_yields_to_event_loop_on_buffer_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db_file = str(tmp_path / "metrics_async.db")
        sleep_calls: List[float] = []

        async def fake_async_sleep(delay: float) -> None:
            sleep_calls.append(delay)

        monkeypatch.setattr(ingestor.asyncio, "sleep", fake_async_sleep)

        with SharedMetricsStore(db_file) as store:
            middleware = WalLogBufferingMiddleware(
                store, max_buffer_retries=4, buffer_retry_sleep=0.02
            )
            mock_producer = MagicMock()
            mock_producer.produce.side_effect = [
                BufferError("Buffer full #1"),
                BufferError("Buffer full #2"),
                None,
            ]
            middleware.producer = mock_producer

            event = SecurityLogEvent(**sample_event_dict())
            await middleware.enqueue_event_async(event)

            assert mock_producer.produce.call_count == 3
            assert sleep_calls == [0.02, 0.02]
            assert store.read_snapshot()["dropped_logs"] == 0


# ===========================================================================
# 3. GELF 1.1 Transformation & Timestamp Preservation Tests (`transform_to_gelf`)
# ===========================================================================
class TestGelfTransformation:
    def test_transform_to_gelf_format_and_timestamp_preservation(self) -> None:
        historic_timestamp = 1700000000.789
        raw_event = sample_event_dict(
            timestamp=historic_timestamp,
            client_ip="172.16.42.108",
            event_type="HONEYTOKEN_ACCESS",
            target_resource="/api/v1/admin/honeytoken_admin/secrets",
            status_code=403,
            severity=1,
            raw_payload={"account": "honeytoken_admin", "trap": True},
        )

        gelf = transform_to_gelf(raw_event, partition=2, offset=42)

        assert gelf["version"] == "1.1"
        assert gelf["host"] == config.GELF_HOST
        assert (
            gelf["short_message"]
            == "[HONEYTOKEN_ACCESS] 172.16.42.108 -> /api/v1/admin/honeytoken_admin/secrets (403)"
        )
        assert gelf["timestamp"] == historic_timestamp
        assert gelf["level"] == 1
        assert gelf["_client_ip"] == "172.16.42.108"
        assert gelf["_event_type"] == "HONEYTOKEN_ACCESS"
        assert gelf["_target_resource"] == "/api/v1/admin/honeytoken_admin/secrets"
        assert gelf["_status_code"] == 403
        assert gelf["_honeytoken_alert"] is True
        assert gelf["_broker_partition"] == 2
        assert gelf["_broker_offset"] == 42
        assert json.loads(gelf["_raw_payload"]) == {
            "account": "honeytoken_admin",
            "trap": True,
        }

    def test_transform_to_gelf_non_honeytoken_event(self) -> None:
        raw_event = sample_event_dict(
            timestamp=1760875000.555,
            event_type="PORT_SCAN",
        )
        gelf = transform_to_gelf(raw_event, partition=0, offset=10)
        assert gelf["version"] == "1.1"
        assert gelf["_honeytoken_alert"] is False
        assert gelf["timestamp"] == 1760875000.555


# ===========================================================================
# 4. Token-Bucket Rate Limiter Tests (`TokenBucketRateLimiter`)
# ===========================================================================
class TestTokenBucketRateLimiter:
    def test_invalid_rate_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            TokenBucketRateLimiter(rate_per_sec=0)
        with pytest.raises(ValueError):
            TokenBucketRateLimiter(rate_per_sec=-2.5)

    def test_token_consumption_and_sleep_calculation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_clock = [100.0]
        slept_durations: List[float] = []

        def fake_monotonic() -> float:
            return fake_clock[0]

        def fake_sleep(seconds: float) -> None:
            slept_durations.append(seconds)
            fake_clock[0] += seconds

        monkeypatch.setattr(consumer_worker.time, "monotonic", fake_monotonic)
        monkeypatch.setattr(consumer_worker.time, "sleep", fake_sleep)

        # 5 batches/sec (0.2s per token), capacity=1.0
        limiter = TokenBucketRateLimiter(rate_per_sec=5.0, capacity=1.0)

        # 1st batch: bucket starts full (1.0 token) -> immediate acquisition
        slept_1 = limiter.acquire(1.0)
        assert slept_1 == 0.0
        assert slept_durations == []
        assert limiter.tokens == 0.0

        # 2nd batch immediately (0s elapsed): 1.0 token deficit at 5.0/sec -> sleeps 0.2s
        slept_2 = limiter.acquire(1.0)
        assert pytest.approx(slept_2, rel=1e-6) == 0.2
        assert len(slept_durations) == 1
        assert pytest.approx(slept_durations[0], rel=1e-6) == 0.2

        # Advance clock by 0.1s (refills 0.5 tokens), then acquire 1.0 -> sleeps 0.1s
        fake_clock[0] += 0.1
        slept_3 = limiter.acquire(1.0)
        assert pytest.approx(slept_3, rel=1e-6) == 0.1

    def test_log_unit_rate_limiting_full_and_partial_batches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_clock = [200.0]
        slept_durations: List[float] = []

        def fake_monotonic() -> float:
            return fake_clock[0]

        def fake_sleep(seconds: float) -> None:
            slept_durations.append(seconds)
            fake_clock[0] += seconds

        monkeypatch.setattr(consumer_worker.time, "monotonic", fake_monotonic)
        monkeypatch.setattr(consumer_worker.time, "sleep", fake_sleep)

        # 500 logs/sec, initial_tokens=100.0 (BATCH_SIZE=100)
        limiter = TokenBucketRateLimiter(
            rate_per_sec=500.0, capacity=200.0, initial_tokens=100.0
        )

        # 1st batch of 100 logs consumes initial 100 tokens immediately
        assert limiter.acquire(100.0) == 0.0
        assert slept_durations == []

        # 2nd batch of 100 logs at 500 logs/sec sleeps 0.20s
        slept_full = limiter.acquire(100.0)
        assert pytest.approx(slept_full, rel=1e-6) == 0.20

        # Partial batch of 25 logs at 500 logs/sec sleeps 0.05s
        slept_partial = limiter.acquire(25.0)
        assert pytest.approx(slept_partial, rel=1e-6) == 0.05


# ===========================================================================
# 5. Consumer Retry, Backoff, Offset Commit & Dead-Letter Tests (`GraylogConsumerWorker`)
# ===========================================================================
class TestGraylogConsumerWorker:
    def test_success_path_commits_offset_and_increments_forwarded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db_file = str(tmp_path / "metrics.db")
        dlq_file = str(tmp_path / "dead_letter_logs.jsonl")
        monkeypatch.setattr(consumer_worker.time, "sleep", lambda _s: None)

        batch_messages = [
            FakeBrokerMessage(sample_event_dict(event_type="PORT_SCAN"), offset=1),
            FakeBrokerMessage(
                sample_event_dict(event_type="HONEYTOKEN_ACCESS"), offset=2
            ),
        ]

        with SharedMetricsStore(db_file) as store:
            with GraylogConsumerWorker(
                metrics_store=store,
                dead_letter_file=dlq_file,
                max_delivery_retries=3,
            ) as worker:
                mock_consumer = MagicMock()
                poll_counter = [0]

                def consume_side_effect(*_args: Any, **_kwargs: Any) -> List[Any]:
                    poll_counter[0] += 1
                    if poll_counter[0] == 1:
                        return batch_messages
                    worker.running = False
                    return []

                mock_consumer.consume.side_effect = consume_side_effect
                worker.consumer = mock_consumer

                mock_post = MagicMock(
                    return_value=httpx.Response(
                        status_code=202, json={"status": "accepted"}
                    )
                )
                monkeypatch.setattr(worker.http_client, "post", mock_post)

                worker.run()

                mock_post.assert_called_once()
                mock_consumer.commit.assert_called_once_with(
                    offsets=[TopicPartition(config.BROKER_TOPIC, 0, 3)],
                    asynchronous=False,
                )

            snapshot = store.read_snapshot()
            assert snapshot["total_forwarded_to_graylog"] == 2
            assert snapshot["dropped_logs"] == 0
            assert not Path(dlq_file).exists()

    def test_transient_outage_recovery_with_backoff_and_delayed_commit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db_file = str(tmp_path / "metrics.db")
        dlq_file = str(tmp_path / "dead_letter_logs.jsonl")

        sleep_calls: List[float] = []
        monkeypatch.setattr(
            consumer_worker.time, "sleep", lambda s: sleep_calls.append(s)
        )

        batch_messages = [
            FakeBrokerMessage(
                sample_event_dict(event_type="PORT_SCAN"), partition=0, offset=10
            ),
            FakeBrokerMessage(
                sample_event_dict(event_type="BRUTE_FORCE"), partition=0, offset=11
            ),
            FakeBrokerMessage(
                sample_event_dict(event_type="IOT_CONTROL"), partition=1, offset=4
            ),
        ]

        with SharedMetricsStore(db_file) as store:
            with GraylogConsumerWorker(
                metrics_store=store,
                dead_letter_file=dlq_file,
                max_delivery_retries=0,
                base_backoff_seconds=1.0,
            ) as worker:
                mock_consumer = MagicMock()

                # Consume returns the batch on first poll, then stops worker on next poll
                poll_counter = [0]

                def consume_side_effect(*_args: Any, **_kwargs: Any) -> List[Any]:
                    poll_counter[0] += 1
                    if poll_counter[0] == 1:
                        return batch_messages
                    worker.running = False
                    return []

                mock_consumer.consume.side_effect = consume_side_effect
                worker.consumer = mock_consumer

                commit_counts_during_post: List[int] = []
                responses = [
                    httpx.Response(status_code=503, text="Service Unavailable #1"),
                    httpx.Response(status_code=503, text="Service Unavailable #2"),
                    httpx.Response(status_code=202, json={"status": "accepted"}),
                ]

                def post_side_effect(*_args: Any, **_kwargs: Any) -> httpx.Response:
                    commit_counts_during_post.append(mock_consumer.commit.call_count)
                    return responses.pop(0)

                monkeypatch.setattr(worker.http_client, "post", post_side_effect)

                worker.run()

                # Offsets must NOT be committed during the first two 503 failures
                assert commit_counts_during_post == [0, 0, 0]
                # consumer.poll() must NEVER be called during backoff sleep (prevents silent log drops)
                mock_consumer.poll.assert_not_called()
                # Exponential backoff sleep must have been triggered during the two 503s
                assert len(sleep_calls) > 0
                # Explicit TopicPartition offsets (offset + 1 per partition) ARE committed once HTTP 202 succeeds
                mock_consumer.commit.assert_called_once_with(
                    offsets=[
                        TopicPartition(config.BROKER_TOPIC, 0, 12),
                        TopicPartition(config.BROKER_TOPIC, 1, 5),
                    ],
                    asynchronous=False,
                )

            snapshot = store.read_snapshot()
            assert snapshot["total_forwarded_to_graylog"] == 3
            assert snapshot["dropped_logs"] == 0

    def test_dead_letter_fallback_writes_jsonl_and_increments_dropped_not_forwarded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db_file = str(tmp_path / "metrics.db")
        dlq_file = tmp_path / "dead_letter_logs.jsonl"

        monkeypatch.setattr(consumer_worker.time, "sleep", lambda _s: None)
        monkeypatch.setattr(consumer_worker, "MAX_DELIVERY_RETRIES", 3)
        monkeypatch.setattr(consumer_worker, "DEAD_LETTER_FILE", str(dlq_file))

        batch_messages = [
            FakeBrokerMessage(sample_event_dict(event_type="PORT_SCAN"), offset=101),
            FakeBrokerMessage(sample_event_dict(event_type="BRUTE_FORCE"), offset=102),
        ]

        with SharedMetricsStore(db_file) as store:
            with GraylogConsumerWorker(metrics_store=store) as worker:
                mock_consumer = MagicMock()
                poll_counter = [0]

                def consume_side_effect(*_args: Any, **_kwargs: Any) -> List[Any]:
                    poll_counter[0] += 1
                    if poll_counter[0] == 1:
                        return batch_messages
                    worker.running = False
                    return []

                mock_consumer.consume.side_effect = consume_side_effect
                worker.consumer = mock_consumer

                mock_post = MagicMock(
                    return_value=httpx.Response(
                        status_code=503, text="Persistent Graylog Outage"
                    )
                )
                monkeypatch.setattr(worker.http_client, "post", mock_post)

                worker.run()

                # Attempted 3 times before falling back to Dead Letter File
                assert mock_post.call_count == 3
                mock_consumer.poll.assert_not_called()
                # Offset committed so poison/undeliverable batch does not block consumer forever
                mock_consumer.commit.assert_called_once_with(
                    offsets=[TopicPartition(config.BROKER_TOPIC, 0, 103)],
                    asynchronous=False,
                )

            snapshot = store.read_snapshot()
            assert snapshot["dropped_logs"] == 2
            assert snapshot["total_forwarded_to_graylog"] == 0

            assert dlq_file.exists()
            dlq_lines = [
                json.loads(line)
                for line in dlq_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            assert len(dlq_lines) == 2
            assert dlq_lines[0]["_broker_offset"] == 101
            assert dlq_lines[0]["_event_id"] == "0:101"
            assert dlq_lines[1]["_broker_offset"] == 102
            assert dlq_lines[1]["_event_id"] == "0:102"

    def test_dlq_auto_replay_recovers_dropped_logs_to_zero_loss(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db_file = str(tmp_path / "metrics_dlq_replay.db")
        dlq_file = tmp_path / "dead_letter_logs.jsonl"
        monkeypatch.setattr(consumer_worker.time, "sleep", lambda _s: None)

        batch_messages = [
            FakeBrokerMessage(sample_event_dict(event_type="PORT_SCAN"), offset=50),
            FakeBrokerMessage(sample_event_dict(event_type="BRUTE_FORCE"), offset=51),
        ]

        with SharedMetricsStore(db_file) as store:
            store.increment_received(2, flush=True)
            with GraylogConsumerWorker(
                metrics_store=store,
                dead_letter_file=str(dlq_file),
                max_delivery_retries=2,
            ) as worker:
                mock_consumer = MagicMock()
                poll_counter = [0]

                def consume_side_effect(*_args: Any, **_kwargs: Any) -> List[Any]:
                    poll_counter[0] += 1
                    if poll_counter[0] == 1:
                        return batch_messages
                    worker.running = False
                    return []

                mock_consumer.consume.side_effect = consume_side_effect
                worker.consumer = mock_consumer

                # Phase 1: Outage exhausts MAX_DELIVERY_RETRIES=2 -> writes to DLQ
                monkeypatch.setattr(
                    worker.http_client,
                    "post",
                    MagicMock(
                        return_value=httpx.Response(status_code=503, text="Outage")
                    ),
                )
                worker.run()

                mid_snapshot = store.read_snapshot()
                assert mid_snapshot["dropped_logs"] == 2
                assert mid_snapshot["total_forwarded_to_graylog"] == 0
                assert mid_snapshot["dlq_replayed_logs"] == 0
                assert dlq_file.exists()

                # Phase 2: Graylog recovers (HTTP 202) -> _replay_dead_letter_file() replays DLQ
                worker.running = True
                replay_post = MagicMock(
                    return_value=httpx.Response(
                        status_code=202, json={"status": "accepted"}
                    )
                )
                monkeypatch.setattr(worker.http_client, "post", replay_post)

                replayed = worker._replay_dead_letter_file()
                assert replayed == 2
                replay_post.assert_called_once()
                assert not dlq_file.exists()

                final_snapshot = store.read_snapshot()
                assert final_snapshot["total_received"] == 2
                assert final_snapshot["total_forwarded_to_graylog"] == 2
                assert final_snapshot["dlq_replayed_logs"] == 2
                assert final_snapshot["dropped_logs"] == 0

    def test_micro_batch_accumulation_respects_batch_size_and_linger(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db_file = str(tmp_path / "micro_batch.db")
        fake_clock = [500.0]

        def fake_monotonic() -> float:
            return fake_clock[0]

        monkeypatch.setattr(consumer_worker.time, "monotonic", fake_monotonic)

        with SharedMetricsStore(db_file) as store:
            with GraylogConsumerWorker(
                metrics_store=store,
                batch_size=4,
                batch_linger_ms=100,
                poll_timeout=0.05,
            ) as worker:
                mock_consumer = MagicMock()
                calls = [0]

                def consume_chunks(
                    num_messages: int, timeout: float
                ) -> List[FakeBrokerMessage]:
                    calls[0] += 1
                    fake_clock[0] += 0.03  # 30ms per poll (< 100ms linger)
                    if calls[0] == 1:
                        return [
                            FakeBrokerMessage(sample_event_dict(), offset=1),
                            FakeBrokerMessage(sample_event_dict(), offset=2),
                        ]
                    if calls[0] == 2:
                        assert num_messages == 2
                        return [
                            FakeBrokerMessage(sample_event_dict(), offset=3),
                            FakeBrokerMessage(sample_event_dict(), offset=4),
                        ]
                    return []

                mock_consumer.consume.side_effect = consume_chunks
                worker.consumer = mock_consumer

                polled = worker._poll_batch()
                assert len(polled) == 4
                assert [m.offset() for m in polled] == [1, 2, 3, 4]

    def test_deliver_batch_returns_explicit_delivery_outcome_enum(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(consumer_worker.time, "sleep", lambda _s: None)
        db_file = str(tmp_path / "metrics.db")
        dlq_file = str(tmp_path / "dlq.jsonl")

        with SharedMetricsStore(db_file) as store:
            with GraylogConsumerWorker(
                metrics_store=store,
                dead_letter_file=dlq_file,
                max_delivery_retries=2,
            ) as worker:
                gelf_batch = [transform_to_gelf(sample_event_dict(), 0, 1)]

                monkeypatch.setattr(
                    worker.http_client,
                    "post",
                    lambda *_a, **_kw: httpx.Response(status_code=202),
                )
                assert (
                    worker._deliver_batch_with_backoff(gelf_batch)
                    is DeliveryOutcome.DELIVERED
                )

                monkeypatch.setattr(
                    worker.http_client,
                    "post",
                    lambda *_a, **_kw: httpx.Response(status_code=503),
                )
                assert (
                    worker._deliver_batch_with_backoff(gelf_batch)
                    is DeliveryOutcome.DEAD_LETTERED
                )

                worker.running = False
                assert (
                    worker._deliver_batch_with_backoff(gelf_batch)
                    is DeliveryOutcome.ABORTED
                )

    def test_deliver_batch_split_post_concurrent_delivery(
        self, tmp_path: Path
    ) -> None:
        calls = []

        def mock_post(url: str, **kwargs: Any) -> httpx.Response:
            calls.append(kwargs)
            return httpx.Response(status_code=202)

        client = GraylogDeliveryClient(split_post=True)
        gelf_batch = [
            transform_to_gelf(sample_event_dict(), 0, 1),
            transform_to_gelf(sample_event_dict(), 0, 2),
            transform_to_gelf(sample_event_dict(), 0, 3),
        ]
        mock_http = MagicMock()
        mock_http.post.side_effect = mock_post

        outcome = client.deliver_batch(
            gelf_batch=gelf_batch,
            http_client=mock_http,
            gelf_url="http://mock-graylog/gelf",
            retry_policy=RetryPolicy(
                max_retries=1,
                base_backoff_seconds=0.01,
                max_backoff_seconds=0.1,
            ),
            dry_run=False,
            is_running_fn=lambda: True,
            on_dead_letter=lambda *a, **k: True,
        )
        assert outcome is DeliveryOutcome.DELIVERED
        assert len(calls) == 3
        for c in calls:
            assert "json" in c
            assert c["json"]["short_message"] is not None

    def test_context_manager_deterministic_cleanup(self, tmp_path: Path) -> None:
        db_file = str(tmp_path / "cleanup.db")
        mock_consumer = MagicMock()
        mock_http = MagicMock()

        with GraylogConsumerWorker(db_path=db_file) as worker:
            worker.consumer = mock_consumer
            worker.http_client = mock_http
            conn = worker.metrics._get_connection()
            assert conn is worker.metrics._get_connection()

        mock_http.close.assert_called_once()
        mock_consumer.close.assert_called_once()
        assert worker.consumer is None
        assert len(worker.metrics._connections) == 0


# ===========================================================================
# 6. FastAPI Endpoint & Mock Graylog Integration Tests (`TestClient`)
# ===========================================================================
class TestFastAPIEndpointsAndMockGraylog:
    def test_ingestor_endpoints_with_mocked_broker(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db_file = str(tmp_path / "ingestor_test.db")
        test_store = SharedMetricsStore(db_file)
        test_middleware = WalLogBufferingMiddleware(
            test_store, max_buffer_retries=3, buffer_retry_sleep=0.0
        )

        mock_producer = MagicMock()
        mock_producer.__len__.return_value = 0

        def produce_with_ack(**kwargs: Any) -> None:
            on_delivery = kwargs.get("on_delivery")
            if on_delivery is not None:
                on_delivery(None, MagicMock())

        mock_producer.produce.side_effect = produce_with_ack
        test_middleware.producer = mock_producer

        lag_state = {
            "broker_total_messages": 4,
            "consumer_committed_total": 1,
            "broker_queue_lag": 3,
            "in_flight_producer_queue": 0,
            "partitions": [
                {
                    "partition": 0,
                    "low_watermark": 0,
                    "high_watermark": 4,
                    "committed_offset": 1,
                    "lag": 3,
                }
            ],
        }

        monkeypatch.setattr(ingestor, "metrics_store", test_store)
        monkeypatch.setattr(ingestor, "wal_middleware", test_middleware)
        monkeypatch.setattr(test_middleware, "start", lambda: None)
        monkeypatch.setattr(
            test_middleware, "stop", lambda: test_middleware.flush_metrics()
        )
        monkeypatch.setattr(
            test_middleware,
            "query_broker_native_lag",
            lambda: lag_state,
        )

        with TestClient(ingestor.app) as client:
            # 1. GET /health
            health_resp = client.get("/health")
            assert health_resp.status_code == 200
            assert health_resp.json()["status"] == "healthy"

            # 2. POST /ingest (single event)
            single_resp = client.post("/ingest", json=sample_event_dict())
            assert single_resp.status_code == 202
            single_data = single_resp.json()
            assert single_data["accepted"] == 1
            assert single_data["partition_key"] == "10.0.0.99"
            assert single_data["total_received"] == 1

            # 3. POST /ingest/batch (wrapped {"logs": [...]} and raw list [...])
            batch_resp = client.post(
                "/ingest/batch",
                json={
                    "logs": [
                        sample_event_dict(event_type="BRUTE_FORCE"),
                        sample_event_dict(event_type="IOT_CONTROL"),
                    ]
                },
            )
            assert batch_resp.status_code == 202
            assert batch_resp.json()["accepted"] == 2
            assert batch_resp.json()["total_received"] == 3

            raw_list_resp = client.post(
                "/ingest/batch",
                json=[sample_event_dict(event_type="HONEYTOKEN_ACCESS")],
            )
            assert raw_list_resp.status_code == 202
            assert raw_list_resp.json()["accepted"] == 1
            assert raw_list_resp.json()["total_received"] == 4

            # 4. GET /metrics (verifies peak_queue_lag, throughput_telemetry, and broker_telemetry)
            test_store.increment_forwarded(1, flush=True)
            metrics_resp = client.get("/metrics")
            assert metrics_resp.status_code == 200
            m_data = metrics_resp.json()
            assert m_data["total_received"] == 4
            assert m_data["total_forwarded_to_graylog"] == 1
            assert m_data["current_queue_lag"] == 3
            assert m_data["peak_queue_lag"] == 3
            assert m_data["dropped_logs"] == 0
            assert m_data["dlq_replayed_logs"] == 0
            assert "throughput_telemetry" in m_data
            assert m_data["throughput_telemetry"]["inbound_eps"] >= 4.0
            assert m_data["throughput_telemetry"]["peak_inbound_eps"] >= 4.0
            assert "broker_telemetry" in m_data
            assert m_data["broker_telemetry"]["total_broker_acked"] == 4
            assert (
                m_data["broker_telemetry"]["consumer_group"] == "graylog-shipper-group"
            )

            # Verify peak_queue_lag remains at high-water mark (3) even after current_queue_lag drains to 0
            lag_state["consumer_committed_total"] = 4
            lag_state["broker_queue_lag"] = 0
            test_store.increment_forwarded(3, flush=True)
            drained_resp = client.get("/metrics")
            drained_data = drained_resp.json()
            assert drained_data["current_queue_lag"] == 0
            assert drained_data["peak_queue_lag"] == 3
            assert drained_data["throughput_telemetry"]["outbound_eps"] >= 4.0

            # 5. POST /metrics/reset resets all counters, peak lag, and EPS back to 0
            reset_resp = client.post("/metrics/reset")
            assert reset_resp.status_code == 200
            assert reset_resp.json() == {"status": "reset"}

            after_reset = client.get("/metrics").json()
            assert after_reset["total_received"] == 0
            assert after_reset["total_forwarded_to_graylog"] == 0
            assert after_reset["current_queue_lag"] == 0
            assert after_reset["peak_queue_lag"] == 0
            assert after_reset["dropped_logs"] == 0
            assert after_reset["dlq_replayed_logs"] == 0
            assert after_reset["throughput_telemetry"]["inbound_eps"] == 0.0
            assert after_reset["throughput_telemetry"]["outbound_eps"] == 0.0

        test_store.close()

    def test_mock_graylog_server_outage_and_kill_chain_verification(self) -> None:
        with TestClient(mock_graylog_server.app) as client:
            reset_resp = client.post("/reset")
            assert reset_resp.status_code == 200

            # 1. Enable HTTP 503 simulated outage
            on_resp = client.post("/outage/on")
            assert on_resp.status_code == 200
            assert on_resp.json()["outage_mode"] is True

            # Verify /gelf returns 503 during outage
            step1_gelf = transform_to_gelf(
                sample_event_dict(
                    timestamp=1760875200.100,
                    client_ip="10.0.0.99",
                    event_type="PORT_SCAN",
                ),
                partition=1,
                offset=0,
            )
            outage_gelf_resp = client.post(
                "/gelf", content=json.dumps(step1_gelf).encode("utf-8")
            )
            assert outage_gelf_resp.status_code == 503
            assert outage_gelf_resp.json()["rejected_503_batches"] == 1

            # 2. Disable HTTP 503 simulated outage
            off_resp = client.post("/outage/off")
            assert off_resp.status_code == 200
            assert off_resp.json()["outage_mode"] is False

            # 3. Send Kill-Chain sequence for 10.0.0.99 + Honeytoken alert as NDJSON batch
            step2_gelf = transform_to_gelf(
                sample_event_dict(
                    timestamp=1760875200.200,
                    client_ip="10.0.0.99",
                    event_type="BRUTE_FORCE",
                ),
                partition=1,
                offset=1,
            )
            step3_gelf = transform_to_gelf(
                sample_event_dict(
                    timestamp=1760875200.300,
                    client_ip="10.0.0.99",
                    event_type="IOT_CONTROL",
                ),
                partition=1,
                offset=2,
            )
            honeytoken_gelf = transform_to_gelf(
                sample_event_dict(
                    timestamp=1760875200.400,
                    client_ip="172.16.42.108",
                    event_type="HONEYTOKEN_ACCESS",
                ),
                partition=2,
                offset=0,
            )

            ndjson_body = "\n".join(
                json.dumps(item)
                for item in (step1_gelf, step2_gelf, step3_gelf, honeytoken_gelf)
            )
            ok_resp = client.post("/gelf", content=ndjson_body.encode("utf-8"))
            assert ok_resp.status_code == 202
            assert ok_resp.json() == {"status": "accepted", "received": 4}

            # 4. Send the exact same NDJSON batch a second time (simulating HTTP timeout retry)
            dup_resp = client.post("/gelf", content=ndjson_body.encode("utf-8"))
            assert dup_resp.status_code == 202

            # 5. Verify /status Kill-Chain chronological ordering, Honeytoken count & _event_id deduplication
            status_resp = client.get("/status")
            assert status_resp.status_code == 200
            report = status_resp.json()
            assert report["total_gelf_received"] == 4
            assert report["duplicate_gelf_ignored"] == 4
            assert report["rejected_503_batches"] == 1
            assert report["honeytoken_alerts_received"] == 1

            kc = report["kill_chain_verification"]
            assert kc["attacker_ip"] == "10.0.0.99"
            assert kc["observed_sequence"] == [
                "PORT_SCAN",
                "BRUTE_FORCE",
                "IOT_CONTROL",
            ]
            assert kc["strict_chronological_order_verified"] is True
            assert kc["same_partition_verified"] is True
