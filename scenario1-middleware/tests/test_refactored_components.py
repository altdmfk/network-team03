import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import httpx
import pytest
from middleware.lightweight_broker import BrokerError, BrokerException, TopicPartition
from fastapi import HTTPException
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import PipelineSettings, load_settings
from consumer_worker import GraylogConsumerWorker
from ingestor import (
    BatchIngestRequest,
    WalLogBufferingMiddleware,
    SecurityLogEvent,
    ingest_batch_logs,
)
from metrics_store import SharedMetricsStore
from middleware import (
    DeliveryOutcome,
    ExplicitOffsetCommitter,
    GelfTransformer,
    GraylogDeliveryClient,
    JsonlDeadLetterStore,
    BrokerBatchPoller,
    RetryPolicy,
    StructuredJsonFormatter,
)
from tests.test_middleware import FakeBrokerMessage, sample_event_dict


# ===========================================================================
# 1. Typed Configuration Validation Tests (`PipelineSettings`)
# ===========================================================================
class TestPipelineSettingsValidation:
    def test_load_settings_defaults_and_legacy_batches_per_sec_fallback(self) -> None:
        default_cfg = load_settings({})
        assert default_cfg.batch_size == 100
        assert default_cfg.max_logs_per_sec == 500.0
        assert default_cfg.broker_partitions == 3
        assert default_cfg.max_delivery_retries == 8

        infinite_cfg = load_settings({"MAX_DELIVERY_RETRIES": "0"})
        assert infinite_cfg.max_delivery_retries == 0

        legacy_cfg = load_settings(
            {"BATCH_SIZE": "50", "MAX_BATCHES_PER_SECOND": "4.0"}
        )
        assert legacy_cfg.batch_size == 50
        assert legacy_cfg.max_logs_per_sec == 200.0

    def test_invalid_settings_raise_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            load_settings({"BATCH_SIZE": "0"})

        with pytest.raises(ValidationError):
            load_settings({"MAX_LOGS_PER_SEC": "-10"})

        with pytest.raises(ValidationError):
            load_settings(
                {"BASE_BACKOFF_SECONDS": "20.0", "MAX_BACKOFF_SECONDS": "5.0"}
            )

        with pytest.raises(ValidationError):
            PipelineSettings(ingestor_port=70000)


# ===========================================================================
# 2. Isolated Module Unit Tests (`middleware/*`)
# ===========================================================================
class TestIsolatedMiddlewareModules:
    def test_retry_policy_backoff_computation(self) -> None:
        policy = RetryPolicy(
            max_retries=5,
            base_backoff_seconds=1.0,
            max_backoff_seconds=10.0,
        )
        assert policy.compute_backoff(1, jitter_value=0.1) == 1.1
        assert policy.compute_backoff(2, jitter_value=0.2) == 2.2
        assert policy.compute_backoff(3, jitter_value=0.25) == 4.25
        # Capped at max_backoff_seconds=10.0 + jitter
        assert policy.compute_backoff(6, jitter_value=0.3) == 10.3

    def test_explicit_offset_committer_rebalance_and_offset_ranges(self) -> None:
        committer = ExplicitOffsetCommitter(default_topic="security-logs")
        mock_consumer = MagicMock()

        assigned = [TopicPartition("security-logs", 0), TopicPartition("security-logs", 1)]
        committer.on_assign(mock_consumer, assigned)
        assert committer.assigned_partitions == {
            ("security-logs", 0),
            ("security-logs", 1),
        }

        committer.on_revoke(mock_consumer, [TopicPartition("security-logs", 1)])
        assert committer.assigned_partitions == {("security-logs", 0)}
        assert committer.revoked_count == 1

        messages = [
            FakeBrokerMessage(sample_event_dict(), partition=0, offset=5),
            FakeBrokerMessage(sample_event_dict(), partition=0, offset=8),
            FakeBrokerMessage(sample_event_dict(), partition=2, offset=12),
        ]
        ranges = committer.compute_partition_offset_ranges(messages)
        assert ranges == {0: (5, 8), 2: (12, 12)}

        committed = committer.commit_batch_offsets(mock_consumer, messages)
        assert committed == [
            TopicPartition("security-logs", 0, 9),
            TopicPartition("security-logs", 2, 13),
        ]
        mock_consumer.commit.assert_called_once_with(
            offsets=committed, asynchronous=False
        )

    def test_gelf_transformer_wraps_malformed_poison_messages_safely(self) -> None:
        transformer = GelfTransformer(host="test-host")
        bad_msg = MagicMock()
        bad_msg.partition.return_value = 1
        bad_msg.offset.return_value = 77
        bad_msg.key.return_value = b"192.168.1.9"
        bad_msg.value.return_value = b"{corrupt-json-payload"

        gelf = transformer.transform_message(bad_msg)
        assert gelf["version"] == "1.1"
        assert gelf["host"] == "test-host"
        assert gelf["_event_id"] == "1:77"
        assert gelf["_event_type"] == "UNPARSED_EVENT"
        assert gelf["_client_ip"] == "192.168.1.9"
        assert gelf["_raw_payload"] == "{corrupt-json-payload"

    def test_batch_poller_filters_partition_eof_and_errors(self) -> None:
        eof_err = MagicMock()
        eof_err.code.return_value = BrokerError._PARTITION_EOF

        fatal_err = MagicMock()
        fatal_err.code.return_value = BrokerError._ALL_BROKERS_DOWN

        raw_list = [
            None,
            FakeBrokerMessage(sample_event_dict(), offset=1, error=eof_err),
            FakeBrokerMessage(sample_event_dict(), offset=2, error=fatal_err),
            FakeBrokerMessage(sample_event_dict(), offset=3, error=None),
        ]
        valid = BrokerBatchPoller.filter_valid_messages(raw_list)
        assert len(valid) == 1
        assert valid[0].offset() == 3

    def test_structured_json_formatter_includes_correlation_fields(self) -> None:
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="soar.test",
            level=logging.WARNING,
            pathname=__file__,
            lineno=10,
            msg="Retry scheduled for batch",
            args=(),
            exc_info=None,
        )
        record.batch_id = "ab12cd34"
        record.partition = 2
        record.offset_range = "100-199"
        record.retry_count = 3

        formatted = json.loads(formatter.format(record))
        assert formatted["level"] == "WARNING"
        assert formatted["logger"] == "soar.test"
        assert formatted["message"] == "Retry scheduled for batch"
        assert formatted["batch_id"] == "ab12cd34"
        assert formatted["partition"] == 2
        assert formatted["offset_range"] == "100-199"
        assert formatted["retry_count"] == 3


# ===========================================================================
# 3. Fault-Injection & Resilience Tests (Commit / Backoff / DLQ / Batch)
# ===========================================================================
class TestFaultInjectionAndInvariants:
    def test_offset_commit_exception_does_not_inflate_forwarded_metric(
        self, tmp_path: Path
    ) -> None:
        """
        Zero-loss invariant check: if Graylog returns 202 Accepted but synchronous
        Broker offset commit raises BrokerException (e.g., broker rebalance),
        `total_forwarded_to_graylog` must NOT be incremented prematurely because
        the uncommitted batch will be re-polled and re-delivered.
        """
        db_file = str(tmp_path / "commit_fault.db")
        with SharedMetricsStore(db_file) as store:
            with GraylogConsumerWorker(metrics_store=store) as worker:
                mock_consumer = MagicMock()
                mock_consumer.commit.side_effect = BrokerException(
                    MagicMock(spec=BrokerError)
                )
                worker.consumer = mock_consumer
                worker.http_client = MagicMock()
                worker.http_client.post.return_value = httpx.Response(status_code=202)

                messages = [FakeBrokerMessage(sample_event_dict(), offset=10)]
                result = worker.process_single_batch(messages)

                assert result.outcome is DeliveryOutcome.DELIVERED
                assert result.error_reason is not None
                snapshot = store.read_snapshot()
                assert snapshot["total_forwarded_to_graylog"] == 0

    def test_dlq_partial_replay_failure_preserves_unreplayed_records(
        self, tmp_path: Path
    ) -> None:
        """
        Fault injection: 3 records in DLQ replayed with batch_size=2.
        Chunk 1 (2 records) succeeds (HTTP 202), Chunk 2 (1 record) fails with
        httpx.ConnectError. Verify Chunk 1 is reconciled and Chunk 2 remains on disk.
        """
        dlq_path = str(tmp_path / "partial_dlq.jsonl")
        dlq_store = JsonlDeadLetterStore()
        records: List[Dict[str, Any]] = [
            {"version": "1.1", "host": "h", "short_message": "m1", "_event_id": "0:1"},
            {"version": "1.1", "host": "h", "short_message": "m2", "_event_id": "0:2"},
            {"version": "1.1", "host": "h", "short_message": "m3", "_event_id": "0:3"},
        ]
        dlq_store.write_batch(dlq_path, records)

        mock_http = MagicMock()
        mock_http.post.side_effect = [
            httpx.Response(status_code=202),
            httpx.ConnectError("Graylog connection reset mid-replay"),
        ]
        reconciled_chunks: List[int] = []

        replayed = dlq_store.replay(
            dlq_path=dlq_path,
            batch_size=2,
            acquire_tokens_fn=lambda _n: 0.0,
            http_client=mock_http,
            gelf_url="http://localhost:12201/gelf",
            dry_run=False,
            is_running_fn=lambda: True,
            on_chunk_replayed=lambda n: reconciled_chunks.append(n),
        )

        assert replayed == 2
        assert reconciled_chunks == [2]
        remaining = dlq_store.read_records(dlq_path)
        assert len(remaining) == 1
        assert remaining[0]["_event_id"] == "0:3"

    @pytest.mark.asyncio
    async def test_batch_ingest_partial_failure_records_accepted_prefix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        Fault injection: When a batch of 3 events fails on the 3rd event with
        BufferError (503), the 2 events already enqueued into broker buffer must still
        be counted in `total_received` so accounting never diverges.
        """
        import ingestor

        db_file = str(tmp_path / "partial_batch.db")
        with SharedMetricsStore(db_file) as store:
            middleware = WalLogBufferingMiddleware(
                store, max_buffer_retries=1, buffer_retry_sleep=0.0
            )
            mock_producer = MagicMock()
            mock_producer.produce.side_effect = [
                None,
                None,
                BufferError("Queue full on 3rd event"),
            ]
            middleware.producer = mock_producer

            monkeypatch.setattr(ingestor, "metrics_store", store)
            monkeypatch.setattr(ingestor, "wal_middleware", middleware)

            events = [
                SecurityLogEvent(**sample_event_dict(event_type="PORT_SCAN")),
                SecurityLogEvent(**sample_event_dict(event_type="BRUTE_FORCE")),
                SecurityLogEvent(**sample_event_dict(event_type="IOT_CONTROL")),
            ]
            with pytest.raises(HTTPException) as exc_info:
                await ingest_batch_logs(BatchIngestRequest(logs=events))

            assert exc_info.value.status_code == 503
            snapshot = store.read_snapshot()
            assert snapshot["total_received"] == 2
            assert snapshot["permanently_dropped_logs"] == 1
            assert snapshot["dlq_quarantined_logs"] == 0
            assert snapshot["dropped_logs"] == 1


# ===========================================================================
# 4. Honest Metrics Ledger, Rollback Invariants & Lag Cache Tests
# ===========================================================================
class TestMetricsLedgerHonestyAndInvariants:
    def test_split_counters_and_dead_letter_offset_does_not_inflate_forwarded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        Verifies:
        1. `permanently_dropped_logs` (producer errors) and `dlq_quarantined_logs` (DLQ waiting)
           are tracked separately, with `dropped_logs = permanently_dropped_logs + dlq_quarantined_logs`.
        2. Committed broker offsets for dead-lettered batches do NOT inflate `total_forwarded_to_graylog`
           in GET /metrics; `consumer_committed_offset_total` is exposed separately.
        3. `reconcile_dlq_replay()` decrements `dlq_quarantined_logs` only and never touches
           `permanently_dropped_logs`.
        """
        from fastapi.testclient import TestClient
        import ingestor

        db_file = str(tmp_path / "split_ledger.db")
        with SharedMetricsStore(db_file) as store:
            middleware = WalLogBufferingMiddleware(
                store, max_buffer_retries=1, buffer_retry_sleep=0.0
            )
            store.increment_received(5, flush=True)
            # 2 producer-side permanent drops
            store.increment_permanently_dropped(2, flush=True)
            # 3 consumer-side DLQ quarantined logs (whose broker offsets were committed)
            store.increment_dlq_quarantined(3, flush=True)

            lag_state = {
                "broker_total_messages": 3,
                "consumer_committed_total": 3,
                "broker_queue_lag": 0,
                "in_flight_producer_queue": 0,
                "partitions": [],
            }
            monkeypatch.setattr(ingestor, "metrics_store", store)
            monkeypatch.setattr(ingestor, "wal_middleware", middleware)
            monkeypatch.setattr(middleware, "start", lambda: None)
            monkeypatch.setattr(middleware, "stop", lambda: None)
            monkeypatch.setattr(middleware, "query_broker_native_lag", lambda: lag_state)

            with TestClient(ingestor.app) as client:
                m = client.get("/metrics").json()
                assert m["permanently_dropped_logs"] == 2
                assert m["dlq_quarantined_logs"] == 3
                assert m["dropped_logs"] == 5
                # Committed offset is 3 because DLQ batch was committed, but 0 logs were delivered to Graylog
                assert m["total_forwarded_to_graylog"] == 0
                assert m["consumer_committed_offset_total"] == 3
                assert m["broker_telemetry"]["consumer_committed_offset_total"] == 3
                assert m["invariant_violations"] == 0

                # Replay the 3 DLQ logs -> decrements dlq_quarantined_logs only, never permanently_dropped_logs
                store.reconcile_dlq_replay(3)
                m_after = client.get("/metrics").json()
                assert m_after["permanently_dropped_logs"] == 2
                assert m_after["dlq_quarantined_logs"] == 0
                assert m_after["dropped_logs"] == 2
                assert m_after["total_forwarded_to_graylog"] == 3
                assert m_after["dlq_replayed_logs"] == 3
                assert m_after["invariant_violations"] == 0

    def test_double_replay_rolls_back_and_does_not_touch_permanently_dropped(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        Double-replay test:
        When 2 DLQ logs are replayed once, `dlq_quarantined_logs` goes from 2 -> 0.
        If a second replay of 2 logs is attempted, `dlq_quarantined_logs` would go to -2.
        The transaction must be rolled back (leaving `total_forwarded_to_graylog`,
        `dlq_replayed_logs`, `dlq_quarantined_logs`, and `permanently_dropped_logs`
        unchanged), an ERROR must be logged, and `invariant_violations` incremented.
        """
        db_file = str(tmp_path / "double_replay.db")
        with SharedMetricsStore(db_file) as store:
            store.increment_received(6, flush=True)
            store.increment_permanently_dropped(4, flush=True)
            store.increment_dlq_quarantined(2, flush=True)

            # 1st replay (valid)
            snap1 = store.reconcile_dlq_replay(2)
            assert snap1["total_forwarded_to_graylog"] == 2
            assert snap1["dlq_replayed_logs"] == 2
            assert snap1["dlq_quarantined_logs"] == 0
            assert snap1["permanently_dropped_logs"] == 4
            assert snap1["dropped_logs"] == 4
            assert snap1["invariant_violations"] == 0

            # 2nd replay (double-replay bug -> would make dlq_quarantined_logs = -2)
            with caplog.at_level(logging.ERROR, logger="soar.metrics_store"):
                snap2 = store.reconcile_dlq_replay(2)

            assert snap2["total_forwarded_to_graylog"] == 2
            assert snap2["dlq_replayed_logs"] == 2
            assert snap2["dlq_quarantined_logs"] == 0
            assert snap2["permanently_dropped_logs"] == 4
            assert snap2["dropped_logs"] == 4
            assert snap2["invariant_violations"] == 1
            assert any(
                "dlq_quarantined_logs" in rec.message and "-2" in rec.message
                for rec in caplog.records
                if rec.levelno == logging.ERROR
            )

    def test_replay_after_metrics_reset_triggers_rollback_and_violation(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        Replay after /metrics/reset test:
        A batch of 2 logs is quarantined in the DLQ file (`dlq_quarantined_logs == 2`).
        Then `/metrics/reset` resets all metrics counters in SQLite to 0 while the
        DLQ file still exists on disk. When the worker subsequently replays the DLQ file,
        `reconcile_dlq_replay(2)` sees `dlq_quarantined_logs == 0`, rolls back the
        transaction instead of clamping to 0, logs an ERROR, and increments `invariant_violations`.
        """
        from fastapi.testclient import TestClient
        import consumer_worker
        import ingestor

        db_file = str(tmp_path / "reset_replay.db")
        dlq_file = tmp_path / "reset_dlq.jsonl"
        monkeypatch.setattr(consumer_worker.time, "sleep", lambda _s: None)

        with SharedMetricsStore(db_file) as store:
            middleware = WalLogBufferingMiddleware(store)
            lag_state = {
                "broker_total_messages": 2,
                "consumer_committed_total": 2,
                "broker_queue_lag": 0,
                "in_flight_producer_queue": 0,
                "partitions": [],
            }
            monkeypatch.setattr(ingestor, "metrics_store", store)
            monkeypatch.setattr(ingestor, "wal_middleware", middleware)
            monkeypatch.setattr(middleware, "start", lambda: None)
            monkeypatch.setattr(middleware, "stop", lambda: None)
            monkeypatch.setattr(middleware, "query_broker_native_lag", lambda: lag_state)

            with GraylogConsumerWorker(
                metrics_store=store,
                dead_letter_file=str(dlq_file),
                max_delivery_retries=1,
            ) as worker:
                mock_consumer = MagicMock()
                worker.consumer = mock_consumer
                monkeypatch.setattr(
                    worker.http_client,
                    "post",
                    MagicMock(return_value=httpx.Response(status_code=503)),
                )

                messages = [
                    FakeBrokerMessage(sample_event_dict(), offset=1),
                    FakeBrokerMessage(sample_event_dict(), offset=2),
                ]
                res = worker.process_single_batch(messages)
                assert res.outcome is DeliveryOutcome.DEAD_LETTERED
                assert store.read_snapshot()["dlq_quarantined_logs"] == 2
                assert dlq_file.exists()

                with TestClient(ingestor.app) as client:
                    # Call POST /metrics/reset while DLQ file still has 2 records
                    reset_resp = client.post("/metrics/reset")
                    assert reset_resp.status_code == 200
                    assert store.read_snapshot()["dlq_quarantined_logs"] == 0

                    # Now Graylog recovers and worker replays the pre-reset DLQ file
                    monkeypatch.setattr(
                        worker.http_client,
                        "post",
                        MagicMock(return_value=httpx.Response(status_code=202)),
                    )
                    with caplog.at_level(logging.ERROR, logger="soar.metrics_store"):
                        replayed = worker._replay_dead_letter_file()
                    assert replayed == 2

                    metrics_data = client.get("/metrics").json()
                    assert metrics_data["dlq_quarantined_logs"] == 0
                    assert metrics_data["total_forwarded_to_graylog"] == 0
                    assert metrics_data["dlq_replayed_logs"] == 0
                    assert metrics_data["invariant_violations"] == 1
                    assert any(
                        "dlq_quarantined_logs" in rec.message
                        for rec in caplog.records
                        if rec.levelno == logging.ERROR
                    )

    def test_invariant_violation_rollback_preserves_pre_transaction_state(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        Verifies that when a decrement would go below zero (e.g. `dlq_quarantined_logs=2`
        decremented by 5), the entire SQLite transaction is rolled back so
        `total_forwarded_to_graylog`, `dlq_replayed_logs`, and `dlq_quarantined_logs`
        remain at their exact pre-transaction values, an ERROR is logged with the
        counter name and values, and `invariant_violations` is incremented.
        """
        db_file = str(tmp_path / "rollback_check.db")
        with SharedMetricsStore(db_file) as store:
            store.increment_received(15, flush=True)
            store.increment_forwarded(10, flush=True)
            store.increment_permanently_dropped(3, flush=True)
            store.increment_dlq_quarantined(2, flush=True)

            with caplog.at_level(logging.ERROR, logger="soar.metrics_store"):
                snap = store.reconcile_dlq_replay(5)

            assert snap["total_received"] == 15
            assert snap["total_forwarded_to_graylog"] == 10
            assert snap["dlq_replayed_logs"] == 0
            assert snap["dlq_quarantined_logs"] == 2
            assert snap["permanently_dropped_logs"] == 3
            assert snap["dropped_logs"] == 5
            assert snap["invariant_violations"] == 1

            error_messages = [
                rec.message for rec in caplog.records if rec.levelno == logging.ERROR
            ]
            assert any(
                "dlq_quarantined_logs" in msg
                and "current_value=2" in msg
                and "decrement_by=5" in msg
                and "resulting_value=-3" in msg
                for msg in error_messages
            )

            # Direct counter decrement below zero also rolls back and increments invariant_violations
            val = store.decrement_counter("dlq_quarantined_logs", 4)
            assert val == 2
            snap_after = store.read_snapshot()
            assert snap_after["dlq_quarantined_logs"] == 2
            assert snap_after["invariant_violations"] == 2

    def test_lag_cache_ttl_fifty_rapid_metrics_calls_trigger_at_most_two_broker_queries(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """
        Proves that `query_broker_native_lag()` caches broker watermark/offset RPCs
        with a 1-second TTL in a thread-safe manner so that 50 rapid `GET /metrics`
        calls trigger at most 2 broker queries.
        """
        from fastapi.testclient import TestClient
        import ingestor

        db_file = str(tmp_path / "lag_cache.db")
        with SharedMetricsStore(db_file) as store:
            store.increment_received(30, flush=True)
            store.increment_forwarded(15, flush=True)
            middleware = WalLogBufferingMiddleware(store, lag_cache_ttl=1.0)
            mock_producer = MagicMock()
            mock_producer.__len__.return_value = 0
            middleware.producer = mock_producer

            mock_admin = MagicMock()
            future_mock = MagicMock()
            group_result_mock = MagicMock()
            group_result_mock.topic_partitions = [
                TopicPartition("security-logs", 0, 5),
                TopicPartition("security-logs", 1, 5),
                TopicPartition("security-logs", 2, 5),
            ]
            future_mock.result.return_value = group_result_mock
            mock_admin.list_consumer_group_offsets.return_value = {
                "graylog-shipper-group": future_mock
            }

            mock_watermark_consumer = MagicMock()
            mock_watermark_consumer.get_watermark_offsets.return_value = (0, 10)

            middleware.admin_client = mock_admin
            middleware._watermark_consumer = mock_watermark_consumer

            monkeypatch.setattr(ingestor, "metrics_store", store)
            monkeypatch.setattr(ingestor, "wal_middleware", middleware)
            monkeypatch.setattr(middleware, "start", lambda: None)
            monkeypatch.setattr(middleware, "stop", lambda: None)

            fake_clock = [1000.0]
            monkeypatch.setattr(ingestor.time, "monotonic", lambda: fake_clock[0])

            with TestClient(ingestor.app) as client:
                for i in range(50):
                    # Advance clock across the 1.0s TTL boundary once halfway through the 50 calls
                    if i == 25:
                        fake_clock[0] += 1.05
                    resp = client.get("/metrics")
                    assert resp.status_code == 200
                    data = resp.json()
                    assert data["current_queue_lag"] == 15
                    assert data["consumer_committed_offset_total"] == 15

            assert 1 <= mock_admin.list_consumer_group_offsets.call_count <= 2
            assert mock_admin.list_consumer_group_offsets.call_count == 2

    def test_five_stage_audit_new_invariant_formula(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        Verifies the updated 5-stage audit invariant in `spike_test_demo.py`:
        `Sent == Received == Forwarded + permanently_dropped + dlq_quarantined == Graylog Stored`
        and checks that each term is formatted and printed.
        """
        from spike_test_demo import (
            format_audit_invariant,
            verify_five_stage_audit_invariant,
        )

        line = verify_five_stage_audit_invariant(
            total_sent=5004,
            total_received=5004,
            total_forwarded=5004,
            permanently_dropped=0,
            dlq_quarantined=0,
            graylog_stored=5004,
            current_queue_lag=0,
        )
        print(line)
        captured = capsys.readouterr().out
        assert "Sent (5,004)" in captured
        assert "Received (5,004)" in captured
        assert "Forwarded (5,004)" in captured
        assert "permanently_dropped (0)" in captured
        assert "dlq_quarantined (0)" in captured
        assert "Graylog Stored (5,004)" in captured

        formatted = format_audit_invariant(
            total_sent=100,
            total_received=100,
            total_forwarded=95,
            permanently_dropped=2,
            dlq_quarantined=3,
            graylog_stored=95,
        )
        assert (
            formatted
            == "Sent (100) == Received (100) == Forwarded (95) + permanently_dropped (2) + dlq_quarantined (3) == Graylog Stored (95)"
        )

        # Mismatch between Received and Forwarded + permanently_dropped + dlq_quarantined raises AssertionError
        with pytest.raises(AssertionError):
            verify_five_stage_audit_invariant(
                total_sent=100,
                total_received=100,
                total_forwarded=90,
                permanently_dropped=2,
                dlq_quarantined=3,
                graylog_stored=100,
                current_queue_lag=0,
            )


# ===========================================================================
# 5. Long Outage Pause/Poll, Cooperative-Sticky Rebalance & SIGTERM Tests
# ===========================================================================
class FakePauseAwareConsumer:
    """
    Fake broker consumer modeling partition assignment, `pause()`, `resume()`,
    `poll()`, `consume()`, `commit()`, and `close()`.
    Proves whether `poll()` is ever called while unpaused:
    - When a partition is NOT paused, `poll()` dequeues and returns a message
      (recording it in `polled_or_discarded_messages`).
    - When a partition IS paused, `poll()` returns `None` and never dequeues
      any message from the partition queue.
    """

    def __init__(
        self,
        assigned_partitions: List[TopicPartition],
        partition_messages: Optional[Dict[int, List[FakeBrokerMessage]]] = None,
    ) -> None:
        self._assigned: List[TopicPartition] = list(assigned_partitions)
        self.queues: Dict[int, List[FakeBrokerMessage]] = {
            int(tp.partition): list((partition_messages or {}).get(int(tp.partition), []))
            for tp in assigned_partitions
        }
        self.paused_partitions: set[tuple[str, int]] = set()
        self.pause_calls: List[List[TopicPartition]] = []
        self.resume_calls: List[List[TopicPartition]] = []
        self.poll_while_paused_history: List[bool] = []
        self.polled_or_discarded_messages: List[FakeBrokerMessage] = []
        self.committed_offsets: List[List[TopicPartition]] = []
        self.commit_side_effect: Optional[ Any ] = None
        self.on_poll_hook: Optional[Any] = None
        self.closed: bool = False

    def assignment(self) -> List[TopicPartition]:
        return list(self._assigned)

    def pause(self, partitions: List[TopicPartition]) -> None:
        self.pause_calls.append(list(partitions))
        for tp in partitions:
            self.paused_partitions.add((tp.topic, int(tp.partition)))

    def resume(self, partitions: List[TopicPartition]) -> None:
        self.resume_calls.append(list(partitions))
        for tp in partitions:
            self.paused_partitions.discard((tp.topic, int(tp.partition)))

    def poll(self, timeout: float = 0.0) -> Optional[FakeBrokerMessage]:
        all_paused = bool(self._assigned) and all(
            (tp.topic, int(tp.partition)) in self.paused_partitions
            for tp in self._assigned
        )
        self.poll_while_paused_history.append(all_paused)
        poll_idx = len(self.poll_while_paused_history)

        # If any assigned partition is NOT paused and has messages, poll() would dequeue it!
        for tp in list(self._assigned):
            if (tp.topic, int(tp.partition)) not in self.paused_partitions:
                q = self.queues.get(int(tp.partition), [])
                if q:
                    leaked_msg = q.pop(0)
                    self.polled_or_discarded_messages.append(leaked_msg)
                    return leaked_msg

        if self.on_poll_hook is not None:
            self.on_poll_hook(self, poll_idx)

        return None

    def consume(
        self, num_messages: int = 1, timeout: float = 0.0
    ) -> List[FakeBrokerMessage]:
        batch: List[FakeBrokerMessage] = []
        for tp in list(self._assigned):
            if (tp.topic, int(tp.partition)) in self.paused_partitions:
                continue
            q = self.queues.get(int(tp.partition), [])
            while q and len(batch) < num_messages:
                batch.append(q.pop(0))
            if len(batch) >= num_messages:
                break
        return batch

    def commit(
        self,
        offsets: Optional[List[TopicPartition]] = None,
        asynchronous: bool = False,
    ) -> None:
        if self.commit_side_effect is not None:
            if callable(self.commit_side_effect):
                self.commit_side_effect(offsets=offsets, asynchronous=asynchronous)
            else:
                raise self.commit_side_effect
        if offsets is not None:
            self.committed_offsets.append(list(offsets))

    def close(self) -> None:
        self.closed = True


class TestLongOutageRebalanceAndGracefulShutdown:
    def test_paused_backoff_polls_only_while_paused_and_never_discards_messages(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        Requirement 1:
        Proves with a fake consumer that during backoff:
        1. `consumer.pause(assigned_partitions)` is called before polling.
        2. `consumer.poll(0)` is called ONLY while paused.
        3. No message is ever returned or discarded by `poll()` while paused, even
           when subsequent messages are sitting in the partition queue.
        4. `consumer.resume(assigned_partitions)` is called after a successful 2xx delivery,
           allowing subsequent queued messages to be consumed and delivered without loss.
        """
        import consumer_worker

        db_file = str(tmp_path / "pause_poll.db")
        monkeypatch.setattr(consumer_worker.time, "sleep", lambda _s: None)

        assigned = [TopicPartition("security-logs", 0)]
        queued_msgs = [
            FakeBrokerMessage(sample_event_dict(event_type="PORT_SCAN"), partition=0, offset=1),
            FakeBrokerMessage(sample_event_dict(event_type="BRUTE_FORCE"), partition=0, offset=2),
            FakeBrokerMessage(sample_event_dict(event_type="IOT_CONTROL"), partition=0, offset=3),
            FakeBrokerMessage(sample_event_dict(event_type="HONEYTOKEN_ACCESS"), partition=0, offset=4),
        ]
        fake_consumer = FakePauseAwareConsumer(
            assigned_partitions=assigned,
            partition_messages={0: queued_msgs},
        )

        with SharedMetricsStore(db_file) as store:
            with GraylogConsumerWorker(
                metrics_store=store,
                batch_size=2,
                batch_linger_ms=0,
                max_delivery_retries=0,  # Infinite backoff
                base_backoff_seconds=0.5,
            ) as worker:
                worker.consumer = fake_consumer
                worker.offset_committer.on_assign(fake_consumer, assigned)

                # Batch 1 (offsets 1, 2): fails twice with 503, succeeds on 3rd attempt (202).
                # Batch 2 (offsets 3, 4): succeeds immediately on 1st attempt (202).
                responses = [
                    httpx.Response(status_code=503, text="Graylog Outage #1"),
                    httpx.Response(status_code=503, text="Graylog Outage #2"),
                    httpx.Response(status_code=202, json={"status": "accepted"}),
                    httpx.Response(status_code=202, json={"status": "accepted"}),
                ]
                delivered_payloads: List[str] = []

                def post_side_effect(_url: str, content: bytes, **_kw: Any) -> httpx.Response:
                    resp = responses.pop(0)
                    if resp.status_code == 202:
                        delivered_payloads.append(content.decode("utf-8"))
                    return resp

                monkeypatch.setattr(worker.http_client, "post", post_side_effect)

                # Process Batch 1 (offsets 1, 2) while offsets 3, 4 remain in fake_consumer's queue
                batch_1 = worker._poll_batch()
                assert [m.offset() for m in batch_1] == [1, 2]
                assert len(fake_consumer.queues[0]) == 2  # offsets 3, 4 still queued

                res_1 = worker.process_single_batch(batch_1)
                assert res_1.outcome is DeliveryOutcome.DELIVERED

                # Verify pause -> poll while paused -> resume sequence
                assert len(fake_consumer.pause_calls) >= 1
                assert fake_consumer.pause_calls[0] == [TopicPartition("security-logs", 0)]
                assert len(fake_consumer.poll_while_paused_history) >= 2
                assert all(fake_consumer.poll_while_paused_history)
                assert fake_consumer.polled_or_discarded_messages == []
                assert len(fake_consumer.resume_calls) == 1
                assert fake_consumer.resume_calls[0] == [TopicPartition("security-logs", 0)]
                assert fake_consumer.paused_partitions == set()

                # Offsets 3 and 4 were NOT discarded during backoff and are now consumed cleanly
                batch_2 = worker._poll_batch()
                assert [m.offset() for m in batch_2] == [3, 4]
                res_2 = worker.process_single_batch(batch_2)
                assert res_2.outcome is DeliveryOutcome.DELIVERED

                assert fake_consumer.committed_offsets == [
                    [TopicPartition("security-logs", 0, 3)],
                    [TopicPartition("security-logs", 0, 5)],
                ]
                assert store.read_snapshot()["total_forwarded_to_graylog"] == 4

    def test_cooperative_sticky_strategy_and_rebalance_callbacks_registration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        Requirement 2:
        Verifies `_setup_consumer()` sets `partition.assignment.strategy=cooperative-sticky`
        and registers `on_assign`, `on_revoke`, and `on_lost` from `ExplicitOffsetCommitter`.
        """
        import consumer_worker

        captured_conf: Dict[str, Any] = {}
        captured_subscribe: Dict[str, Any] = {}

        class DummyConsumer:
            def __init__(self, conf: Dict[str, Any]) -> None:
                captured_conf.update(conf)

            def subscribe(self, topics: List[str], **kwargs: Any) -> None:
                captured_subscribe["topics"] = topics
                captured_subscribe.update(kwargs)

            def close(self) -> None:
                pass

        monkeypatch.setattr(consumer_worker, "Consumer", DummyConsumer)

        with GraylogConsumerWorker() as worker:
            worker._setup_consumer()
            assert (
                captured_conf.get("partition.assignment.strategy")
                == "cooperative-sticky"
            )
            assert captured_conf.get("enable.auto.commit") is False
            assert captured_subscribe.get("on_assign") == worker.offset_committer.on_assign
            assert captured_subscribe.get("on_revoke") == worker.offset_committer.on_revoke
            assert captured_subscribe.get("on_lost") == worker.offset_committer.on_lost

    def test_on_revoke_commits_only_confirmed_batches_never_unconfirmed(self) -> None:
        """
        Requirement 2 (`on_revoke`):
        Proves that `on_revoke` NEVER commits offsets for an in-flight batch that was
        not confirmed 2xx, and commits ONLY offsets of already-confirmed batches.
        """
        committer = ExplicitOffsetCommitter(default_topic="security-logs")
        mock_consumer = MagicMock()

        committer.on_assign(
            mock_consumer,
            [TopicPartition("security-logs", 0), TopicPartition("security-logs", 1)],
        )

        # Batch A on partition 0 (offsets 1..3) is confirmed 2xx
        confirmed_msgs = [
            FakeBrokerMessage(sample_event_dict(), partition=0, offset=1),
            FakeBrokerMessage(sample_event_dict(), partition=0, offset=3),
        ]
        committer.begin_batch("batch_a", confirmed_msgs)
        committer.mark_batch_confirmed(confirmed_msgs, batch_id="batch_a")

        # Batch B on partition 1 (offsets 10..12) is currently in-flight and NOT confirmed 2xx
        unconfirmed_msgs = [
            FakeBrokerMessage(sample_event_dict(), partition=1, offset=10),
            FakeBrokerMessage(sample_event_dict(), partition=1, offset=12),
        ]
        committer.begin_batch("batch_b", unconfirmed_msgs)

        # Rebalance revokes both partition 0 and partition 1
        committer.on_revoke(
            mock_consumer,
            [TopicPartition("security-logs", 0), TopicPartition("security-logs", 1)],
        )

        # Only partition 0's confirmed offset (3 + 1 = 4) is committed; partition 1 is NEVER committed
        mock_consumer.commit.assert_called_once_with(
            offsets=[TopicPartition("security-logs", 0, 4)],
            asynchronous=False,
        )
        assert committer.in_flight_aborted is True
        assert committer.assigned_partitions == set()

    def test_on_lost_drops_in_flight_state_without_committing_and_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """
        Requirement 2 (`on_lost`):
        Proves that `on_lost` drops in-flight batch state without committing any offsets
        and logs a WARNING containing `batch_id` and `offset_range`.
        """
        committer = ExplicitOffsetCommitter(default_topic="security-logs")
        mock_consumer = MagicMock()
        committer.on_assign(mock_consumer, [TopicPartition("security-logs", 2)])

        in_flight_msgs = [
            FakeBrokerMessage(sample_event_dict(), partition=2, offset=20),
            FakeBrokerMessage(sample_event_dict(), partition=2, offset=25),
        ]
        committer.begin_batch("b99f0011", in_flight_msgs)

        with caplog.at_level(logging.WARNING, logger="soar.offset_committer"):
            committer.on_lost(mock_consumer, [TopicPartition("security-logs", 2)])

        mock_consumer.commit.assert_not_called()
        assert committer.in_flight_batch is None
        assert committer.in_flight_aborted is True
        assert committer.lost_count == 1
        assert committer.assigned_partitions == set()

        warning_records = [
            r for r in caplog.records if r.levelno == logging.WARNING
        ]
        assert any(
            "b99f0011" in r.getMessage()
            and "2:20-25" in r.getMessage()
            and getattr(r, "batch_id", None) == "b99f0011"
            and getattr(r, "offset_range", None) == "2:20-25"
            for r in warning_records
        )

    def test_fault_injection_rebalance_during_backoff_aborts_unconfirmed_batch_without_commit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        Requirement 6 (Fault Injection - Rebalance during backoff):
        Worker receives HTTP 503 and enters pause-based backoff. During `consumer.poll(0)`
        while paused in backoff, a rebalance fires `on_lost` (and `on_revoke` in a second scenario)
        for the in-flight partition.
        Verifies:
        - Offsets are NEVER committed for the unconfirmed batch.
        - `on_lost` logs a WARNING with `batch_id` and `offset_range`.
        - The in-flight batch is aborted (`DeliveryOutcome.ABORTED`).
        - `total_forwarded_to_graylog` remains 0.
        """
        import consumer_worker

        db_file = str(tmp_path / "rebalance_backoff.db")
        monkeypatch.setattr(consumer_worker.time, "sleep", lambda _s: None)

        assigned = [TopicPartition("security-logs", 0)]
        fake_consumer = FakePauseAwareConsumer(assigned_partitions=assigned)

        with SharedMetricsStore(db_file) as store:
            with GraylogConsumerWorker(
                metrics_store=store,
                max_delivery_retries=0,
                base_backoff_seconds=1.0,
            ) as worker:
                worker.consumer = fake_consumer
                worker.offset_committer.on_assign(fake_consumer, assigned)

                # Trigger on_lost during the first poll(0) inside backoff
                def trigger_rebalance_on_poll(cons: FakePauseAwareConsumer, poll_idx: int) -> None:
                    if poll_idx == 1:
                        cons._assigned = []
                        worker.offset_committer.on_lost(
                            cons, [TopicPartition("security-logs", 0)]
                        )

                fake_consumer.on_poll_hook = trigger_rebalance_on_poll
                monkeypatch.setattr(
                    worker.http_client,
                    "post",
                    MagicMock(return_value=httpx.Response(status_code=503, text="Outage")),
                )

                messages = [
                    FakeBrokerMessage(sample_event_dict(), partition=0, offset=10),
                    FakeBrokerMessage(sample_event_dict(), partition=0, offset=11),
                ]
                with caplog.at_level(logging.WARNING, logger="soar.offset_committer"):
                    result = worker.process_single_batch(messages)

                assert result.outcome is DeliveryOutcome.ABORTED
                assert fake_consumer.committed_offsets == []
                assert store.read_snapshot()["total_forwarded_to_graylog"] == 0
                assert any(
                    result.batch_id in r.getMessage() and "0:10-11" in r.getMessage()
                    for r in caplog.records
                )

    def test_fault_injection_rebalance_commit_failure_after_2xx_logs_structured_context_without_double_count(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        Requirements 3 & 6 (Fault Injection - Commit failure after 2xx):
        After Graylog returns HTTP 202 Accepted, synchronous `consumer.commit()` fails
        with a rebalance-related `BrokerException` (`ILLEGAL_GENERATION`).
        Verifies:
        - Worker treats it as an expected at-least-once duplicate, logs a WARNING with
        structured correlation fields (`batch_id`, `partition`, `offset_range`, `message_count`),
        and does NOT crash.
        - `total_forwarded_to_graylog` is NOT incremented on the failed commit, so when
        the new partition owner re-delivers and commits the batch, `total_forwarded_to_graylog`
        is counted exactly once (never double-counted).
        """
        db_file = str(tmp_path / "commit_rebalance_2xx.db")
        with SharedMetricsStore(db_file) as store:
            with GraylogConsumerWorker(metrics_store=store) as worker:
                rebalance_err = MagicMock(spec=BrokerError)
                rebalance_err.code.return_value = BrokerError.ILLEGAL_GENERATION
                rebalance_err.name.return_value = "ILLEGAL_GENERATION"

                mock_consumer = MagicMock()
                mock_consumer.commit.side_effect = [
                    BrokerException(rebalance_err),
                    None,  # Succeeds when re-polled by new owner
                ]
                worker.consumer = mock_consumer
                monkeypatch.setattr(
                    worker.http_client,
                    "post",
                    MagicMock(return_value=httpx.Response(status_code=202)),
                )

                messages = [
                    FakeBrokerMessage(sample_event_dict(), partition=0, offset=40),
                    FakeBrokerMessage(sample_event_dict(), partition=0, offset=41),
                ]

                # 1st delivery: 202 Accepted, but commit raises ILLEGAL_GENERATION
                with caplog.at_level(logging.WARNING, logger="soar.consumer_worker"):
                    res1 = worker.process_single_batch(messages)

                assert res1.outcome is DeliveryOutcome.DELIVERED
                assert res1.error_reason is not None
                assert store.read_snapshot()["total_forwarded_to_graylog"] == 0

                rebalance_logs = [
                    r
                    for r in caplog.records
                    if r.levelno == logging.WARNING
                    and getattr(r, "batch_id", None) == res1.batch_id
                ]
                assert len(rebalance_logs) == 1
                assert rebalance_logs[0].partition == 0
                assert rebalance_logs[0].offset_range == "0:40-41"
                assert rebalance_logs[0].message_count == 2
                assert "at-least-once duplicate" in rebalance_logs[0].getMessage()

                # 2nd delivery (re-polled after rebalance): 202 Accepted + commit succeeds
                res2 = worker.process_single_batch(messages)
                assert res2.outcome is DeliveryOutcome.DELIVERED
                assert res2.error_reason is None
                # Counted once (2 logs), never double-counted (4 logs)
                assert store.read_snapshot()["total_forwarded_to_graylog"] == 2

    def test_fault_injection_sigterm_mid_backoff_abandons_unconfirmed_batch_and_closes_cleanly(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """
        Requirements 4 & 6 (Graceful shutdown & SIGTERM mid-backoff):
        Worker is in infinite backoff (`max_delivery_retries=0`, `base_backoff_seconds=30.0`)
        during a Graylog 503 outage when SIGTERM arrives mid-backoff.
        Verifies:
        - Worker abandons the unconfirmed batch safely without committing offsets.
        - Closes the broker consumer cleanly (`consumer.close()`).
        - Exits promptly well within `stop_grace_period` (20s).
        """
        import signal as std_signal
        import time as std_time
        import consumer_worker

        db_file = str(tmp_path / "sigterm_backoff.db")
        slept_steps: List[float] = []
        monkeypatch.setattr(
            consumer_worker.time, "sleep", lambda s: slept_steps.append(s)
        )

        assigned = [TopicPartition("security-logs", 0)]
        batch_msgs = [
            FakeBrokerMessage(sample_event_dict(), partition=0, offset=70),
            FakeBrokerMessage(sample_event_dict(), partition=0, offset=71),
        ]
        fake_consumer = FakePauseAwareConsumer(
            assigned_partitions=assigned,
            partition_messages={0: batch_msgs},
        )

        with SharedMetricsStore(db_file) as store:
            with GraylogConsumerWorker(
                metrics_store=store,
                batch_size=2,
                batch_linger_ms=0,
                max_delivery_retries=0,
                base_backoff_seconds=30.0,
                max_backoff_seconds=30.0,
            ) as worker:
                worker.consumer = fake_consumer
                worker.offset_committer.on_assign(fake_consumer, assigned)

                def send_sigterm_mid_backoff(
                    _cons: FakePauseAwareConsumer, poll_idx: int
                ) -> None:
                    if poll_idx == 1:
                        handler = std_signal.getsignal(std_signal.SIGTERM)
                        assert handler == worker.stop
                        handler(std_signal.SIGTERM, None)

                fake_consumer.on_poll_hook = send_sigterm_mid_backoff
                monkeypatch.setattr(
                    worker.http_client,
                    "post",
                    MagicMock(return_value=httpx.Response(status_code=503, text="Outage")),
                )

                start_wall = std_time.monotonic()
                worker.run()
                elapsed_wall = std_time.monotonic() - start_wall

                # Exited well within stop_grace_period (20s) without sleeping the full 30s backoff
                assert elapsed_wall < 5.0
                assert sum(slept_steps) < 1.0
                # Never committed the unconfirmed batch
                assert fake_consumer.committed_offsets == []
                # Closed consumer cleanly
                assert fake_consumer.closed is True
                assert worker.consumer is None
                # Metrics remain untouched
                snap = store.read_snapshot()
                assert snap["total_forwarded_to_graylog"] == 0
                assert snap["dropped_logs"] == 0


