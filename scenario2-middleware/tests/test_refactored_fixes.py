import argparse
import asyncio
import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

import config
import ingestor
from ingestor import (
    LenientSecurityLogEvent,
    SecurityLogEvent,
    StrictSecurityLogEvent,
    app as ingestor_app,
)
from consumer_worker import GraylogConsumerWorker
from metrics_store import SharedMetricsStore
from middleware.delivery_client import GraylogDeliveryClient
from middleware.dlq_publisher import BrokerDeadLetterPublisher
from middleware.ingest_rate_limiter import PerClientRateLimiter, ingest_rate_limiter
from middleware.lightweight_broker import LightweightConsumer as Consumer, SQLiteBrokerStorage
from middleware.models import DeliveryOutcome, RetryPolicy


def sample_log_dict(**kwargs: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "client_ip": "192.168.1.100",
        "event_type": "PORT_SCAN",
        "target_resource": "/api/v1/auth",
        "status_code": 200,
        "severity": 4,
        "raw_payload": {"msg": "test probe"},
    }
    base.update(kwargs)
    return base


class TestEventLoopBlockingFix:
    """Verifies Task 1: health_check offloads SQLite calls to worker threads with timeout guard."""

    def test_health_check_offloaded_to_thread(self) -> None:
        client = TestClient(ingestor_app)
        thread_ids = []

        mw = ingestor._active_middleware()
        orig_check = getattr(mw, "check_health", None)

        def mock_check_health(timeout: float = 0.1) -> bool:
            thread_ids.append(threading.current_thread().ident)
            return True

        with patch.object(mw, "check_health", side_effect=mock_check_health):
            resp = client.get("/v1/health")
            assert resp.status_code == 200
            assert resp.json()["status"] == "healthy"
            assert len(thread_ids) == 1
            # Must run on a worker thread, not the main thread
            main_thread_id = threading.main_thread().ident
            assert thread_ids[0] != main_thread_id

    @pytest.mark.asyncio
    async def test_health_check_timeout_guard(self) -> None:
        mw = ingestor._active_middleware()

        def hanging_check_health(timeout: float = 0.1) -> bool:
            time.sleep(1.0)
            return True

        with patch.object(mw, "check_health", side_effect=hanging_check_health):
            t0 = time.perf_counter()
            with pytest.raises(Exception) as exc_info:
                await ingestor.health_check()
            elapsed = time.perf_counter() - t0
            assert exc_info.value.status_code == 503
            assert exc_info.value.detail == "Broker WAL storage unhealthy or locked"
            assert elapsed < 0.6  # Explicit timeout guard fired at ~0.3s without blocking


class TestAPIKeyHashingInMemory:
    """Verifies Task 2: Raw API keys are never stored in rate limiter buckets or memory state."""

    def test_raw_api_key_hashed_in_rate_limiter_buckets(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret_key = "super_secret_production_api_key_12345"
        expected_hash = hashlib.sha256(secret_key.encode("utf-8")).hexdigest()

        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("INGEST_API_KEYS", secret_key)

        custom_limiter = PerClientRateLimiter(rate_per_sec=100.0, capacity=100.0)
        monkeypatch.setattr(ingestor, "ingest_rate_limiter", custom_limiter)

        client = TestClient(ingestor_app)
        with patch.object(ingestor.wal_middleware, "enqueue_event_async"):
            resp = client.post(
                "/v1/ingest",
                json=sample_log_dict(),
                headers={"X-API-Key": secret_key},
            )
            assert resp.status_code == 202

        bucket_keys = list(custom_limiter._buckets.keys())
        assert len(bucket_keys) == 1
        # Raw API key MUST NOT appear anywhere in the buckets
        assert secret_key not in bucket_keys
        # Key must be the SHA-256 hex digest
        assert bucket_keys[0] == expected_hash

    def test_auth_disabled_ip_fallback_in_buckets(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTH_ENABLED", "false")
        custom_limiter = PerClientRateLimiter(rate_per_sec=100.0, capacity=100.0)
        monkeypatch.setattr(ingestor, "ingest_rate_limiter", custom_limiter)

        client = TestClient(ingestor_app)
        with patch.object(ingestor.wal_middleware, "enqueue_event_async"):
            resp = client.post(
                "/v1/ingest",
                json=sample_log_dict(),
            )
            assert resp.status_code == 202

        bucket_keys = list(custom_limiter._buckets.keys())
        assert len(bucket_keys) == 1
        assert bucket_keys[0].startswith("ip:")

    def test_direct_limiter_call_with_raw_key_normalizes_to_sha256(self) -> None:
        limiter = PerClientRateLimiter()
        raw_key = "plain_api_key_sent_to_limiter"
        expected_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

        allowed, _ = limiter.check_and_consume(raw_key)
        assert allowed is True
        assert raw_key not in limiter._buckets
        assert expected_hash in limiter._buckets


class TestPreventDuplicateRedeliveryOnSplitFailure:
    """Verifies Task 3: Retrying a batch in split mode retries ONLY failed items."""

    def test_partial_split_failure_retries_only_failed_subset(self) -> None:
        call_records: List[Dict[str, Any]] = []

        def mock_post(url: str, **kwargs: Any) -> httpx.Response:
            json_doc = kwargs.get("json", {})
            call_records.append(json_doc)
            # Item with serial 2 fails on attempt 1, succeeds on attempt 2
            if json_doc.get("item_id") == 2:
                # If this is the first time item 2 is seen, fail it
                item_2_calls = [c for c in call_records if c.get("item_id") == 2]
                if len(item_2_calls) == 1:
                    return httpx.Response(status_code=500, text="Internal Server Error")
            return httpx.Response(status_code=202, text="Accepted")

        client = GraylogDeliveryClient(split_post=True)
        gelf_batch = [
            {"short_message": "log1", "item_id": 1},
            {"short_message": "log2", "item_id": 2},
            {"short_message": "log3", "item_id": 3},
        ]
        mock_http = MagicMock()
        mock_http.post.side_effect = mock_post

        retry_policy = RetryPolicy(
            max_retries=2,
            base_backoff_seconds=0.01,
            max_backoff_seconds=0.05,
        )

        outcome = client.deliver_batch(
            gelf_batch=gelf_batch,
            http_client=mock_http,
            gelf_url="http://mock-graylog/gelf",
            retry_policy=retry_policy,
            dry_run=False,
            is_running_fn=lambda: True,
            on_dead_letter=lambda *a, **k: True,
        )

        assert outcome is DeliveryOutcome.DELIVERED
        # Attempt 1 sends items 1, 2, 3 (3 calls)
        # Attempt 2 must ONLY retry item 2 (1 call)
        # Total calls must be 4, NOT 6!
        assert len(call_records) == 4
        item_1_calls = [c for c in call_records if c.get("item_id") == 1]
        item_2_calls = [c for c in call_records if c.get("item_id") == 2]
        item_3_calls = [c for c in call_records if c.get("item_id") == 3]

        assert len(item_1_calls) == 1  # No duplicate delivery!
        assert len(item_3_calls) == 1  # No duplicate delivery!
        assert len(item_2_calls) == 2  # Retried only the failed item!

    def test_split_failure_exhausted_dead_letters_only_failed_subset(self) -> None:
        dlq_batches = []
        dlq_msgs = []

        def mock_dead_letter(batch: List[Dict[str, Any]], **kwargs: Any) -> bool:
            dlq_batches.append(batch)
            dlq_msgs.append(kwargs.get("messages"))
            return True

        def mock_post(url: str, **kwargs: Any) -> httpx.Response:
            json_doc = kwargs.get("json", {})
            if json_doc.get("item_id") == 2:
                return httpx.Response(status_code=500, text="Failed always")
            return httpx.Response(status_code=202, text="OK")

        client = GraylogDeliveryClient(split_post=True)
        gelf_batch = [
            {"short_message": "log1", "item_id": 1},
            {"short_message": "log2", "item_id": 2},
            {"short_message": "log3", "item_id": 3},
        ]
        dummy_messages = ["msg1", "msg2", "msg3"]
        mock_http = MagicMock()
        mock_http.post.side_effect = mock_post

        retry_policy = RetryPolicy(
            max_retries=1,
            base_backoff_seconds=0.01,
            max_backoff_seconds=0.05,
        )

        outcome = client.deliver_batch(
            gelf_batch=gelf_batch,
            http_client=mock_http,
            gelf_url="http://mock-graylog/gelf",
            retry_policy=retry_policy,
            dry_run=False,
            is_running_fn=lambda: True,
            on_dead_letter=mock_dead_letter,
            messages=dummy_messages,
        )

        assert outcome is DeliveryOutcome.DEAD_LETTERED
        assert len(dlq_batches) == 1
        # Only item 2 should be in DLQ, since items 1 and 3 were delivered!
        assert len(dlq_batches[0]) == 1
        assert dlq_batches[0][0]["item_id"] == 2
        assert dlq_msgs[0] == ["msg2"]


class TestPydanticModelStatelessValidation:
    """Verifies Task 4: Elimination of global state mutation; context and subclasses work statelessly."""

    def test_pydantic_validation_context_strict_and_lenient(self) -> None:
        raw_with_extra = sample_log_dict(unexpected_extra="leak_value")

        lenient_event = SecurityLogEvent.model_validate(
            raw_with_extra,
            context={"strict_schema": False},
        )
        assert isinstance(lenient_event.raw_payload, dict)
        assert lenient_event.raw_payload["unexpected_extra"] == "leak_value"

        with pytest.raises(Exception):
            SecurityLogEvent.model_validate(
                raw_with_extra,
                context={"strict_schema": True},
            )

    def test_subclass_strict_and_lenient_models(self) -> None:
        raw_with_extra = sample_log_dict(vendor_field="custom_val")

        with pytest.raises(Exception):
            StrictSecurityLogEvent(**raw_with_extra)

        lenient_event = LenientSecurityLogEvent(**raw_with_extra)
        assert isinstance(lenient_event.raw_payload, dict)
        assert lenient_event.raw_payload["vendor_field"] == "custom_val"


class TestRetryConsumerLifecycleIntegration:
    """Verifies Task 1: RetryTopicConsumer managed background lifecycle in GraylogConsumerWorker."""

    def test_worker_starts_and_stops_retry_consumer_thread(self, tmp_path: Path) -> None:
        db_file = str(tmp_path / "metrics.db")
        broker_db = str(tmp_path / "broker.db")
        with SharedMetricsStore(db_file) as store:
            worker = GraylogConsumerWorker(
                metrics_store=store,
                enable_tiered_retry=True,
            )
            worker.broker_db_path = broker_db
            try:
                started = worker.start_retry_consumer()
                assert started is True
                assert worker._retry_consumer_thread is not None
                assert worker._retry_consumer_thread.is_alive()
                assert worker.retry_consumer is not None
                assert worker.retry_consumer.running is True

                worker.stop_retry_consumer()
                assert worker._retry_consumer_thread is None
                assert worker.retry_consumer is None
            finally:
                worker.close()

    def test_worker_disabled_tiered_retry_does_not_start_thread(self, tmp_path: Path) -> None:
        db_file = str(tmp_path / "metrics.db")
        with SharedMetricsStore(db_file) as store:
            worker = GraylogConsumerWorker(
                metrics_store=store,
                enable_tiered_retry=False,
            )
            try:
                started = worker.start_retry_consumer()
                assert started is False
                assert worker._retry_consumer_thread is None
                assert worker.retry_consumer is None
            finally:
                worker.close()


class TestRealDLQReplay:
    """Verifies Task 2: Real DLQ replay in BrokerDeadLetterPublisher re-publishes to target and commits."""

    def test_real_dlq_replay_end_to_end(self, tmp_path: Path) -> None:
        broker_db = str(tmp_path / "broker_dlq_replay.db")
        dlq_topic = "test-security-logs.dlq"
        target_topic = "test-security-logs"

        publisher = BrokerDeadLetterPublisher(
            dlq_topic=dlq_topic,
            default_source_topic=target_topic,
            broker_db_path=broker_db,
            num_partitions=1,
        )

        test_batch = [
            {
                "schema_version": "1.0",
                "client_ip": "10.0.0.99",
                "event_type": "PORT_SCAN",
                "target_resource": "/api/v1/auth",
                "status_code": 403,
                "severity": 4,
                "raw_payload": {"msg": "bad payload 1"},
                "_broker_topic": target_topic,
                "_broker_partition": 0,
                "_broker_offset": 101,
            },
            {
                "schema_version": "1.0",
                "client_ip": "10.0.0.99",
                "event_type": "PORT_SCAN",
                "target_resource": "/api/v1/login",
                "status_code": 401,
                "severity": 4,
                "raw_payload": {"msg": "bad payload 2"},
                "_broker_topic": target_topic,
                "_broker_partition": 0,
                "_broker_offset": 102,
            },
        ]

        published = publisher.publish_messages(
            topic=dlq_topic, messages=test_batch, reason="Delivery failure 503"
        )
        assert published is True

        replayed_count = publisher.replay(
            source_topic=dlq_topic,
            target_topic=target_topic,
            limit=10,
        )
        assert replayed_count == 2

        consumer = Consumer(
            {
                "bootstrap.servers": "localhost:9092",
                "group.id": "test-replay-verifier-group",
                "auto.offset.reset": "earliest",
                "broker.db.path": broker_db,
                "num_partitions": 1,
            },
            db_path=broker_db,
            num_partitions=1,
        )
        consumer.subscribe([target_topic])

        replayed_events = []
        for _ in range(10):
            msg = consumer.poll(timeout=0.2)
            if msg is not None:
                headers = dict(msg.headers() or [])
                assert "x-replay-id" in headers or b"x-replay-id" in headers
                assert "x-original-event-id" in headers or b"x-original-event-id" in headers
                data = json.loads(msg.value().decode("utf-8"))
                replayed_events.append(data)
                if len(replayed_events) == 2:
                    break
        consumer.close()

        assert len(replayed_events) == 2
        assert replayed_events[0]["_event_id"] == "0:101"
        assert replayed_events[1]["_event_id"] == "0:102"

        # Replay again: DLQ was committed, so subsequent replay returns 0
        replayed_count_again = publisher.replay(
            source_topic=dlq_topic,
            target_topic=target_topic,
            limit=10,
        )
        assert replayed_count_again == 0


class TestLegacyAliasesRemoved:
    """Verifies Task 3: Redundant legacy aliases are completely eliminated."""

    def test_config_aliases_removed(self) -> None:
        for legacy_name in [
            "TOPIC",
            "PRIORITY_TOPIC",
            "PARTITIONS",
            "CONSUMER_GROUP",
            "DLQ_TOPIC",
            "RETRY_1M_TOPIC",
            "RETRY_10M_TOPIC",
            "POISON_TOPIC",
        ]:
            assert not hasattr(config, legacy_name), f"Legacy alias '{legacy_name}' still exists in config!"

        # Canonical BROKER_* constants must exist
        assert hasattr(config, "BROKER_TOPIC")
        assert hasattr(config, "BROKER_PRIORITY_TOPIC")
        assert hasattr(config, "BROKER_PARTITIONS")
        assert hasattr(config, "BROKER_CONSUMER_GROUP")
        assert hasattr(config, "BROKER_DLQ_TOPIC")
        assert hasattr(config, "ENABLE_TIERED_RETRY")

    def test_ingestor_lag_aliases_removed(self) -> None:
        assert not hasattr(
            ingestor.WalLogBufferingMiddleware, "query_broker_lag_snapshot"
        ), "Legacy alias 'query_broker_lag_snapshot' still exists on WalLogBufferingMiddleware!"
        assert not hasattr(
            ingestor.WalLogBufferingMiddleware, "_query_broker_lag_snapshot"
        ), "Legacy alias '_query_broker_lag_snapshot' still exists on WalLogBufferingMiddleware!"
        assert hasattr(
            ingestor.WalLogBufferingMiddleware, "query_broker_native_lag"
        ), "Canonical 'query_broker_native_lag' must exist on WalLogBufferingMiddleware!"


class TestSQLitePragmaTuningExternalization:
    """Verifies Task 1: SQLite PRAGMA tuning parameters are externalized in config and injected."""

    def test_config_defaults(self) -> None:
        assert hasattr(config, "SQLITE_CACHE_SIZE_KB")
        assert config.SQLITE_CACHE_SIZE_KB == -64000
        assert hasattr(config, "SQLITE_BUSY_TIMEOUT_MS")
        assert config.SQLITE_BUSY_TIMEOUT_MS == 15000

    def test_sqlite_storage_uses_configured_pragmas(self, tmp_path: Path) -> None:
        db_path = str(tmp_path / "pragma_test.db")
        storage = SQLiteBrokerStorage(
            db_path=db_path,
            cache_size_kb=-32000,
            busy_timeout_ms=5000,
        )
        conn = storage.get_connection()
        cache_row = conn.execute("PRAGMA cache_size;").fetchone()
        busy_row = conn.execute("PRAGMA busy_timeout;").fetchone()
        assert cache_row[0] == -32000
        assert busy_row[0] == 5000

    def test_sqlite_storage_environment_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SQLITE_CACHE_SIZE_KB", "-16000")
        monkeypatch.setenv("SQLITE_BUSY_TIMEOUT_MS", "3000")
        db_path = str(tmp_path / "pragma_env_test.db")
        storage = SQLiteBrokerStorage(db_path=db_path)
        conn = storage.get_connection()
        cache_row = conn.execute("PRAGMA cache_size;").fetchone()
        busy_row = conn.execute("PRAGMA busy_timeout;").fetchone()
        assert cache_row[0] == -16000
        assert busy_row[0] == 3000


class TestDeliveryWorkerPoolExternalization:
    """Verifies Task 2: GELF split worker pool and split-post configuration."""

    def test_config_gelf_split_max_workers_default(self) -> None:
        assert hasattr(config, "GELF_SPLIT_MAX_WORKERS")
        assert config.GELF_SPLIT_MAX_WORKERS == 20
        assert hasattr(config, "GELF_SPLIT_POST")

    def test_delivery_client_custom_worker_count(self) -> None:
        client = GraylogDeliveryClient(split_max_workers=5)
        assert client._split_max_workers == 5

    def test_delivery_client_inherits_config(self) -> None:
        client = GraylogDeliveryClient()
        assert client._split_max_workers == config.GELF_SPLIT_MAX_WORKERS


class TestSimulatorAndN8nParameterization:
    """Verifies Task 3: Simulator IPs and n8n webhook expression parameterization."""

    def test_spike_demo_has_parameterized_constants(self) -> None:
        import simulators.spike_test_demo as demo

        assert hasattr(demo, "ATTACKER_IP")
        assert hasattr(demo, "HONEYTOKEN_IP")
        assert hasattr(demo, "NORMAL_SUBNET_PREFIX")

    def test_n8n_workflow_contains_env_expression(self) -> None:
        workflow_path = (
            Path(__file__).resolve().parent.parent
            / "n8n"
            / "scenario2_bruteforce_response_workflow.json"
        )
        assert workflow_path.exists(), f"Workflow file not found at {workflow_path}"
        with open(workflow_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        found_env_url = False
        for node in data.get("nodes", []):
            if node.get("name") == "Block Attacker IP":
                url_expr = node.get("parameters", {}).get("url", "")
                if "$env.AUTOMATION_WEBHOOK_BASE_URL" in url_expr:
                    found_env_url = True
                    assert "http://host.docker.internal:5000" in url_expr

        assert (
            found_env_url
        ), "n8n Block Attacker IP node does not use $env.AUTOMATION_WEBHOOK_BASE_URL expression!"


class TestBenchmarkAndSimulatorsFairness:
    """Verifies Task 1: Fair benchmark methodology without artificial handicaps."""

    def test_compare_middleware_cli_arguments(self) -> None:
        import simulators.compare_middleware as comp

        parser = argparse.ArgumentParser()
        assert hasattr(comp, "benchmark_single_direct_graylog")
        assert hasattr(comp, "benchmark_single_middleware")
        assert hasattr(comp, "benchmark_batch_direct_graylog")
        assert hasattr(comp, "benchmark_batch_middleware")
        assert hasattr(comp, "set_mock_graylog_latency")

    def test_compare_middleware_uses_connection_pooling(self) -> None:
        import simulators.compare_middleware as comp

        # Ensure no artificial max_keepalive_connections=0 remains in the module source
        import inspect

        source = inspect.getsource(comp)
        assert "max_keepalive_connections=0" not in source, (
            "Found artificial handicap 'max_keepalive_connections=0' in compare_middleware.py!"
        )


class TestHMACSignatureAcrossSimulators:
    """Verifies Task 2: Real HMAC-SHA256 signature generation and verification."""

    def test_auth_helper_signature_generation(self) -> None:
        from simulators.auth_helper import generate_hmac_signature_headers
        from middleware.auth import verify_hmac_signature

        key = "test-secret-ingest-key"
        payload = {"event": "test_event", "code": 123}
        body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        headers = generate_hmac_signature_headers(key, body_bytes)
        assert "X-Signature" in headers
        assert "X-Timestamp" in headers

        verified = verify_hmac_signature(
            raw_body=body_bytes,
            timestamp_str=headers["X-Timestamp"],
            provided_signature=headers["X-Signature"],
            allowed_keys=[key],
        )
        assert verified == key

    def test_client_integration_snippet_defaults_to_hmac(self) -> None:
        import simulators.client_integration_snippet as snippet

        client = snippet.SafeSecurityLogClient()
        assert client.use_hmac is True


class TestMockGraylogDeduplicationAndLatency:
    """Verifies Task 3: Mock Graylog deduplication metrics and simulated latency."""

    def test_mock_graylog_state_tracking(self) -> None:
        from simulators.mock_graylog_server import MockGraylogState

        state = MockGraylogState()
        records = [
            {"version": "1.1", "short_message": "ev1", "_event_id": "evt-001", "_broker_topic": "test"},
            {"version": "1.1", "short_message": "ev2", "_event_id": "evt-002", "_broker_topic": "test"},
            {"version": "1.1", "short_message": "ev1-dup", "_event_id": "evt-001", "_broker_topic": "test"},
        ]
        accepted = state.ingest_gelf_records(records)
        assert accepted == 3
        assert state.total_received == 3
        assert state.unique_events == 2
        assert state.duplicate_events == 1
        assert state.total_gelf_received == 2
        assert state.duplicate_gelf_ignored == 1

        report = state.get_verification_report()
        assert report["total_received"] == 3
        assert report["unique_events"] == 2
        assert report["duplicate_events"] == 1

    def test_mock_graylog_stats_and_latency_endpoints(self) -> None:
        from simulators.mock_graylog_server import app as graylog_app, graylog_state
        client = TestClient(graylog_app)

        graylog_state.reset()
        records = [
            {"version": "1.1", "short_message": "ev1", "_event_id": "id-10"},
            {"version": "1.1", "short_message": "ev1-dup", "_event_id": "id-10"},
        ]
        ndjson = "\n".join(json.dumps(r) for r in records)
        resp = client.post("/gelf", content=ndjson)
        assert resp.status_code == 202

        stats_resp = client.get("/stats")
        assert stats_resp.status_code == 200
        stats = stats_resp.json()
        assert stats["total_received"] == 2
        assert stats["unique_events"] == 1
        assert stats["duplicate_events"] == 1
        assert "deduplication_note" in stats

        lat_resp = client.post("/latency/0.05")
        assert lat_resp.status_code == 200
        assert lat_resp.json()["simulated_latency_sec"] == 0.05
        assert graylog_state.simulated_latency_sec == 0.05

        client.post("/latency/0")
        assert graylog_state.simulated_latency_sec == 0.0

    def test_mock_graylog_capacity_and_queue_saturation(self) -> None:
        from simulators.mock_graylog_server import app as graylog_app, graylog_state
        client = TestClient(graylog_app)

        graylog_state.reset()
        cap_resp = client.get("/capacity")
        assert cap_resp.status_code == 200
        cap_data = cap_resp.json()
        assert cap_data["max_ingest_eps"] == 650.0
        assert cap_data["queue_capacity"] == 1500

        # Tight capacity for deterministic overflow test (capacity=5, eps=10)
        set_resp = client.post("/capacity", json={"max_ingest_eps": 10.0, "queue_capacity": 5})
        assert set_resp.status_code == 200
        assert set_resp.json()["queue_capacity"] == 5

        records_fit = [
            {"version": "1.1", "short_message": f"fit_{i}", "_event_id": f"fit-{i}"}
            for i in range(5)
        ]
        resp_fit = client.post("/gelf", content="\n".join(json.dumps(r) for r in records_fit))
        assert resp_fit.status_code == 202
        assert resp_fit.json()["received"] == 5
        assert graylog_state.get_current_backlog() > 0

        # Exceed queue_capacity (5 + 1 > 5) -> HTTP 503
        record_overflow = [{"version": "1.1", "short_message": "overflow_1"}]
        resp_overflow = client.post("/gelf", content=json.dumps(record_overflow[0]))
        assert resp_overflow.status_code == 503
        data_503 = resp_overflow.json()
        assert "OpenSearch EsRejectedExecutionException" in data_503["error"]
        assert data_503["dropped_overflow_events"] == 1
        assert data_503["rejected_503_batches"] == 1

        stats = client.get("/stats").json()
        assert stats["dropped_overflow_events"] == 1
        assert stats["rejected_503_batches"] == 1

        reset_resp = client.post("/reset")
        assert reset_resp.status_code == 200
        assert reset_resp.json()["dropped_overflow_events"] == 0
        stats_after = client.get("/stats").json()
        assert stats_after["dropped_overflow_events"] == 0
        assert stats_after["queue_capacity"] == 1500


class TestOuterMiddlewareApiKeyInheritance:
    """Verifies that MIDDLEWARE_API_KEY from outer .env is seamlessly inherited by config and auth."""

    def test_config_inherits_middleware_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("INGEST_API_KEYS", raising=False)
        monkeypatch.delenv("INGEST_API_KEYS_FILE", raising=False)
        monkeypatch.setenv("MIDDLEWARE_API_KEY", "inherited-outer-key-777")

        settings = config.load_settings()
        assert "inherited-outer-key-777" in settings.ingest_api_keys

    def test_auth_inherits_middleware_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from middleware.auth import get_ingest_api_keys

        monkeypatch.delenv("INGEST_API_KEYS", raising=False)
        monkeypatch.delenv("INGEST_API_KEYS_FILE", raising=False)
        monkeypatch.setenv("MIDDLEWARE_API_KEY", "inherited-outer-key-888")

        keys = get_ingest_api_keys()
        assert "inherited-outer-key-888" in keys





