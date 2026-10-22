# -*- coding: utf-8 -*-
"""
Production Resilience & Observability Test Suite.

Verifies:
1. Deep Healthcheck (/v1/health & legacy /health) with SQLite WAL lock detection and RFC 7807 503 details.
2. Schema Tolerance (STRICT_SCHEMA) toggle with surplus field auto-merge and PII redaction.
3. Asynchronous Fail-Open Circuit Breaker client (SafeSecurityLogClient) with local file fallback.
4. Mock Graylog Server End-to-End Tail Latency Telemetry (p95/p99) per lane and reset behavior.
"""

import json
import os
import queue
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

# Ensure scenario2-middleware paths are resolved
_test_dir = Path(__file__).resolve().parent
_root_dir = _test_dir.parent
for p in [str(_root_dir / "src"), str(_root_dir / "simulators"), str(_root_dir)]:
    if p not in sys.path:
        sys.path.insert(0, p)

import config
import ingestor
from client_integration_snippet import SafeSecurityLogClient, log_iot_event
from ingestor import (
    BROKER_PARTITIONS,
    BROKER_TOPIC,
    SecurityLogEvent,
    app as ingestor_app,
)
from middleware.errors import PROBLEM_JSON_MEDIA_TYPE
from mock_graylog_server import app as graylog_app, graylog_state
from tests.test_middleware import sample_event_dict


# ===========================================================================
# 1. Deep Healthcheck Tests (/v1/health and legacy /health)
# ===========================================================================
class TestDeepHealthcheck:
    def test_v1_health_normal_returns_200_with_storage_fields(self) -> None:
        client = TestClient(ingestor_app)
        resp = client.get("/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        # Verify backward compatibility
        assert data["status"] == "healthy"
        assert data["topic"] == BROKER_TOPIC
        assert data["partitions"] == BROKER_PARTITIONS
        assert "in_flight_producer_messages" in data
        # Verify deep healthcheck enhancement fields
        assert data["storage"] == "healthy"
        assert data["wal_writable"] is True
        # Verify no Deprecation header on v1
        assert "Deprecation" not in resp.headers

    def test_legacy_health_normal_returns_200_and_deprecation_header(self) -> None:
        client = TestClient(ingestor_app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.headers.get("Deprecation") == "true"
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["storage"] == "healthy"
        assert data["wal_writable"] is True

    def test_v1_health_db_lock_returns_503_rfc7807_problem_json(self) -> None:
        client = TestClient(ingestor_app)
        mw = ingestor._active_middleware()

        # Simulate database locked condition on middleware check_health
        with patch.object(
            mw,
            "check_health",
            side_effect=sqlite3.OperationalError("database is locked"),
        ):
            resp = client.get("/v1/health")
            assert resp.status_code == 503
            assert resp.headers["content-type"] == PROBLEM_JSON_MEDIA_TYPE
            data = resp.json()
            assert data["type"] == "about:blank"
            assert data["title"] == "Service Unavailable"
            assert data["status"] == 503
            assert data["detail"] == "Broker WAL storage unhealthy or locked"
            assert data["instance"] == "/v1/health"

    def test_legacy_health_error_retains_deprecation_header_on_503(self) -> None:
        client = TestClient(ingestor_app)
        mw = ingestor._active_middleware()

        with patch.object(
            mw,
            "check_health",
            side_effect=sqlite3.OperationalError("disk I/O error"),
        ):
            resp = client.get("/health")
            assert resp.status_code == 503
            assert resp.headers["content-type"] == PROBLEM_JSON_MEDIA_TYPE
            assert resp.headers.get("Deprecation") == "true"
            data = resp.json()
            assert data["title"] == "Service Unavailable"
            assert data["detail"] == "Broker WAL storage unhealthy or locked"

    def test_healthcheck_with_real_exclusive_sqlite_lock(self, tmp_path: Path) -> None:
        """Tests that a real exclusive transaction holding the lock triggers a 503 within 0.1s."""
        db_file = str(tmp_path / "test_wal_locked.db")
        conn = sqlite3.connect(db_file, isolation_level=None)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("CREATE TABLE IF NOT EXISTS probe (id INT);")
        # Hold an exclusive write lock
        conn.execute("BEGIN EXCLUSIVE;")

        mw = ingestor._active_middleware()
        # Point broker producer db_path or override mw.producer.db_path to locked file
        mock_producer = MagicMock()
        mock_producer.db_path = db_file
        # When check_health runs on the mock producer, use actual sqlite connection with 0.1s timeout
        def locked_check_health(timeout: float = 0.1) -> bool:
            p_conn = sqlite3.connect(db_file, timeout=timeout, isolation_level=None)
            try:
                p_conn.execute(f"PRAGMA busy_timeout = {int(timeout * 1000)};")
                p_conn.execute("BEGIN IMMEDIATE;")
                p_conn.execute("ROLLBACK;")
                return True
            finally:
                p_conn.close()

        mock_producer.check_health.side_effect = locked_check_health

        try:
            with patch.object(mw, "producer", mock_producer):
                client = TestClient(ingestor_app)
                t0 = time.perf_counter()
                resp = client.get("/v1/health")
                elapsed = time.perf_counter() - t0
                assert resp.status_code == 503
                assert elapsed < 0.5  # Must fail fast within probe timeout
                assert resp.json()["detail"] == "Broker WAL storage unhealthy or locked"
        finally:
            conn.execute("ROLLBACK;")
            conn.close()


# ===========================================================================
# 2. Schema Tolerance (STRICT_SCHEMA) and PII Auto-Masking Tests
# ===========================================================================
class TestSchemaToleranceAndMasking:
    @pytest.fixture(autouse=True)
    def reset_schema_override(self) -> None:
        SecurityLogEvent.set_strict_schema(None)
        yield
        SecurityLogEvent.set_strict_schema(None)

    def test_strict_schema_true_rejects_extra_fields_with_422(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(config, "STRICT_SCHEMA", True)
        SecurityLogEvent.set_strict_schema(True)

        payload = sample_event_dict(unexpected_vendor_field="extra_value")
        with pytest.raises(ValidationError):
            SecurityLogEvent(**payload)

        client = TestClient(ingestor_app)
        resp = client.post("/v1/ingest", json=payload)
        assert resp.status_code == 422
        assert resp.headers["content-type"] == PROBLEM_JSON_MEDIA_TYPE

    def test_strict_schema_false_absorbs_extra_fields_into_raw_payload(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(config, "STRICT_SCHEMA", False)
        SecurityLogEvent.set_strict_schema(False)

        raw = {
            "client_ip": "10.0.1.55",
            "event_type": "PORT_SCAN",
            "target_resource": "/api/v1/status",
            "status_code": 200,
            "severity": 6,
            "raw_payload": {"initial_key": "initial_val"},
            "device_firmware": "v3.1.4",
            "hardware_serial": "ESP32-NODE-09",
        }
        event = SecurityLogEvent(**raw)
        assert isinstance(event.raw_payload, dict)
        # Extra fields absorbed losslessly
        assert event.raw_payload["device_firmware"] == "v3.1.4"
        assert event.raw_payload["hardware_serial"] == "ESP32-NODE-09"
        assert event.raw_payload["initial_key"] == "initial_val"
        assert "_extra_fields" in event.raw_payload
        assert event.raw_payload["_extra_fields"]["device_firmware"] == "v3.1.4"

    def test_strict_schema_false_masks_sensitive_extra_fields_as_redacted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(config, "STRICT_SCHEMA", False)
        SecurityLogEvent.set_strict_schema(False)

        raw = {
            "client_ip": "10.0.1.55",
            "event_type": "LOGIN",
            "target_resource": "/api/v1/auth",
            "status_code": 200,
            "severity": 6,
            "raw_payload": {},
            "secret_token": "super_secret_session_token",
            "userPassword": "ClearTextPassword123!",
            "api_key": "ak_live_leaked_secret",
            "non_sensitive_field": "public_data",
        }
        event = SecurityLogEvent(**raw)
        assert isinstance(event.raw_payload, dict)
        # Sensitive fields must be masked as [REDACTED]
        assert event.raw_payload["secret_token"] == "[REDACTED]"
        assert event.raw_payload["userPassword"] == "[REDACTED]"
        assert event.raw_payload["api_key"] == "[REDACTED]"
        assert event.raw_payload["_extra_fields"]["secret_token"] == "[REDACTED]"
        assert event.raw_payload["_extra_fields"]["userPassword"] == "[REDACTED]"
        # Non-sensitive field preserved
        assert event.raw_payload["non_sensitive_field"] == "public_data"

    def test_strict_schema_false_ingest_endpoint_and_serialization(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(config, "STRICT_SCHEMA", False)
        SecurityLogEvent.set_strict_schema(False)

        client = TestClient(ingestor_app)
        raw_req = {
            "client_ip": "192.168.1.99",
            "event_type": "BRUTE_FORCE",
            "target_resource": "/login",
            "status_code": 401,
            "severity": 2,
            "raw_payload": {"attempt": 1},
            "passwd": "leaked_plain_password",
            "sensor_model": "DHT22",
        }
        with patch.object(ingestor.wal_middleware, "enqueue_event_async"):
            resp = client.post("/v1/ingest", json=raw_req)
            assert resp.status_code == 202
            assert resp.json()["status"] == "queued"

        # Verify serialization produces redacted JSON payload
        event = SecurityLogEvent(**raw_req)
        _key, val_bytes, _ts = ingestor.wal_middleware._serialize_event(event)
        data = json.loads(val_bytes.decode("utf-8"))
        assert data["raw_payload"]["passwd"] == "[REDACTED]"
        assert data["raw_payload"]["sensor_model"] == "DHT22"


# ===========================================================================
# 3. Client Asynchronous Fail-Open Circuit Breaker Tests
# ===========================================================================
class TestSafeSecurityLogClient:
    def test_client_send_log_non_blocking_0ms(self, tmp_path: Path) -> None:
        fallback_file = str(tmp_path / "fallback.jsonl")
        client = SafeSecurityLogClient(
            endpoint_url="http://localhost:8000/v1/ingest",
            max_queue_size=100,
            fallback_file_path=fallback_file,
        )
        try:
            sample_log = {
                "client_ip": "10.0.0.1",
                "event_type": "PORT_SCAN",
                "target_resource": "/test",
                "status_code": 200,
                "severity": 6,
                "raw_payload": {"msg": "benchmark"},
            }
            t0 = time.perf_counter()
            queued = client.send_log(sample_log)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            assert queued is True
            assert elapsed_ms < 10.0  # Must return immediately in sub-millisecond range
        finally:
            client.close()

    def test_client_circuit_trips_to_open_on_failures_and_writes_fallback(
        self, tmp_path: Path
    ) -> None:
        fallback_file = str(tmp_path / "fallback.jsonl")
        client = SafeSecurityLogClient(
            endpoint_url="http://invalid.local.outage:8000/v1/ingest",
            max_queue_size=50,
            failure_threshold=3,
            recovery_timeout=5.0,
            fallback_file_path=fallback_file,
            request_timeout=0.05,
        )
        try:
            # Send 5 events; with connection failure, threshold 3 triggers OPEN
            for i in range(5):
                client.send_log({"event_index": i, "client_ip": f"10.0.0.{i}"})

            # Wait for background worker to attempt deliveries
            client.flush(timeout=2.0)

            # Circuit must be OPEN
            assert client.state == "OPEN"
            assert client.consecutive_failures >= 3

            # Any subsequent log must be directly appended to fallback file
            client.send_log({"event_index": 99, "client_ip": "10.0.0.99"})

            # Verify fallback file contents
            assert os.path.exists(fallback_file)
            with open(fallback_file, "r", encoding="utf-8") as f:
                lines = [json.loads(line) for line in f if line.strip()]

            # All 6 logs must be safely preserved in fallback storage without loss
            assert len(lines) >= 6
            indices = [item["event_index"] for item in lines]
            assert 99 in indices
            for i in range(5):
                assert i in indices
        finally:
            client.close()

    def test_client_queue_full_fail_open_writes_directly_to_fallback(
        self, tmp_path: Path
    ) -> None:
        fallback_file = str(tmp_path / "fallback_full.jsonl")
        # Create client with max_queue_size=2 and worker blocked/stopped
        client = SafeSecurityLogClient(
            endpoint_url="http://localhost:8000/v1/ingest",
            max_queue_size=2,
            fallback_file_path=fallback_file,
        )
        # Stop worker so queue fills up
        client._stop_event.set()
        try:
            client.send_log({"id": 1})
            client.send_log({"id": 2})
            # 3rd log exceeds queue capacity -> put_nowait raises queue.Full -> writes to fallback
            t0 = time.perf_counter()
            client.send_log({"id": 3})
            elapsed_ms = (time.perf_counter() - t0) * 1000
            assert elapsed_ms < 20.0

            assert os.path.exists(fallback_file)
            with open(fallback_file, "r", encoding="utf-8") as f:
                saved = [json.loads(line) for line in f if line.strip()]
            assert any(item.get("id") == 3 for item in saved)
        finally:
            client.close()

    def test_esp32_snippet_fail_open_isolation(self) -> None:
        """Verifies that ESP32 log_iot_event never raises exceptions even on connection failure."""
        outcome = log_iot_event("192.168.1.50", "GPIO_14", "TEST_OFF")
        # Connection to dummy 192.168.1.100 will fail or timeout, must return False without crashing
        assert outcome in (True, False)


# ===========================================================================
# 4. Mock Graylog Server End-to-End Latency Telemetry Tests
# ===========================================================================
class TestMockGraylogLatencyTelemetry:
    @pytest.fixture(autouse=True)
    def reset_graylog(self) -> None:
        graylog_state.reset()
        yield
        graylog_state.reset()

    def test_mock_graylog_status_calculates_lane_latency_statistics(self) -> None:
        client = TestClient(graylog_app)
        now = time.time()

        # Ingest 3 standard records with artificial timestamp gaps
        std_batch = (
            json.dumps({
                "version": "1.1",
                "host": "test-host",
                "short_message": "Standard log 1",
                "timestamp": now - 1.5,
                "level": 6,
                "_event_id": "0:1",
                "_broker_topic": "security-logs",
                "_event_type": "PORT_SCAN",
            })
            + "\n"
            + json.dumps({
                "version": "1.1",
                "host": "test-host",
                "short_message": "Standard log 2",
                "timestamp": now - 0.5,
                "level": 6,
                "_event_id": "0:2",
                "_broker_topic": "security-logs",
                "_event_type": "PORT_SCAN",
            })
        )
        r1 = client.post("/gelf", content=std_batch.encode("utf-8"))
        assert r1.status_code == 202

        # Ingest 1 priority honeytoken record with near-zero latency
        prio_batch = json.dumps({
            "version": "1.1",
            "host": "test-host",
            "short_message": "HONEYTOKEN_ACCESS Alert",
            "timestamp": now - 0.05,
            "level": 1,
            "_event_id": "0:100",
            "_broker_topic": "security-logs.priority",
            "_event_type": "HONEYTOKEN_ACCESS",
            "_honeytoken_alert": True,
        })
        r2 = client.post("/gelf", content=prio_batch.encode("utf-8"))
        assert r2.status_code == 202

        # Query GET /status
        resp = client.get("/status")
        assert resp.status_code == 200
        data = resp.json()

        assert "latency_telemetry" in data
        telem = data["latency_telemetry"]
        assert "standard_lane" in telem
        assert "priority_lane" in telem

        std_stats = telem["standard_lane"]
        assert std_stats["count"] == 2
        assert std_stats["min_sec"] > 0.0
        assert std_stats["max_sec"] >= std_stats["min_sec"]
        assert std_stats["avg_sec"] > 0.0
        assert "p95_sec" in std_stats
        assert "p99_sec" in std_stats

        prio_stats = telem["priority_lane"]
        assert prio_stats["count"] == 1
        assert prio_stats["avg_sec"] < 1.0  # Honeytoken was near-zero latency

    def test_mock_graylog_post_reset_clears_latencies(self) -> None:
        client = TestClient(graylog_app)
        now = time.time()
        gelf_line = json.dumps({
            "version": "1.1",
            "host": "test-host",
            "short_message": "Log to reset",
            "timestamp": now - 0.2,
            "level": 6,
            "_event_id": "0:1",
            "_broker_topic": "security-logs",
            "_event_type": "INFO",
        })
        client.post("/gelf", content=gelf_line.encode("utf-8"))

        s_before = client.get("/status").json()
        assert s_before["latency_telemetry"]["standard_lane"]["count"] == 1

        # Reset
        r_reset = client.post("/reset")
        assert r_reset.status_code == 200

        s_after = client.get("/status").json()
        assert s_after["latency_telemetry"]["standard_lane"]["count"] == 0
        assert s_after["latency_telemetry"]["priority_lane"]["count"] == 0
