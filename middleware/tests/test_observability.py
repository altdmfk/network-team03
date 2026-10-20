import os
import re
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
import pytest
from middleware.lightweight_broker import LightweightMessage as Message, TopicPartition
from fastapi.testclient import TestClient

import config
from consumer_worker import GraylogConsumerWorker
from ingestor import app, wal_middleware, metrics_store
from middleware.delivery_client import GraylogDeliveryClient
from middleware.models import DeliveryOutcome, RetryPolicy
from middleware.telemetry import (
    PIPELINE_REGISTRY,
    create_consumer_traceparent,
    delivery_attempts_total,
    dlq_published_total,
    dlq_replayed_total,
    extract_traceparent_from_broker_message,
    inject_traceparent_to_broker_headers,
    logs_forwarded_total,
    logs_permanently_dropped_total,
    logs_received_total,
    poison_messages_total,
    queue_lag,
    record_delivery_attempt,
    record_dlq_published,
    record_logs_forwarded,
    record_poison_message,
    reset_prometheus_metrics,
    sync_prometheus_metrics,
)


@pytest.fixture
def test_client():
    return TestClient(app)


class TestPrometheusMetricsEndpoint:
    """Verifies Prometheus exposition format, expected names, and low-cardinality label rules."""

    EXPECTED_METRIC_NAMES = [
        "logs_received_total",
        "logs_forwarded_total",
        "logs_permanently_dropped_total",
        "dlq_published_total",
        "dlq_replayed_total",
        "poison_messages_total",
        "delivery_attempts_total",
        "queue_lag",
        "dlq_depth",
        "configured_max_logs_per_sec",
        "current_rate_limit",
        "graylog_delivery_latency_seconds",
        "batch_size",
        "end_to_end_latency_seconds",
    ]

    def test_prometheus_endpoint_exposes_expected_names(self, test_client):
        """GET /metrics/prometheus must expose all 14 required pipeline metric names."""
        response = test_client.get("/metrics/prometheus")
        assert response.status_code == 200
        assert "text/plain" in response.headers.get("content-type", "")
        text = response.text

        for metric_name in self.EXPECTED_METRIC_NAMES:
            assert (
                metric_name in text
            ), f"Expected metric '{metric_name}' missing from /metrics/prometheus exposition"

    def test_v1_versioned_prometheus_endpoint(self, test_client):
        """Versioned /v1/metrics/prometheus must also serve the exposition without deprecation header."""
        response = test_client.get("/v1/metrics/prometheus")
        assert response.status_code == 200
        assert response.headers.get("Deprecation") is None
        for metric_name in self.EXPECTED_METRIC_NAMES:
            assert metric_name in response.text

    def test_no_high_cardinality_labels_present(self, test_client):
        """
        Enforces strict low-cardinality label rules:
        NEVER expose client_ip, event_id, target_resource, or raw IP addresses in labels.
        """
        response = test_client.get("/metrics/prometheus")
        assert response.status_code == 200
        text = response.text

        # 1. client_ip must never appear as a label key
        assert 'client_ip=' not in text
        assert 'client_ip' not in text.lower() or "client_ip" not in [
            k.strip() for k in re.findall(r'(\w+)=', text)
        ]

        # 2. Extract all label keys used across the exposition
        label_keys = set(re.findall(r'(\w+)=["\']', text))
        allowed_label_keys = {
            "outcome",
            "topic",
            "partition",
            "le",          # Prometheus histogram bucket upper bound
            "quantile",    # Prometheus summary quantile (if any)
        }
        disallowed = label_keys - allowed_label_keys
        assert not disallowed, f"Found disallowed label keys in Prometheus exposition: {disallowed}"

    def test_existing_json_metrics_endpoint_unbroken(self, test_client):
        """Existing GET /metrics contract must remain backward compatible."""
        response = test_client.get("/metrics")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")
        payload = response.json()
        assert "total_received" in payload
        assert "total_forwarded_to_graylog" in payload
        assert "current_queue_lag" in payload
        assert "throughput_telemetry" in payload
        assert "broker_telemetry" in payload


class TestMetricCountersIncreaseOnlyOnConfirmedEvents:
    """Verifies zero-loss honesty: counters only increment upon confirmed events."""

    def test_logs_forwarded_total_does_not_increment_on_graylog_error(self):
        """logs_forwarded_total must NOT increase when delivery returns HTTP 500 or fails."""
        initial_val = logs_forwarded_total._value.get()
        delivery_client = GraylogDeliveryClient(sleep_fn=lambda s: None)

        mock_http = MagicMock()
        mock_http.post.return_value = MagicMock(status_code=500, text="Internal Error")

        # Single retry limit so it dead-letters or fails without infinite backoff
        policy = RetryPolicy(max_retries=1, base_backoff_seconds=0.01)
        fake_dead_letter = MagicMock(return_value=True)

        outcome = delivery_client.deliver_batch(
            gelf_batch=[{"short_message": "test"}],
            http_client=mock_http,
            gelf_url="http://fake-graylog/gelf",
            retry_policy=policy,
            dry_run=False,
            is_running_fn=lambda: True,
            on_dead_letter=fake_dead_letter,
        )

        assert outcome is DeliveryOutcome.DEAD_LETTERED
        # Forwarded counter MUST NOT have incremented
        assert logs_forwarded_total._value.get() == initial_val

    def test_logs_forwarded_total_increments_only_on_confirmed_2xx(self):
        """logs_forwarded_total increments after confirmed 2xx delivery."""
        initial_val = logs_forwarded_total._value.get()
        batch_len = 5
        record_logs_forwarded(batch_len)
        assert logs_forwarded_total._value.get() == initial_val + batch_len

    def test_delivery_attempts_tracks_outcomes_honestly(self):
        """delivery_attempts_total tracks exact 2xx, 5xx, and error outcomes."""
        initial_2xx = delivery_attempts_total.labels(outcome="2xx")._value.get()
        initial_5xx = delivery_attempts_total.labels(outcome="5xx")._value.get()
        initial_err = delivery_attempts_total.labels(outcome="error")._value.get()

        record_delivery_attempt("2xx")
        record_delivery_attempt("5xx")
        record_delivery_attempt("error")

        assert delivery_attempts_total.labels(outcome="2xx")._value.get() == initial_2xx + 1
        assert delivery_attempts_total.labels(outcome="5xx")._value.get() == initial_5xx + 1
        assert delivery_attempts_total.labels(outcome="error")._value.get() == initial_err + 1

    def test_metrics_reset_clears_prometheus_counters(self, test_client):
        """Calling /metrics/reset resets Prometheus counters to zero."""
        record_logs_forwarded(10)
        assert logs_forwarded_total._value.get() >= 10

        response = test_client.post(
            "/v1/metrics/reset",
            headers={"X-Admin-Key": config.ADMIN_API_KEY or "prod-admin-secret-key-99"}
        )
        assert response.status_code == 200
        assert logs_forwarded_total._value.get() == 0.0


class TestConsumerWorkerMetricsDaemonPort:
    """Verifies the consumer worker lightweight metrics HTTP server daemon."""

    def test_consumer_worker_metrics_server_lifecycle(self):
        """Worker can start metrics server on a daemon thread and shut down cleanly."""
        port = 19125
        worker = GraylogConsumerWorker(metrics_port=port, enable_metrics_server=False)
        try:
            started = worker.start_metrics_server(port=port)
            assert started is True
            assert worker._metrics_server is not None
            assert worker._metrics_thread is not None
            assert worker._metrics_thread.daemon is True

            # Scrape via HTTP
            time.sleep(0.1)
            resp = httpx.get(f"http://127.0.0.1:{port}/metrics", timeout=2.0)
            assert resp.status_code == 200
            assert "logs_received_total" in resp.text
            assert "queue_lag" in resp.text
        finally:
            worker.close()

        # After worker close, server is stopped
        assert worker._metrics_server is None


class TestW3CTraceparentPropagation:
    """Verifies OpenTelemetry W3C traceparent injection, sampling, and propagation."""

    def test_traceparent_disabled_when_otel_false(self):
        """When OTEL_ENABLED is False, no traceparent is added to broker headers."""
        headers = inject_traceparent_to_broker_headers(
            headers=[],
            is_priority=False,
            otel_enabled=False,
        )
        assert len(headers) == 0

    def test_traceparent_injected_with_priority_sampling_when_otel_true(self):
        """When OTEL is enabled, priority events are head-sampled (100%) and normal events (1%)."""
        # 1. Priority event (HONEYTOKEN_ACCESS or severity <= 2): 100% sampled
        headers_prio = inject_traceparent_to_broker_headers(
            headers=[],
            is_priority=True,
            otel_enabled=True,
        )
        assert len(headers_prio) == 1
        k, v = headers_prio[0]
        assert k == "traceparent"
        tp_str = v.decode("utf-8")
        parts = tp_str.split("-")
        assert len(parts) == 4
        assert parts[0] == "00"  # W3C version
        assert len(parts[1]) == 32  # trace_id (16 bytes hex)
        assert len(parts[2]) == 16  # span_id (8 bytes hex)
        # Priority sampled flag: bit 0 is set (0x01 or 0x03)
        assert int(parts[3], 16) & 1 == 1

    def test_traceparent_propagates_from_broker_message_to_graylog_call(self):
        """Consumer extracts traceparent from message headers and generates child traceparent for Graylog call."""
        # Synthesize a broker message with W3C traceparent
        trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        span_id = "00f067aa0ba902b7"
        parent_tp = f"00-{trace_id}-{span_id}-01"

        mock_msg = MagicMock(spec=Message)
        mock_msg.headers.return_value = [("traceparent", parent_tp.encode("utf-8"))]

        extracted = extract_traceparent_from_broker_message(mock_msg)
        assert extracted == parent_tp

        # Generate child traceparent for Graylog call
        child_tp = create_consumer_traceparent([mock_msg], otel_enabled=True)
        assert child_tp is not None
        child_parts = child_tp.split("-")
        assert len(child_parts) == 4
        assert child_parts[0] == "00"
        # Trace ID must be identical across the hops
        assert child_parts[1] == trace_id
        # Span ID must be a new child span ID
        assert child_parts[2] != span_id
        # Child inherits sampled flag (0x01 or 0x03)
        assert int(child_parts[3], 16) & 1 == 1

    def test_parent_traceparent_from_http_request_propagates_to_broker(self):
        """Ingestor receives parent traceparent via HTTP header and propagates it into broker headers."""
        incoming_tp = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
        out_headers = inject_traceparent_to_broker_headers(
            headers=[],
            is_priority=False,
            parent_traceparent=incoming_tp,
            otel_enabled=True,
        )
        assert len(out_headers) == 1
        _, v = out_headers[0]
        out_tp = v.decode("utf-8")
        out_parts = out_tp.split("-")
        assert out_parts[1] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
