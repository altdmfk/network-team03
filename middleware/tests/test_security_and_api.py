import hashlib
import hmac
import json
import math
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
import ingestor
from ingestor import (
    BatchIngestRequest,
    WalLogBufferingMiddleware,
    SecurityLogEvent,
    app as ingestor_app,
)
from metrics_store import SharedMetricsStore
from middleware.auth import (
    REPLAY_WINDOW_SECONDS,
    ReplayProtectionCache,
    get_admin_api_keys,
    get_ingest_api_keys,
    is_auth_enabled,
    replay_cache,
)
from middleware.errors import PROBLEM_JSON_MEDIA_TYPE
from middleware.ingest_rate_limiter import PerClientRateLimiter, ingest_rate_limiter
from middleware.redaction import is_sensitive_key, redact_sensitive_data
from tests.test_middleware import sample_event_dict


# ---------------------------------------------------------------------------
# Test Fixtures & Helpers
# ---------------------------------------------------------------------------
def compute_hmac_signature(key: str, body: bytes) -> str:
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


# ===========================================================================
# 1. PII and Secret Redaction Tests (Requirement 3)
# ===========================================================================
class TestPIIAndSecretRedaction:
    def test_case_variants_and_camelcase_detection(self) -> None:
        patterns = config.REDACTION_PATTERNS
        assert is_sensitive_key("password", patterns)
        assert is_sensitive_key("Password", patterns)
        assert is_sensitive_key("PASSWORD", patterns)
        assert is_sensitive_key("passwd", patterns)
        assert is_sensitive_key("token", patterns)
        assert is_sensitive_key("session_token", patterns)
        assert is_sensitive_key("Session-Token", patterns)
        assert is_sensitive_key("sessionToken", patterns)
        assert is_sensitive_key("api_key", patterns)
        assert is_sensitive_key("apiKey", patterns)
        assert is_sensitive_key("API_KEY", patterns)
        assert is_sensitive_key("api_key_id", patterns)
        assert is_sensitive_key("secret", patterns)
        assert is_sensitive_key("clientSecret", patterns)
        assert is_sensitive_key("authorization", patterns)
        assert is_sensitive_key("Authorization", patterns)
        assert is_sensitive_key("cookie", patterns)
        assert is_sensitive_key("set_cookie", patterns)
        assert is_sensitive_key("session", patterns)
        assert is_sensitive_key("session_id", patterns)

        # Non-sensitive keys
        assert not is_sensitive_key("username", patterns)
        assert not is_sensitive_key("client_ip", patterns)
        assert not is_sensitive_key("target_resource", patterns)
        assert not is_sensitive_key("account", patterns)
        assert not is_sensitive_key("ports", patterns)

    def test_nested_dictionary_and_list_redaction(self) -> None:
        payload = {
            "user": "analyst",
            "auth": {
                "password": "ClearTextPassword123!",
                "apiKey": "ak_live_secret_key_8899",
                "nested": {
                    "session_token": "tok_xyz_secret",
                    "safe_field": 42,
                },
            },
            "items_list": [
                {"token": "first_token_val", "type": "bearer"},
                {"cookie": "session_cookie_secret", "domain": "example.com"},
            ],
            "raw_cookies": ["cookie1", "cookie2"],
            "details": "Regular logging info",
        }

        redacted = redact_sensitive_data(payload)
        assert redacted["user"] == "analyst"
        assert redacted["auth"]["password"] == "[REDACTED]"
        assert redacted["auth"]["apiKey"] == "[REDACTED]"
        assert redacted["auth"]["nested"]["session_token"] == "[REDACTED]"
        assert redacted["auth"]["nested"]["safe_field"] == 42
        assert redacted["items_list"][0]["token"] == "[REDACTED]"
        assert redacted["items_list"][0]["type"] == "bearer"
        assert redacted["items_list"][1]["cookie"] == "[REDACTED]"
        assert redacted["items_list"][1]["domain"] == "example.com"
        assert redacted["raw_cookies"] == "[REDACTED]"
        assert redacted["details"] == "Regular logging info"

    def test_embedded_json_string_redaction(self) -> None:
        inner_json = json.dumps({"api_key": "leaked_123", "action": "login"})
        redacted_str = redact_sensitive_data(inner_json)
        parsed = json.loads(redacted_str)
        assert parsed["api_key"] == "[REDACTED]"
        assert parsed["action"] == "login"

    def test_configurable_redaction_patterns(self) -> None:
        custom_patterns = ["ssn", "credit_card", "pin"]
        payload = {
            "ssn": "123-45-6789",
            "credit_card": "4111-2222-3333-4444",
            "pin": "1234",
            "token": "not_redacted_with_custom_patterns",
        }
        redacted = redact_sensitive_data(payload, patterns=custom_patterns)
        assert redacted["ssn"] == "[REDACTED]"
        assert redacted["credit_card"] == "[REDACTED]"
        assert redacted["pin"] == "[REDACTED]"
        assert redacted["token"] == "not_redacted_with_custom_patterns"


# ===========================================================================
# 2. Authentication & Admin Key Separation Tests (Requirement 1)
# ===========================================================================
class TestAuthenticationAndRoleSeparation:
    @pytest.fixture(autouse=True)
    def reset_replay_cache(self) -> None:
        replay_cache.clear()

    def test_auth_disabled_allows_all_routes_without_headers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTH_ENABLED", "false")
        client = TestClient(ingestor_app)

        with patch("ingestor.wal_middleware.enqueue_event_async"):
            resp = client.post("/v1/ingest", json=sample_event_dict())
            assert resp.status_code == 202
            assert resp.json()["status"] == "queued"

    def test_auth_enabled_rejects_missing_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("INGEST_API_KEYS", "valid-ingest-key")
        client = TestClient(ingestor_app)

        resp = client.post("/v1/ingest", json=sample_event_dict())
        assert resp.status_code == 401
        assert resp.headers["content-type"] == PROBLEM_JSON_MEDIA_TYPE
        assert "WWW-Authenticate" in resp.headers
        data = resp.json()
        assert data["status"] == 401
        assert "Authentication required" in data["detail"]

    def test_auth_api_key_success_and_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("INGEST_API_KEYS", "key-alpha,key-beta")
        client = TestClient(ingestor_app)

        with patch("ingestor.wal_middleware.enqueue_event_async"):
            # Valid key-alpha
            resp_alpha = client.post(
                "/v1/ingest",
                json=sample_event_dict(),
                headers={"X-API-Key": "key-alpha"},
            )
            assert resp_alpha.status_code == 202

            # Valid key-beta
            resp_beta = client.post(
                "/v1/ingest",
                json=sample_event_dict(),
                headers={"X-API-Key": "key-beta"},
            )
            assert resp_beta.status_code == 202

            # Invalid key
            resp_invalid = client.post(
                "/v1/ingest",
                json=sample_event_dict(),
                headers={"X-API-Key": "wrong-key"},
            )
            assert resp_invalid.status_code == 401
            assert resp_invalid.json()["title"] == "Unauthorized"

    def test_auth_hmac_signature_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("INGEST_API_KEYS", "hmac-secret-key-123")
        client = TestClient(ingestor_app)

        raw_event = sample_event_dict()
        body_bytes = json.dumps(raw_event, separators=(",", ":")).encode("utf-8")
        now_ts = str(round(time.time(), 3))
        sig = compute_hmac_signature("hmac-secret-key-123", body_bytes)

        with patch("ingestor.wal_middleware.enqueue_event_async"):
            resp = client.post(
                "/v1/ingest",
                content=body_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-Timestamp": now_ts,
                    "X-Signature": sig,
                },
            )
            assert resp.status_code == 202
            assert resp.json()["status"] == "queued"

    def test_auth_hmac_expired_timestamp_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("INGEST_API_KEYS", "hmac-secret-key-123")
        client = TestClient(ingestor_app)

        raw_event = sample_event_dict()
        body_bytes = json.dumps(raw_event, separators=(",", ":")).encode("utf-8")

        # 305 seconds in the past (> 300s window)
        expired_ts = str(round(time.time() - 305.0, 3))
        sig = compute_hmac_signature("hmac-secret-key-123", body_bytes)

        resp = client.post(
            "/v1/ingest",
            content=body_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Timestamp": expired_ts,
                "X-Signature": sig,
            },
        )
        assert resp.status_code == 401
        assert "replay window" in resp.json()["detail"].lower()

    def test_auth_hmac_replay_attack_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("INGEST_API_KEYS", "hmac-secret-key-123")
        client = TestClient(ingestor_app)

        raw_event = sample_event_dict()
        body_bytes = json.dumps(raw_event, separators=(",", ":")).encode("utf-8")
        now_ts = str(round(time.time(), 3))
        sig = compute_hmac_signature("hmac-secret-key-123", body_bytes)

        headers = {
            "Content-Type": "application/json",
            "X-Timestamp": now_ts,
            "X-Signature": sig,
        }

        with patch("ingestor.wal_middleware.enqueue_event_async"):
            # 1st request succeeds
            resp1 = client.post("/v1/ingest", content=body_bytes, headers=headers)
            assert resp1.status_code == 202

            # 2nd request with identical (signature, timestamp) rejected as replay attack
            resp2 = client.post("/v1/ingest", content=body_bytes, headers=headers)
            assert resp2.status_code == 401
            assert "replay attack" in resp2.json()["detail"].lower()

    def test_admin_key_separation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """
        Ingest key cannot access admin endpoints.
        Admin key cannot access ingest endpoints.
        """
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("INGEST_API_KEYS", "ingest-key-only")
        monkeypatch.setenv("ADMIN_API_KEY", "admin-key-only")
        client = TestClient(ingestor_app)

        with patch("ingestor.wal_middleware.enqueue_event_async"):
            # 1. Ingest key on ingest endpoint -> PASS
            resp = client.post(
                "/v1/ingest",
                json=sample_event_dict(),
                headers={"X-API-Key": "ingest-key-only"},
            )
            assert resp.status_code == 202

            # 2. Admin key on ingest endpoint -> FAIL (401)
            resp = client.post(
                "/v1/ingest",
                json=sample_event_dict(),
                headers={"X-API-Key": "admin-key-only"},
            )
            assert resp.status_code == 401
            assert "Invalid ingest API key" in resp.json()["detail"]

        with patch("ingestor.wal_middleware.query_topic_stats") as mock_stats:
            mock_stats.return_value = {"topics": {}, "total_dlq_count": 0}

            # 3. Ingest key on admin endpoint -> FAIL (401)
            resp = client.get(
                "/v1/admin/dlq",
                headers={"X-API-Key": "ingest-key-only"},
            )
            assert resp.status_code == 401
            assert "Invalid admin API key" in resp.json()["detail"]

            # 4. Admin key on admin endpoint -> PASS (200)
            resp = client.get(
                "/v1/admin/dlq",
                headers={"X-API-Key": "admin-key-only"},
            )
            assert resp.status_code == 200

    def test_keys_loaded_from_secret_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ingest_file = tmp_path / "ingest.secret"
        ingest_file.write_text("file-ingest-key-1\nfile-ingest-key-2\n", encoding="utf-8")

        admin_file = tmp_path / "admin.secret"
        admin_file.write_text("file-admin-key\n", encoding="utf-8")

        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("INGEST_API_KEYS_FILE", str(ingest_file))
        monkeypatch.setenv("ADMIN_API_KEY_FILE", str(admin_file))
        monkeypatch.delenv("INGEST_API_KEYS", raising=False)
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)

        client = TestClient(ingestor_app)

        with patch("ingestor.wal_middleware.enqueue_event_async"):
            resp = client.post(
                "/v1/ingest",
                json=sample_event_dict(),
                headers={"X-API-Key": "file-ingest-key-1"},
            )
            assert resp.status_code == 202

        with patch("ingestor.wal_middleware.query_topic_stats") as mock_stats:
            mock_stats.return_value = {"topics": {}, "total_dlq_count": 0}
            resp = client.get(
                "/v1/admin/dlq",
                headers={"X-API-Key": "file-admin-key"},
            )
            assert resp.status_code == 200


# ===========================================================================
# 3. Per-Client Rate Limiting at Ingestor Tests (Requirement 2)
# ===========================================================================
class TestPerClientRateLimiting:
    def test_rate_limiter_returns_429_with_retry_after(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("INGEST_API_KEYS", "client-rate-key")

        # Custom tight rate limiter: 2 logs/sec, burst capacity = 2.0
        custom_limiter = PerClientRateLimiter(rate_per_sec=2.0, capacity=2.0)
        monkeypatch.setattr(ingestor, "ingest_rate_limiter", custom_limiter)

        client = TestClient(ingestor_app)

        with patch("ingestor.wal_middleware.enqueue_event_async"):
            # 1st request -> OK
            r1 = client.post(
                "/v1/ingest",
                json=sample_event_dict(),
                headers={"X-API-Key": "client-rate-key"},
            )
            assert r1.status_code == 202

            # 2nd request -> OK
            r2 = client.post(
                "/v1/ingest",
                json=sample_event_dict(),
                headers={"X-API-Key": "client-rate-key"},
            )
            assert r2.status_code == 202

            # 3rd request -> Rate limited (429)
            r3 = client.post(
                "/v1/ingest",
                json=sample_event_dict(),
                headers={"X-API-Key": "client-rate-key"},
            )
            assert r3.status_code == 429
            assert "Retry-After" in r3.headers
            retry_after_val = int(r3.headers["Retry-After"])
            assert retry_after_val >= 1
            assert r3.headers["content-type"] == PROBLEM_JSON_MEDIA_TYPE
            assert r3.json()["title"] == "Too Many Requests"

    def test_rate_limiter_client_isolation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("INGEST_API_KEYS", "client-a,client-b")

        custom_limiter = PerClientRateLimiter(rate_per_sec=1.0, capacity=1.0)
        monkeypatch.setattr(ingestor, "ingest_rate_limiter", custom_limiter)

        client = TestClient(ingestor_app)

        with patch("ingestor.wal_middleware.enqueue_event_async"):
            # Client A consumes its token
            r_a1 = client.post(
                "/v1/ingest",
                json=sample_event_dict(),
                headers={"X-API-Key": "client-a"},
            )
            assert r_a1.status_code == 202

            # Client A is rate limited
            r_a2 = client.post(
                "/v1/ingest",
                json=sample_event_dict(),
                headers={"X-API-Key": "client-a"},
            )
            assert r_a2.status_code == 429

            # Client B has its own bucket and succeeds
            r_b1 = client.post(
                "/v1/ingest",
                json=sample_event_dict(),
                headers={"X-API-Key": "client-b"},
            )
            assert r_b1.status_code == 202


# ===========================================================================
# 4. RFC 7807 Problem Details Uniform Error Model (Requirement 5)
# ===========================================================================
class TestRFC7807ProblemDetails:
    def test_validation_error_422_problem_json(self) -> None:
        client = TestClient(ingestor_app)
        bad_payload = {"invalid": "payload"}
        resp = client.post("/v1/ingest", json=bad_payload)
        assert resp.status_code == 422
        assert resp.headers["content-type"] == PROBLEM_JSON_MEDIA_TYPE
        data = resp.json()
        assert data["type"] == "about:blank"
        assert data["title"] == "Unprocessable Entity"
        assert data["status"] == 422
        assert "instance" in data
        assert "errors" in data

    def test_broker_backpressure_503_has_retry_after_and_problem_json(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = TestClient(ingestor_app)

        async def fake_enqueue_exhausted(_event: Any) -> None:
            raise ingestor.HTTPException(
                status_code=503,
                detail="Broker producer local buffer saturated under extreme backpressure.",
                headers={"Retry-After": "1"},
            )

        monkeypatch.setattr(
            ingestor.wal_middleware, "enqueue_event_async", fake_enqueue_exhausted
        )

        resp = client.post("/v1/ingest", json=sample_event_dict())
        assert resp.status_code == 503
        assert resp.headers["content-type"] == PROBLEM_JSON_MEDIA_TYPE
        assert resp.headers.get("Retry-After") == "1"
        data = resp.json()
        assert data["type"] == "about:blank"
        assert data["title"] == "Service Unavailable"
        assert data["status"] == 503
        assert "extreme backpressure" in data["detail"]


# ===========================================================================
# 5. Versioned API & Deprecated Aliases (Requirement 4)
# ===========================================================================
class TestVersionedAPIAndDeprecatedAliases:
    def test_v1_endpoints_do_not_have_deprecation_header(self) -> None:
        client = TestClient(ingestor_app)

        # /v1/health
        h_resp = client.get("/v1/health")
        assert h_resp.status_code == 200
        assert "Deprecation" not in h_resp.headers

        # /v1/metrics
        with patch("ingestor.wal_middleware.query_broker_native_lag") as mock_lag:
            mock_lag.return_value = {
                "broker_total_messages": 0,
                "consumer_committed_total": 0,
                "broker_queue_lag": 0,
                "in_flight_producer_queue": 0,
                "partitions": [],
            }
            m_resp = client.get("/v1/metrics")
            assert m_resp.status_code == 200
            assert "Deprecation" not in m_resp.headers

    def test_legacy_endpoints_return_deprecation_header(self) -> None:
        client = TestClient(ingestor_app)

        # /health
        h_resp = client.get("/health")
        assert h_resp.status_code == 200
        assert h_resp.headers.get("Deprecation") == "true"

        # /metrics
        with patch("ingestor.wal_middleware.query_broker_native_lag") as mock_lag:
            mock_lag.return_value = {
                "broker_total_messages": 0,
                "consumer_committed_total": 0,
                "broker_queue_lag": 0,
                "in_flight_producer_queue": 0,
                "partitions": [],
            }
            m_resp = client.get("/metrics")
            assert m_resp.status_code == 200
            assert m_resp.headers.get("Deprecation") == "true"

        # /ingest
        with patch("ingestor.wal_middleware.enqueue_event_async"):
            i_resp = client.post("/ingest", json=sample_event_dict())
            assert i_resp.status_code == 202
            assert i_resp.headers.get("Deprecation") == "true"

        # /admin/dlq
        with patch("ingestor.wal_middleware.query_topic_stats") as mock_stats:
            mock_stats.return_value = {"topics": {}, "total_dlq_count": 0}
            a_resp = client.get("/admin/dlq")
            assert a_resp.status_code == 200
            assert a_resp.headers.get("Deprecation") == "true"


# ===========================================================================
# 6. BufferError Fast-Fail (Requirement 6)
# ===========================================================================
class TestBufferErrorFastFail:
    def test_buffer_error_fails_fast_without_pathological_sleep(
        self, tmp_path: Path
    ) -> None:
        db_file = str(tmp_path / "fast_fail.db")
        with SharedMetricsStore(db_file) as store:
            # Default retries = 2, sleep = 0.001
            middleware = WalLogBufferingMiddleware(store)
            mock_producer = MagicMock()
            mock_producer.produce.side_effect = BufferError("Queue saturated")
            middleware.producer = mock_producer

            event = SecurityLogEvent(**sample_event_dict())

            start_t = time.monotonic()
            with pytest.raises(ingestor.HTTPException) as exc_info:
                middleware.enqueue_event(event)
            elapsed = time.monotonic() - start_t

            # Must fail fast in well under 0.2s, not 1.0s
            assert elapsed < 0.2
            assert exc_info.value.status_code == 503
            assert exc_info.value.headers.get("Retry-After") == "1"
            assert mock_producer.produce.call_count == 2
