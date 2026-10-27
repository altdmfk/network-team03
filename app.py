"""EngineSquare main API server for the team project.

The server owns request authentication and security-event creation. It does
not make the final Graylog/Wazuh decision or replace the Middleware service.
Those services consume the JSON event sent to ``/v1/ingest`` when the
``MIDDLEWARE_INGEST_URL`` environment variable is configured.
"""

from collections import defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from flask import Flask, jsonify, request


app = Flask(__name__)

# Demo-only state. A real service would keep these values in a database or
# cache. The field names used in emitted events are fixed by the project plan.
API_KEYS = {
    "test-key-01": {
        # The dictionary key is the authentication secret.  It must never be
        # written to security events or forwarded to Middleware.
        "api_key_id": "key-001",
        "status": "active",
        "allowed_ips": {"127.0.0.1"},
    },
}

REQUEST_COUNTS = defaultdict(int)
SECURITY_EVENTS = []
INCIDENTS = []
BLOCKED_IPS = set()

REQUEST_LIMIT = 5
SUSPICIOUS_USER_AGENT_WORDS = ("kali", "sqlmap", "nikto", "masscan")
LOG_FILE = Path(
    os.getenv("SECURITY_LOG_FILE", Path(__file__).with_name("security_events.jsonl"))
)
MIDDLEWARE_INGEST_URL = os.getenv(
    "MIDDLEWARE_INGEST_URL", "http://localhost:8000/ingest"
)
MIDDLEWARE_API_KEY = os.getenv("MIDDLEWARE_API_KEY", "")
MIDDLEWARE_TIMEOUT_SECONDS = float(os.getenv("MIDDLEWARE_TIMEOUT_SECONDS", "0.5"))

EVENT_SEVERITY = {
    "api_request_allowed": 6,
    "authentication_failed": 4,
    "api_request_rate_limited": 4,
    "api_key_compromised": 1,
    "api_response_completed": 6,
}


def utc_timestamp():
    return datetime.now(timezone.utc).isoformat()


def client_ip():
    """Allow Postman to simulate a remote IP during local demonstrations."""
    return request.headers.get("X-Demo-Client-IP", request.remote_addr or "unknown")


def _forward_to_middleware(event):
    """Forward one event to Middleware using its standard ingest schema."""
    if not MIDDLEWARE_INGEST_URL:
        return False

    middleware_fields = {
        "schema_version": "1.0",
        "timestamp": event["timestamp"],
        "client_ip": event["client_ip"],
        "event_type": event["event_type"],
        "target_resource": event["target_resource"],
        "status_code": event["status_code"],
        "severity": EVENT_SEVERITY.get(event["event_type"], 4),
        "raw_payload": {
            key: value
            for key, value in event.items()
            if key
            not in {
                "timestamp",
                "client_ip",
                "event_type",
                "target_resource",
                "status_code",
            }
        },
    }
    body = json.dumps(middleware_fields, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if MIDDLEWARE_API_KEY:
        headers["X-API-Key"] = MIDDLEWARE_API_KEY
    http_request = Request(
        MIDDLEWARE_INGEST_URL,
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(http_request, timeout=MIDDLEWARE_TIMEOUT_SECONDS) as response:
            return 200 <= response.status < 300
    except (OSError, URLError, TimeoutError):
        # Local API tests still work when Middleware is not running.
        return False


def write_security_log(
    event_type,
    status_code,
    api_key_id="unknown",
    token_id=None,
    detection_reason=None,
    incident_id=None,
    action=None,
    status=None,
):
    """Create, persist, print, and forward a project-format security event."""
    event = {
        "timestamp": utc_timestamp(),
        "event_type": event_type,
        "api_key_id": api_key_id,
        "client_ip": client_ip(),
        "target_resource": request.path,
        "status_code": status_code,
        "user_agent": request.headers.get("User-Agent", "unknown"),
    }
    optional_fields = {
        "token_id": token_id,
        "detection_reason": detection_reason,
        "incident_id": incident_id,
        "action": action,
        "status": status,
    }
    event.update(
        {field: value for field, value in optional_fields.items() if value is not None}
    )

    SECURITY_EVENTS.append(event)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(event, ensure_ascii=False) + "\n")

    _forward_to_middleware(event)
    print(json.dumps(event, ensure_ascii=False), flush=True)
    return event


def find_api_key(raw_api_key):
    return API_KEYS.get(raw_api_key)


def find_api_key_by_id(api_key_id):
    """Return ``(secret, record)`` for a non-secret identifier."""
    for secret, record in API_KEYS.items():
        if record.get("api_key_id") == api_key_id:
            return secret, record
    return None, None


def revoke_api_key(api_key_id, reason="manual_demo_action"):
    _secret, record = find_api_key_by_id(api_key_id)
    if record is None:
        return None
    record["status"] = "revoked"
    record["revoked_reason"] = reason
    return record


def create_incident(api_key_id, reason, blocked_ip=None, ip_blocked=False):
    incident = {
        "incident_id": f"INC-API-{len(INCIDENTS) + 1:03d}",
        "event_type": "api_key_compromised",
        "api_key_id": api_key_id,
        "client_ip": blocked_ip,
        "timestamp": utc_timestamp(),
        "detection_reason": reason,
        "action": "key_revoked_and_ip_blocked",
        "status": "created",
        "ip_blocked": ip_blocked,
    }
    INCIDENTS.append(incident)
    return incident


def automatic_response(api_key_id, reason, suspicious_ip):
    """Simulate the n8n workflow called after detection is confirmed."""
    secret, record = find_api_key_by_id(api_key_id)
    if record is None:
        return {"key_revoked": False, "new_api_key_id": None, "incident": None}

    record["status"] = "revoked"
    record["revoked_reason"] = reason
    new_api_key_id = f"{api_key_id}-renewed"
    new_api_key = f"{secret}-renewed"
    API_KEYS[new_api_key] = {
        "api_key_id": new_api_key_id,
        "status": "active",
        "allowed_ips": set(record["allowed_ips"]),
    }

    ip_blocked = suspicious_ip not in {"unknown", "127.0.0.1"}
    if ip_blocked:
        BLOCKED_IPS.add(suspicious_ip)

    incident = create_incident(
        api_key_id,
        reason,
        blocked_ip=suspicious_ip if ip_blocked else None,
        ip_blocked=ip_blocked,
    )
    write_security_log(
        "api_response_completed",
        200,
        api_key_id=api_key_id,
        detection_reason=reason,
        incident_id=incident["incident_id"],
        action="key_revoked_and_ip_blocked",
        status="completed",
    )
    return {
        "key_revoked": True,
        "new_api_key_id": new_api_key_id,
        # This is returned only as the key-rotation result. It is not included
        # in security events, Middleware payloads, Graylog, or Discord text.
        "new_api_key": new_api_key,
        "ip_blocked": ip_blocked,
        "incident": incident,
    }


def rejected_response(status_code, event_type, api_key_id, reason, message):
    write_security_log(
        event_type,
        status_code,
        api_key_id=api_key_id,
        detection_reason=reason,
    )
    return jsonify(error="request_rejected", message=message), status_code


@app.get("/")
def index():
    return jsonify(
        service="enginesquare-api-server",
        message="Main API server is running",
        test_endpoint="GET /api/data",
        api_key_header="X-API-Key",
    )


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.route("/api/data", methods=["GET", "POST"])
def protected_data():
    current_ip = client_ip()
    raw_api_key = request.headers.get("X-API-Key", "")
    record = find_api_key(raw_api_key)
    api_key_id = record["api_key_id"] if record else "unknown"

    if current_ip in BLOCKED_IPS:
        return rejected_response(
            403,
            "api_key_compromised",
            api_key_id,
            "blocked_ip",
            "Client IP has been blocked",
        )

    if record is None:
        return rejected_response(
            401,
            "authentication_failed",
            "unknown",
            "missing_or_invalid_api_key",
            "Use a valid X-API-Key",
        )

    if record["status"] != "active":
        return rejected_response(
            401,
            "authentication_failed",
            api_key_id,
            "revoked_api_key",
            "API key is revoked",
        )

    REQUEST_COUNTS[api_key_id] += 1
    request_number = REQUEST_COUNTS[api_key_id]

    if current_ip not in record["allowed_ips"]:
        return rejected_response(
            403,
            "api_key_compromised",
            api_key_id,
            "not_allowed_ip",
            "Client IP is not allowed",
        )

    user_agent = request.headers.get("User-Agent", "unknown").lower()
    matched_word = next(
        (word for word in SUSPICIOUS_USER_AGENT_WORDS if word in user_agent),
        None,
    )
    if matched_word:
        return rejected_response(
            403,
            "api_key_compromised",
            api_key_id,
            f"suspicious_user_agent:{matched_word}",
            "Suspicious User-Agent",
        )

    if request_number > REQUEST_LIMIT:
        return rejected_response(
            429,
            "api_request_rate_limited",
            api_key_id,
            f"request_limit_exceeded:{REQUEST_LIMIT}",
            "Request limit exceeded",
        )

    write_security_log("api_request_allowed", 200, api_key_id=api_key_id)
    return jsonify(
        message="authorized",
        data="demo response",
        request_count=request_number,
    )


@app.get("/api/key/status")
def key_status():
    api_key_id = request.args.get("api_key_id", "key-001")
    _secret, record = find_api_key_by_id(api_key_id)
    if record is None:
        return jsonify(error="not_found", message="Unknown API key"), 404
    return jsonify(
        api_key_id=record["api_key_id"],
        status=record["status"],
        request_count=REQUEST_COUNTS[record["api_key_id"]],
        allowed_ips=sorted(record["allowed_ips"]),
    )


@app.get("/api/incidents")
def incidents():
    return jsonify(count=len(INCIDENTS), incidents=INCIDENTS)


@app.get("/api/security-events")
def security_events():
    return jsonify(count=len(SECURITY_EVENTS), events=SECURITY_EVENTS)


@app.get("/api/blocked-ips")
def blocked_ips():
    return jsonify(count=len(BLOCKED_IPS), blocked_ips=sorted(BLOCKED_IPS))


@app.post("/automation/revoke-key")
def automation_revoke_key():
    """Demo n8n webhook for response after Graylog/Wazuh detection."""
    body = request.get_json(silent=True) or {}
    api_key_id = body.get("api_key_id", "key-001")
    reason = body.get("detection_reason", "suspicious_api_key_usage")
    suspicious_ip = body.get("client_ip") or "unknown"

    if revoke_api_key(api_key_id, reason) is None:
        return jsonify(error="not_found", message="Unknown API key"), 404

    response = automatic_response(api_key_id, reason, suspicious_ip)
    return jsonify(response), 200


if __name__ == "__main__":
    # Dockerized n8n reaches the host API through host.docker.internal.
    app.run(host="0.0.0.0", port=5000, debug=False)
