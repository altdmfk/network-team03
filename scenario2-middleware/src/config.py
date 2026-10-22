import os
from typing import Any, Dict, List, Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PipelineSettings(BaseModel):
    """
    Typed, validated configuration for the SOAR log buffering & traffic control middleware.
    Validates numeric bounds, URLs, and legacy rate-limiting fallback rules at startup.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    @model_validator(mode="before")
    @classmethod
    def _remap_legacy_keys(cls, data: Any) -> Any:
        if isinstance(data, dict):
            mapping = {
                "broker_topic": "topic",
                "broker_priority_topic": "priority_topic",
                "broker_partitions": "partitions",
                "broker_consumer_group": "consumer_group",
                "broker_retention_ms": "retention_ms",
                "broker_dlq_topic": "dlq_topic",
                "broker_retry_1m_topic": "retry_1m_topic",
                "broker_retry_10m_topic": "retry_10m_topic",
                "broker_poison_topic": "poison_topic",
            }
            d = dict(data)
            for old_key, new_key in mapping.items():
                if old_key in d and new_key not in d:
                    d[new_key] = d[old_key]
            return d
        return data

    # Broker & Topic Configuration (Lightweight Partitioned WAL Broker)
    topic: str = Field(default="security-logs", min_length=1)
    priority_topic: str = Field(default="security-logs.priority", min_length=1)
    partitions: int = Field(default=3, ge=1, le=256)
    consumer_group: str = Field(default="graylog-shipper-group", min_length=1)
    retention_ms: int = Field(default=86400000, ge=1)

    # Priority Routing & Weighted Draining Configuration
    priority_event_types: List[str] = Field(
        default_factory=lambda: ["HONEYTOKEN_ACCESS"]
    )
    priority_max_severity: int = Field(default=2, ge=0, le=7)
    priority_weight: float = Field(default=0.7, gt=0.0)
    standard_weight: float = Field(default=0.3, gt=0.0)
    standard_reserved_share: float = Field(default=0.3, ge=0.001, le=0.999)
    honeytoken_latency_budget: float = Field(default=2.0, gt=0.0)

    # Persistent State & Dead-Letter Paths
    broker_db_path: str = Field(default="./state/broker_wal.db", min_length=1)
    max_broker_buffer_messages: int = Field(default=100000, ge=10)
    metrics_db_path: str = Field(default="./state/metrics.db", min_length=1)
    dead_letter_file: str = Field(
        default="./state/dead_letter_logs.jsonl", min_length=1
    )
    dlq_backend: str = Field(default="broker")
    dlq_topic: str = Field(default="security-logs.dlq", min_length=1)
    retry_1m_topic: str = Field(default="security-logs.retry.1m", min_length=1)
    retry_10m_topic: str = Field(default="security-logs.retry.10m", min_length=1)
    poison_topic: str = Field(default="security-logs.poison", min_length=1)
    max_retry_topic_attempts: int = Field(default=3, ge=1)

    # HTTP Ingestor & Mock Graylog Server Configuration
    ingestor_host: str = Field(default="0.0.0.0", min_length=1)
    ingestor_port: int = Field(default=8000, ge=1, le=65535)
    ingestor_base_url: str = Field(default="http://localhost:8000", min_length=1)

    mock_graylog_host: str = Field(default="0.0.0.0", min_length=1)
    mock_graylog_port: int = Field(default=12201, ge=1, le=65535)
    mock_graylog_base_url: str = Field(default="http://localhost:12201", min_length=1)

    graylog_gelf_url: str = Field(default="http://localhost:12201/gelf", min_length=1)
    gelf_host: str = Field(default="security-middleware", min_length=1)
    dry_run_graylog_mock: bool = Field(default=False)

    # Consumer Worker Batching, Rate-Limiting & Backoff Configuration
    batch_size: int = Field(default=100, ge=1, le=10000)
    max_logs_per_sec: float = Field(default=500.0, gt=0.0)
    batch_linger_ms: int = Field(default=100, ge=0, le=60000)
    poll_timeout: float = Field(default=0.1, gt=0.0, le=60.0)
    max_batches_per_second: float = Field(default=5.0, gt=0.0)

    base_backoff_seconds: float = Field(default=1.0, gt=0.0)
    max_backoff_seconds: float = Field(default=30.0, gt=0.0)
    max_delivery_retries: int = Field(
        default=8, ge=0
    )  # 8 = finite default; 0 = infinite retry (requires pause-based backoff)

    # Kill-Chain Correlation & Verification Constants
    kill_chain_target_ip: str = Field(default="10.0.0.99", min_length=2)
    expected_kill_chain: List[str] = Field(
        default_factory=lambda: ["PORT_SCAN", "BRUTE_FORCE", "IOT_CONTROL"]
    )

    # API Authentication & Security Basics
    auth_enabled: bool = Field(default=True)
    ingest_api_keys: List[str] = Field(default_factory=list)
    admin_api_key: Optional[str] = Field(default=None)
    auth_replay_window_seconds: float = Field(default=300.0, gt=0.0)

    # Ingestor Rate Limiting Configuration
    ingest_rate_limit_rps: float = Field(default=1000.0, gt=0.0)
    ingest_rate_limit_burst: float = Field(default=2000.0, gt=0.0)

    # PII / Secret Redaction
    redaction_patterns: List[str] = Field(
        default_factory=lambda: [
            "password",
            "passwd",
            "token",
            "api_key",
            "secret",
            "authorization",
            "cookie",
            "session",
        ]
    )

    # Producer Buffer Fast-Fail Backpressure Configuration
    producer_buffer_retries: int = Field(default=2, ge=1)
    producer_buffer_retry_sleep: float = Field(default=0.001, ge=0.0)

    # Structured Logging Configuration
    log_format: str = Field(default="text")

    # Schema Tolerance Configuration
    strict_schema: bool = Field(default=True)

    # Observability & OpenTelemetry Configuration
    consumer_metrics_port: int = Field(default=9100, ge=1, le=65535)
    otel_enabled: bool = Field(default=False)
    otel_sample_rate_normal: float = Field(default=0.01, ge=0.0, le=1.0)
    otel_sample_rate_priority: float = Field(default=1.0, ge=0.0, le=1.0)

    # Primary Broker Property Accessors
    @property
    def broker_topic(self) -> str:
        return self.topic

    @property
    def broker_priority_topic(self) -> str:
        return self.priority_topic

    @property
    def broker_partitions(self) -> int:
        return self.partitions

    @property
    def broker_consumer_group(self) -> str:
        return self.consumer_group

    @property
    def broker_retention_ms(self) -> int:
        return self.retention_ms

    @property
    def broker_dlq_topic(self) -> str:
        return self.dlq_topic

    @property
    def broker_retry_1m_topic(self) -> str:
        return self.retry_1m_topic

    @property
    def broker_retry_10m_topic(self) -> str:
        return self.retry_10m_topic

    @property
    def broker_poison_topic(self) -> str:
        return self.poison_topic

    @model_validator(mode="after")
    def validate_backoff_bounds(self) -> "PipelineSettings":
        if self.max_backoff_seconds < self.base_backoff_seconds:
            raise ValueError(
                f"max_backoff_seconds ({self.max_backoff_seconds}) must be >= base_backoff_seconds ({self.base_backoff_seconds})"
            )
        if not (0.0 < self.standard_reserved_share < 1.0):
            raise ValueError(
                f"standard_reserved_share ({self.standard_reserved_share}) must be between 0.0 and 1.0 exclusive so standard traffic is never starved"
            )
        if self.priority_weight <= 0.0:
            raise ValueError(
                f"priority_weight ({self.priority_weight}) must be > 0.0"
            )
        if self.standard_weight <= 0.0:
            raise ValueError(
                f"standard_weight ({self.standard_weight}) must be > 0.0"
            )
        return self


def _parse_bool(raw: str) -> bool:
    return raw.strip().lower() in ("1", "true", "yes", "on")


def load_settings(env: Optional[Mapping[str, str]] = None) -> PipelineSettings:
    """
    Loads and validates `PipelineSettings` from an environment mapping (defaults to `os.environ`).
    Preserves legacy `MAX_BATCHES_PER_SECOND` fallback calculation when `MAX_LOGS_PER_SEC` is unset.
    """
    source: Mapping[str, str] = os.environ if env is None else env

    ingestor_port = int(source.get("INGESTOR_PORT", "8000"))
    ingestor_base_url = source.get(
        "INGESTOR_BASE_URL", f"http://localhost:{ingestor_port}"
    )

    mock_graylog_port = int(source.get("MOCK_GRAYLOG_PORT", "12201"))
    mock_graylog_base_url = source.get(
        "MOCK_GRAYLOG_BASE_URL", f"http://localhost:{mock_graylog_port}"
    )
    graylog_gelf_url = source.get(
        "GRAYLOG_GELF_URL", f"{mock_graylog_base_url}/gelf"
    )

    batch_size = int(source.get("BATCH_SIZE", "100"))
    if source.get("MAX_LOGS_PER_SEC") is not None:
        max_logs_per_sec = float(source["MAX_LOGS_PER_SEC"])
    elif source.get("MAX_BATCHES_PER_SECOND") is not None:
        max_logs_per_sec = float(source["MAX_BATCHES_PER_SECOND"]) * batch_size
    else:
        max_logs_per_sec = 500.0

    max_batches_per_second = float(
        source.get(
            "MAX_BATCHES_PER_SECOND",
            str(max_logs_per_sec / max(1, batch_size)),
        )
    )

    auth_enabled = _parse_bool(source.get("AUTH_ENABLED", "true"))

    raw_ingest_keys = source.get("INGEST_API_KEYS", "")
    ingest_keys_file = source.get("INGEST_API_KEYS_FILE")
    if ingest_keys_file and os.path.isfile(ingest_keys_file):
        try:
            with open(ingest_keys_file, "r", encoding="utf-8") as f:
                raw_ingest_keys = f.read()
        except Exception:
            pass
    elif raw_ingest_keys and os.path.isfile(raw_ingest_keys):
        try:
            with open(raw_ingest_keys, "r", encoding="utf-8") as f:
                raw_ingest_keys = f.read()
        except Exception:
            pass
    ingest_api_keys = [
        k.strip()
        for k in raw_ingest_keys.replace("\n", ",").split(",")
        if k.strip()
    ]

    raw_admin_key = source.get("ADMIN_API_KEY", "")
    admin_key_file = source.get("ADMIN_API_KEY_FILE")
    if admin_key_file and os.path.isfile(admin_key_file):
        try:
            with open(admin_key_file, "r", encoding="utf-8") as f:
                raw_admin_key = f.read().strip()
        except Exception:
            pass
    elif raw_admin_key and os.path.isfile(raw_admin_key):
        try:
            with open(raw_admin_key, "r", encoding="utf-8") as f:
                raw_admin_key = f.read().strip()
        except Exception:
            pass
    admin_api_key = raw_admin_key.strip() if raw_admin_key else None

    raw_patterns = source.get("REDACTION_PATTERNS")
    if raw_patterns:
        redaction_patterns = [p.strip() for p in raw_patterns.split(",") if p.strip()]
    else:
        redaction_patterns = [
            "password",
            "passwd",
            "token",
            "api_key",
            "secret",
            "authorization",
            "cookie",
            "session",
        ]

    data: Dict[str, object] = {
        "topic": source.get("BROKER_TOPIC", "security-logs"),
        "priority_topic": source.get(
            "BROKER_PRIORITY_TOPIC", "security-logs.priority"
        ),
        "priority_event_types": (
            [
                p.strip().upper()
                for p in source["PRIORITY_EVENT_TYPES"].split(",")
                if p.strip()
            ]
            if "PRIORITY_EVENT_TYPES" in source
            else ["HONEYTOKEN_ACCESS"]
        ),
        "priority_max_severity": int(source.get("PRIORITY_MAX_SEVERITY", "2")),
        "priority_weight": float(source.get("PRIORITY_WEIGHT", "0.7")),
        "standard_weight": float(source.get("STANDARD_WEIGHT", "0.3")),
        "standard_reserved_share": float(
            source.get("STANDARD_RESERVED_SHARE", "0.3")
        ),
        "honeytoken_latency_budget": float(
            source.get("HONEYTOKEN_LATENCY_BUDGET", "2.0")
        ),
        "partitions": int(source.get("BROKER_PARTITIONS", "3")),
        "consumer_group": source.get(
            "BROKER_CONSUMER_GROUP",
            source.get("CONSUMER_GROUP", "graylog-shipper-group"),
        ),
        "retention_ms": int(source.get("BROKER_RETENTION_MS", "86400000")),
        "auth_enabled": auth_enabled,
        "ingest_api_keys": ingest_api_keys,
        "admin_api_key": admin_api_key,
        "auth_replay_window_seconds": float(
            source.get("AUTH_REPLAY_WINDOW_SECONDS", "300.0")
        ),
        "ingest_rate_limit_rps": float(
            source.get("INGEST_RATE_LIMIT_RPS", "1000.0")
        ),
        "ingest_rate_limit_burst": float(
            source.get("INGEST_RATE_LIMIT_BURST", "2000.0")
        ),
        "redaction_patterns": redaction_patterns,
        "producer_buffer_retries": int(
            source.get("PRODUCER_BUFFER_RETRIES", "2")
        ),
        "producer_buffer_retry_sleep": float(
            source.get("PRODUCER_BUFFER_RETRY_SLEEP", "0.001")
        ),
        "broker_db_path": source.get("BROKER_DB_PATH", "./state/broker_wal.db"),
        "max_broker_buffer_messages": int(
            source.get(
                "MAX_BROKER_BUFFER_MESSAGES",
                source.get("MAX_QUEUE_SIZE", "100000"),
            )
        ),
        "metrics_db_path": source.get("METRICS_DB_PATH", "./state/metrics.db"),
        "dead_letter_file": source.get(
            "DEAD_LETTER_FILE", "./state/dead_letter_logs.jsonl"
        ),
        "dlq_backend": source.get("DLQ_BACKEND", "broker").strip().lower(),
        "dlq_topic": source.get(
            "BROKER_DLQ_TOPIC",
            source.get("DLQ_TOPIC", "security-logs.dlq"),
        ),
        "retry_1m_topic": source.get(
            "BROKER_RETRY_1M_TOPIC",
            source.get("RETRY_1M_TOPIC", "security-logs.retry.1m"),
        ),
        "retry_10m_topic": source.get(
            "BROKER_RETRY_10M_TOPIC",
            source.get("RETRY_10M_TOPIC", "security-logs.retry.10m"),
        ),
        "poison_topic": source.get(
            "BROKER_POISON_TOPIC",
            source.get("POISON_TOPIC", "security-logs.poison"),
        ),
        "max_retry_topic_attempts": int(
            source.get("MAX_RETRY_TOPIC_ATTEMPTS", "3")
        ),
        "ingestor_host": source.get("INGESTOR_HOST", "0.0.0.0"),
        "ingestor_port": ingestor_port,
        "ingestor_base_url": ingestor_base_url,
        "mock_graylog_host": source.get("MOCK_GRAYLOG_HOST", "0.0.0.0"),
        "mock_graylog_port": mock_graylog_port,
        "mock_graylog_base_url": mock_graylog_base_url,
        "graylog_gelf_url": graylog_gelf_url,
        "gelf_host": source.get("GELF_HOST", "security-middleware"),
        "dry_run_graylog_mock": _parse_bool(
            source.get("DRY_RUN_GRAYLOG_MOCK", "false")
        ),
        "batch_size": batch_size,
        "max_logs_per_sec": max_logs_per_sec,
        "batch_linger_ms": int(source.get("BATCH_LINGER_MS", "100")),
        "poll_timeout": float(source.get("POLL_TIMEOUT", "0.1")),
        "max_batches_per_second": max_batches_per_second,
        "base_backoff_seconds": float(source.get("BASE_BACKOFF_SECONDS", "1.0")),
        "max_backoff_seconds": float(source.get("MAX_BACKOFF_SECONDS", "30.0")),
        "max_delivery_retries": int(source.get("MAX_DELIVERY_RETRIES", "8")),
        "kill_chain_target_ip": source.get("KILL_CHAIN_TARGET_IP", "10.0.0.99"),
        "log_format": source.get("LOG_FORMAT", "text"),
        "consumer_metrics_port": int(source.get("CONSUMER_METRICS_PORT", "9100")),
        "strict_schema": _parse_bool(source.get("STRICT_SCHEMA", "true")),
        "otel_enabled": _parse_bool(source.get("OTEL_ENABLED", "false")),
        "otel_sample_rate_normal": float(
            source.get("OTEL_SAMPLE_RATE_NORMAL", "0.01")
        ),
        "otel_sample_rate_priority": float(
            source.get("OTEL_SAMPLE_RATE_PRIORITY", "1.0")
        ),
    }
    return PipelineSettings(**data)


SETTINGS: PipelineSettings = load_settings()

# ---------------------------------------------------------------------------
# Primary Broker Constants
# ---------------------------------------------------------------------------
BROKER_DB_PATH: str = SETTINGS.broker_db_path
MAX_BROKER_BUFFER_MESSAGES: int = SETTINGS.max_broker_buffer_messages
BROKER_TOPIC: str = SETTINGS.topic
BROKER_PRIORITY_TOPIC: str = SETTINGS.priority_topic
BROKER_PARTITIONS: int = SETTINGS.partitions
BROKER_RETENTION_MS: int = SETTINGS.retention_ms
BROKER_CONSUMER_GROUP: str = SETTINGS.consumer_group
BROKER_DLQ_TOPIC: str = SETTINGS.dlq_topic
BROKER_RETRY_1M_TOPIC: str = SETTINGS.retry_1m_topic
BROKER_RETRY_10M_TOPIC: str = SETTINGS.retry_10m_topic
BROKER_POISON_TOPIC: str = SETTINGS.poison_topic

# Legacy Broker Aliases
TOPIC: str = BROKER_TOPIC
PRIORITY_TOPIC: str = BROKER_PRIORITY_TOPIC
PARTITIONS: int = BROKER_PARTITIONS
CONSUMER_GROUP: str = BROKER_CONSUMER_GROUP
DLQ_TOPIC: str = BROKER_DLQ_TOPIC
RETRY_1M_TOPIC: str = BROKER_RETRY_1M_TOPIC
RETRY_10M_TOPIC: str = BROKER_RETRY_10M_TOPIC
POISON_TOPIC: str = BROKER_POISON_TOPIC

# Operational Constants
PRIORITY_EVENT_TYPES: List[str] = list(SETTINGS.priority_event_types)
PRIORITY_MAX_SEVERITY: int = SETTINGS.priority_max_severity
PRIORITY_WEIGHT: float = SETTINGS.priority_weight
STANDARD_WEIGHT: float = SETTINGS.standard_weight
STANDARD_RESERVED_SHARE: float = SETTINGS.standard_reserved_share
HONEYTOKEN_LATENCY_BUDGET: float = SETTINGS.honeytoken_latency_budget

AUTH_ENABLED: bool = SETTINGS.auth_enabled
INGEST_API_KEYS: List[str] = list(SETTINGS.ingest_api_keys)
ADMIN_API_KEY: Optional[str] = SETTINGS.admin_api_key
AUTH_REPLAY_WINDOW_SECONDS: float = SETTINGS.auth_replay_window_seconds

INGEST_RATE_LIMIT_RPS: float = SETTINGS.ingest_rate_limit_rps
INGEST_RATE_LIMIT_BURST: float = SETTINGS.ingest_rate_limit_burst
REDACTION_PATTERNS: List[str] = list(SETTINGS.redaction_patterns)
PRODUCER_BUFFER_RETRIES: int = SETTINGS.producer_buffer_retries
PRODUCER_BUFFER_RETRY_SLEEP: float = SETTINGS.producer_buffer_retry_sleep

METRICS_DB_PATH: str = SETTINGS.metrics_db_path
DEAD_LETTER_FILE: str = SETTINGS.dead_letter_file
DLQ_BACKEND: str = SETTINGS.dlq_backend
MAX_RETRY_TOPIC_ATTEMPTS: int = SETTINGS.max_retry_topic_attempts

INGESTOR_HOST: str = SETTINGS.ingestor_host
INGESTOR_PORT: int = SETTINGS.ingestor_port
INGESTOR_BASE_URL: str = SETTINGS.ingestor_base_url

MOCK_GRAYLOG_HOST: str = SETTINGS.mock_graylog_host
MOCK_GRAYLOG_PORT: int = SETTINGS.mock_graylog_port
MOCK_GRAYLOG_BASE_URL: str = SETTINGS.mock_graylog_base_url

GRAYLOG_GELF_URL: str = SETTINGS.graylog_gelf_url
GELF_HOST: str = SETTINGS.gelf_host
DRY_RUN_GRAYLOG_MOCK: bool = SETTINGS.dry_run_graylog_mock

BATCH_SIZE: int = SETTINGS.batch_size
MAX_LOGS_PER_SEC: float = SETTINGS.max_logs_per_sec
BATCH_LINGER_MS: int = SETTINGS.batch_linger_ms
POLL_TIMEOUT: float = SETTINGS.poll_timeout
MAX_BATCHES_PER_SECOND: float = SETTINGS.max_batches_per_second

BASE_BACKOFF_SECONDS: float = SETTINGS.base_backoff_seconds
MAX_BACKOFF_SECONDS: float = SETTINGS.max_backoff_seconds
MAX_DELIVERY_RETRIES: int = SETTINGS.max_delivery_retries

KILL_CHAIN_TARGET_IP: str = SETTINGS.kill_chain_target_ip
EXPECTED_KILL_CHAIN: List[str] = list(SETTINGS.expected_kill_chain)
LOG_FORMAT: str = SETTINGS.log_format
STRICT_SCHEMA: bool = SETTINGS.strict_schema
CONSUMER_METRICS_PORT: int = SETTINGS.consumer_metrics_port
OTEL_ENABLED: bool = SETTINGS.otel_enabled
OTEL_SAMPLE_RATE_NORMAL: float = SETTINGS.otel_sample_rate_normal
OTEL_SAMPLE_RATE_PRIORITY: float = SETTINGS.otel_sample_rate_priority
