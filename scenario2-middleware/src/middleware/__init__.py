from middleware.auth import (
    authenticate_request,
    is_auth_enabled,
    require_admin_auth,
    require_ingest_auth,
)
from middleware.batch_poller import BrokerBatchPoller
from middleware.delivery_client import GraylogDeliveryClient
from middleware.dlq_publisher import (
    BrokerDeadLetterPublisher,
    DeadLetterSink,
    get_header_value,
)
from middleware.dlq_store import JsonlDeadLetterStore
from middleware.retry_topic_consumer import RetryTopicConsumer
from middleware.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    build_problem_response,
    register_problem_handlers,
)
from middleware.exceptions import (
    ConfigurationError,
    DeadLetterStoreError,
    DownstreamDeliveryError,
    MiddlewareError,
    OffsetCommitError,
    ProducerBackpressureError,
    ProducerEnqueueError,
)
from middleware.gelf_transformer import (
    GelfTransformer,
    serialize_ndjson_batch,
    transform_to_gelf,
)
from middleware.ingest_rate_limiter import (
    PerClientRateLimiter,
    check_client_rate_limit,
    ingest_rate_limiter,
)
from middleware.lightweight_broker import (
    LightweightAdminClient,
    LightweightConsumer,
    LightweightMessage,
    LightweightProducer,
    OFFSET_INVALID,
    SQLiteBrokerStorage,
    TopicPartition,
)
from middleware.logging_utils import StructuredJsonFormatter, configure_logging
from middleware.models import (
    BatchResult,
    BrokerLagSnapshot,
    DeliveryOutcome,
    InFlightBatchState,
    PartitionLagInfo,
    RetryPolicy,
)
from middleware.offset_committer import ExplicitOffsetCommitter
from middleware.rate_limiter import TokenBucketRateLimiter
from middleware.redaction import (
    DEFAULT_REDACTION_PATTERNS,
    is_sensitive_key,
    redact_sensitive_data,
)
from middleware.telemetry import (
    PIPELINE_REGISTRY,
    batch_size,
    configured_max_logs_per_sec,
    create_consumer_traceparent,
    current_rate_limit,
    delivery_attempts_total,
    dlq_depth,
    dlq_published_total,
    dlq_replayed_total,
    end_to_end_latency_seconds,
    extract_traceparent_from_broker_message,
    graylog_delivery_latency_seconds,
    inject_traceparent_to_broker_headers,
    invariant_violations,
    logs_forwarded_total,
    logs_permanently_dropped_total,
    logs_received_total,
    poison_messages_total,
    queue_lag,
    record_batch_size,
    record_delivery_attempt,
    record_dlq_published,
    record_dlq_replayed,
    record_end_to_end_latency,
    record_graylog_delivery_latency,
    record_logs_forwarded,
    record_logs_permanently_dropped,
    record_logs_received,
    record_poison_message,
    reset_prometheus_metrics,
    sync_prometheus_metrics,
)

__all__ = [
    "DEFAULT_REDACTION_PATTERNS",
    "PROBLEM_JSON_MEDIA_TYPE",
    "BatchResult",
    "BrokerBatchPoller",
    "BrokerDeadLetterPublisher",
    "BrokerLagSnapshot",
    "ConfigurationError",
    "DeadLetterSink",
    "DeadLetterStoreError",
    "DeliveryOutcome",
    "DownstreamDeliveryError",
    "ExplicitOffsetCommitter",
    "GelfTransformer",
    "GraylogDeliveryClient",
    "InFlightBatchState",
    "JsonlDeadLetterStore",
    "LightweightAdminClient",
    "LightweightConsumer",
    "LightweightMessage",
    "LightweightProducer",
    "MiddlewareError",
    "OFFSET_INVALID",
    "OffsetCommitError",
    "PartitionLagInfo",
    "PerClientRateLimiter",
    "ProducerBackpressureError",
    "ProducerEnqueueError",
    "RetryPolicy",
    "RetryTopicConsumer",
    "SQLiteBrokerStorage",
    "StructuredJsonFormatter",
    "TokenBucketRateLimiter",
    "TopicPartition",
    "WalLogBufferingMiddleware",
    "authenticate_request",
    "build_problem_response",
    "check_client_rate_limit",
    "configure_logging",
    "get_header_value",
    "ingest_rate_limiter",
    "is_auth_enabled",
    "is_sensitive_key",
    "redact_sensitive_data",
    "register_problem_handlers",
    "require_admin_auth",
    "require_ingest_auth",
    "serialize_ndjson_batch",
    "transform_to_gelf",
    "PIPELINE_REGISTRY",
    "batch_size",
    "configured_max_logs_per_sec",
    "create_consumer_traceparent",
    "current_rate_limit",
    "delivery_attempts_total",
    "dlq_depth",
    "dlq_published_total",
    "dlq_replayed_total",
    "end_to_end_latency_seconds",
    "extract_traceparent_from_broker_message",
    "graylog_delivery_latency_seconds",
    "inject_traceparent_to_broker_headers",
    "invariant_violations",
    "logs_forwarded_total",
    "logs_permanently_dropped_total",
    "logs_received_total",
    "poison_messages_total",
    "queue_lag",
    "record_batch_size",
    "record_delivery_attempt",
    "record_dlq_published",
    "record_dlq_replayed",
    "record_end_to_end_latency",
    "record_graylog_delivery_latency",
    "record_logs_forwarded",
    "record_logs_permanently_dropped",
    "record_logs_received",
    "record_poison_message",
    "reset_prometheus_metrics",
    "sync_prometheus_metrics",
]


def __getattr__(name: str):
    if name == "WalLogBufferingMiddleware":
        from ingestor import WalLogBufferingMiddleware
        return WalLogBufferingMiddleware
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
