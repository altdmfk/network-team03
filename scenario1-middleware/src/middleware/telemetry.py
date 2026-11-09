import logging
import random
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    start_http_server,
)

from config import (
    BROKER_DLQ_TOPIC,
    BROKER_PARTITIONS,
    BROKER_PRIORITY_TOPIC,
    BROKER_TOPIC,
    MAX_LOGS_PER_SEC,
    OTEL_ENABLED,
    OTEL_SAMPLE_RATE_NORMAL,
    OTEL_SAMPLE_RATE_PRIORITY,
)

logger = logging.getLogger("soar.telemetry")

# ---------------------------------------------------------------------------
# Prometheus Metric Registry & Definitions
# Low-cardinality label rule: Only event_type, topic, partition, outcome.
# NEVER client_ip or high-cardinality identifiers.
# ---------------------------------------------------------------------------
PIPELINE_REGISTRY = CollectorRegistry(auto_describe=True)

# 1. Counters
logs_received_total = Counter(
    "logs_received_total",
    "Total count of security log events successfully received at the ingestor.",
    registry=PIPELINE_REGISTRY,
)

logs_forwarded_total = Counter(
    "logs_forwarded_total",
    "Total count of log events confirmed delivered to Graylog with HTTP 2xx.",
    registry=PIPELINE_REGISTRY,
)

logs_permanently_dropped_total = Counter(
    "logs_permanently_dropped_total",
    "Total count of log events permanently dropped without delivery or DLQ persistence.",
    registry=PIPELINE_REGISTRY,
)

dlq_published_total = Counter(
    "dlq_published_total",
    "Total count of log events durably published to the Dead Letter Queue topic or file.",
    registry=PIPELINE_REGISTRY,
)

dlq_replayed_total = Counter(
    "dlq_replayed_total",
    "Total count of log events successfully replayed from the Dead Letter Queue.",
    registry=PIPELINE_REGISTRY,
)

poison_messages_total = Counter(
    "poison_messages_total",
    "Total count of unparseable poison messages detected and quarantined to the poison topic.",
    registry=PIPELINE_REGISTRY,
)

delivery_attempts_total = Counter(
    "delivery_attempts_total",
    "Total delivery attempts to Graylog categorized by low-cardinality outcome.",
    ["outcome"],
    registry=PIPELINE_REGISTRY,
)

# 2. Gauges
queue_lag = Gauge(
    "queue_lag",
    "Broker partition queue lag between high-watermark and committed consumer group offset.",
    ["topic", "partition"],
    registry=PIPELINE_REGISTRY,
)

dlq_depth = Gauge(
    "dlq_depth",
    "Current number of un-replayed messages residing in the Dead Letter Queue.",
    registry=PIPELINE_REGISTRY,
)

configured_max_logs_per_sec = Gauge(
    "configured_max_logs_per_sec",
    "Configured rate-limit throughput budget in logs per second.",
    registry=PIPELINE_REGISTRY,
)

current_rate_limit = Gauge(
    "current_rate_limit",
    "Current active token-bucket rate limit in logs per second.",
    registry=PIPELINE_REGISTRY,
)

invariant_violations = Gauge(
    "invariant_violations",
    "Count of detected pipeline invariant violations (zero-loss, counter consistency).",
    registry=PIPELINE_REGISTRY,
)

# 3. Histograms
graylog_delivery_latency_seconds = Histogram(
    "graylog_delivery_latency_seconds",
    "HTTP POST delivery latency to Graylog SIEM in seconds.",
    registry=PIPELINE_REGISTRY,
    buckets=(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 10.0, float("inf")),
)

batch_size = Histogram(
    "batch_size",
    "Distribution of batch sizes processed by the consumer worker.",
    registry=PIPELINE_REGISTRY,
    buckets=(1, 5, 10, 25, 50, 100, 250, 500, 1000, float("inf")),
)

end_to_end_latency_seconds = Histogram(
    "end_to_end_latency_seconds",
    "End-to-end latency from broker produce timestamp to confirmed Graylog 2xx delivery.",
    registry=PIPELINE_REGISTRY,
    buckets=(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 10.0, float("inf")),
)


def _init_default_series() -> None:
    """Pre-populates known low-cardinality series so all metric names are immediately visible in exposition."""
    for outcome in ("2xx", "5xx", "4xx", "error", "dlq", "aborted"):
        delivery_attempts_total.labels(outcome=outcome)

    for pid in range(BROKER_PARTITIONS):
        queue_lag.labels(topic=BROKER_TOPIC, partition=str(pid)).set(0.0)
        queue_lag.labels(topic=BROKER_PRIORITY_TOPIC, partition=str(pid)).set(0.0)

    dlq_depth.set(0.0)
    configured_max_logs_per_sec.set(float(MAX_LOGS_PER_SEC))
    current_rate_limit.set(float(MAX_LOGS_PER_SEC))
    invariant_violations.set(0.0)


_init_default_series()


# ---------------------------------------------------------------------------
# Metric Sync & Reset Functions
# ---------------------------------------------------------------------------
def sync_prometheus_metrics(
    snapshot: Dict[str, Any],
    lag_snapshot: Optional[Dict[str, Any]] = None,
    topic_stats: Optional[Dict[str, Any]] = None,
    rate_limit: Optional[float] = None,
    max_logs_per_sec: Optional[float] = None,
) -> None:
    """
    Synchronizes Prometheus counters and gauges with the authoritative SQLite WAL snapshot
    and broker partition watermarks.
    """
    try:
        logs_received_total._value.set(float(snapshot.get("total_received", 0)))
        logs_forwarded_total._value.set(float(snapshot.get("total_forwarded_to_graylog", 0)))
        logs_permanently_dropped_total._value.set(float(snapshot.get("permanently_dropped_logs", 0)))
        dlq_published_total._value.set(float(snapshot.get("dlq_quarantined_logs", 0)))
        dlq_replayed_total._value.set(float(snapshot.get("dlq_replayed_logs", 0)))
        poison_messages_total._value.set(float(snapshot.get("poison_messages", 0)))
        invariant_violations.set(float(snapshot.get("invariant_violations", 0)))

        configured_max_logs_per_sec.set(
            float(max_logs_per_sec if max_logs_per_sec is not None else MAX_LOGS_PER_SEC)
        )
        current_rate_limit.set(
            float(rate_limit if rate_limit is not None else MAX_LOGS_PER_SEC)
        )

        if lag_snapshot:
            for p in lag_snapshot.get("partitions", []):
                pid = str(p.get("partition", 0))
                lag_val = float(p.get("lag", 0))
                queue_lag.labels(topic=BROKER_TOPIC, partition=pid).set(lag_val)
            for p in lag_snapshot.get("priority_partitions", []):
                pid = str(p.get("partition", 0))
                lag_val = float(p.get("lag", 0))
                queue_lag.labels(topic=BROKER_PRIORITY_TOPIC, partition=pid).set(lag_val)

        if topic_stats:
            dlq_stats = topic_stats.get(BROKER_DLQ_TOPIC, {})
            dlq_depth.set(float(dlq_stats.get("total_messages", 0)))
    except Exception as exc:
        logger.debug("Telemetry sync error: %s", exc)


def reset_prometheus_metrics() -> None:
    """Resets all metrics to clean zero baselines."""
    logs_received_total._value.set(0.0)
    logs_forwarded_total._value.set(0.0)
    logs_permanently_dropped_total._value.set(0.0)
    dlq_published_total._value.set(0.0)
    dlq_replayed_total._value.set(0.0)
    poison_messages_total._value.set(0.0)
    invariant_violations.set(0.0)
    dlq_depth.set(0.0)
    _init_default_series()


# ---------------------------------------------------------------------------
# Individual Event Recording Functions (Strict Confirmed Events Only)
# ---------------------------------------------------------------------------
def record_logs_received(count: int = 1) -> None:
    if count > 0:
        logs_received_total.inc(count)


def record_logs_forwarded(count: int = 1) -> None:
    """Must ONLY be called after receiving a confirmed 2xx HTTP response from Graylog."""
    if count > 0:
        logs_forwarded_total.inc(count)


def record_logs_permanently_dropped(count: int = 1) -> None:
    if count > 0:
        logs_permanently_dropped_total.inc(count)


def record_dlq_published(count: int = 1) -> None:
    """Must ONLY be called after durable write to Broker DLQ or JSONL DLQ file."""
    if count > 0:
        dlq_published_total.inc(count)


def record_dlq_replayed(count: int = 1) -> None:
    if count > 0:
        dlq_replayed_total.inc(count)


def record_poison_message(count: int = 1) -> None:
    if count > 0:
        poison_messages_total.inc(count)


def record_delivery_attempt(outcome: str) -> None:
    lowered = outcome.lower()
    valid_outcomes = {"2xx", "5xx", "4xx", "error", "dlq", "aborted"}
    target = lowered if lowered in valid_outcomes else "error"
    delivery_attempts_total.labels(outcome=target).inc()


def record_graylog_delivery_latency(seconds: float) -> None:
    if seconds >= 0.0:
        graylog_delivery_latency_seconds.observe(seconds)


def record_batch_size(size: int) -> None:
    if size >= 0:
        batch_size.observe(size)


def record_end_to_end_latency(messages: Optional[List[Any]]) -> None:
    """Calculates latency from message produce timestamp to confirmed delivery."""
    if not messages:
        return
    now = time.time()
    for msg in messages:
        ts_val: Optional[float] = None
        ts_fn = getattr(msg, "timestamp", None)
        if callable(ts_fn):
            try:
                t_type, t_ms = ts_fn()
                if t_ms is not None and t_ms > 0:
                    ts_val = t_ms / 1000.0
            except Exception:
                pass
        if ts_val is None and isinstance(msg, dict):
            raw_ts = msg.get("timestamp")
            if isinstance(raw_ts, (int, float)) and raw_ts > 0:
                ts_val = float(raw_ts)

        if ts_val is not None and 0 < ts_val <= now + 1.0:
            latency = max(0.0, now - ts_val)
            end_to_end_latency_seconds.observe(latency)


# ---------------------------------------------------------------------------
# OpenTelemetry W3C Trace Context Propagation
# ---------------------------------------------------------------------------
_tracer = None
_tracer_provider = None
_propagator = None


def _setup_opentelemetry(
    enabled: bool = OTEL_ENABLED,
    normal_ratio: float = OTEL_SAMPLE_RATE_NORMAL,
    priority_ratio: float = OTEL_SAMPLE_RATE_PRIORITY,
) -> None:
    global _tracer, _tracer_provider, _propagator
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.sampling import Decision, ParentBased, Sampler, SamplingResult
        from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

        class HeadSampler(Sampler):
            """Head-based sampler: 100% for priority events, 1% for standard events by default."""

            def __init__(self, norm_ratio: float = 0.01, prio_ratio: float = 1.0):
                self.norm_ratio = norm_ratio
                self.prio_ratio = prio_ratio

            def should_sample(
                self, parent_context, trace_id, name, kind=None, attributes=None, links=None
            ):
                is_prio = bool((attributes or {}).get("event.is_priority", False))
                ratio = self.prio_ratio if is_prio else self.norm_ratio
                sampled = (random.random() < ratio) or (ratio >= 1.0)
                decision = Decision.RECORD_AND_SAMPLE if sampled else Decision.DROP
                return SamplingResult(decision, attributes, None)

            def get_description(self):
                return f"PriorityHeadSampler(normal={self.norm_ratio}, priority={self.prio_ratio})"

        sampler = ParentBased(root=HeadSampler(normal_ratio, priority_ratio))
        _tracer_provider = TracerProvider(sampler=sampler)
        _tracer = _tracer_provider.get_tracer("soar.middleware", "1.1.0")
        _propagator = TraceContextTextMapPropagator()
    except Exception as exc:
        logger.warning("Could not initialize OpenTelemetry: %s", exc)
        _tracer = None
        _propagator = None


_setup_opentelemetry()


def is_otel_enabled(override: Optional[bool] = None) -> bool:
    if override is not None:
        return override
    return bool(OTEL_ENABLED)


def inject_traceparent_to_broker_headers(
    headers: Optional[List[Tuple[str, bytes]]] = None,
    is_priority: bool = False,
    parent_traceparent: Optional[str] = None,
    otel_enabled: Optional[bool] = None,
) -> List[Tuple[str, bytes]]:
    """
    Creates an OpenTelemetry span with head-based sampling and injects W3C `traceparent`
    into the broker message headers list.
    """
    out_headers: List[Tuple[str, bytes]] = list(headers or [])
    if not is_otel_enabled(otel_enabled) or _tracer is None or _propagator is None:
        return out_headers

    try:
        from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

        parent_ctx = None
        if parent_traceparent:
            parent_ctx = _propagator.extract({"traceparent": parent_traceparent})

        with _tracer.start_as_current_span(
            "ingest_event",
            context=parent_ctx,
            attributes={"event.is_priority": is_priority},
        ):
            carrier: Dict[str, str] = {}
            _propagator.inject(carrier)
            tp_val = carrier.get("traceparent")
            if tp_val:
                out_headers = [
                    (k, v) for k, v in out_headers if k.lower() != "traceparent"
                ]
                out_headers.append(("traceparent", tp_val.encode("utf-8")))
    except Exception as exc:
        logger.debug("Failed to inject traceparent to broker headers: %s", exc)

    return out_headers


def extract_traceparent_from_broker_message(msg: Any) -> Optional[str]:
    """Extracts W3C `traceparent` string from broker message headers."""
    headers_fn = getattr(msg, "headers", None)
    if callable(headers_fn):
        raw_headers = headers_fn()
        if raw_headers:
            for k, v in raw_headers:
                if k == "traceparent" or (isinstance(k, str) and k.lower() == "traceparent"):
                    if isinstance(v, bytes):
                        return v.decode("utf-8", errors="replace")
                    return str(v)
    elif isinstance(msg, dict):
        h_dict = msg.get("headers", {})
        if "traceparent" in h_dict:
            return str(h_dict["traceparent"])
    return None


def create_consumer_traceparent(
    messages: Optional[List[Any]] = None,
    otel_enabled: Optional[bool] = None,
) -> Optional[str]:
    """
    Extracts parent traceparent from batch messages and creates a child consumer span,
    returning the propagated W3C `traceparent` header string for the downstream Graylog HTTP call.
    """
    if not is_otel_enabled(otel_enabled) or _tracer is None or _propagator is None:
        return None

    try:
        parent_tp: Optional[str] = None
        if messages:
            for m in messages:
                tp = extract_traceparent_from_broker_message(m)
                if tp:
                    parent_tp = tp
                    break

        parent_ctx = None
        if parent_tp:
            parent_ctx = _propagator.extract({"traceparent": parent_tp})

        with _tracer.start_as_current_span("graylog_batch_delivery", context=parent_ctx):
            carrier: Dict[str, str] = {}
            _propagator.inject(carrier)
            return carrier.get("traceparent")
    except Exception as exc:
        logger.debug("Failed to create consumer traceparent: %s", exc)
        return None
