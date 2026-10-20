import logging
import random
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import httpx
from middleware.lightweight_broker import TopicPartition

from middleware.gelf_transformer import serialize_ndjson_batch
from middleware.models import DeliveryOutcome, RetryPolicy
from middleware.telemetry import (
    create_consumer_traceparent,
    record_batch_size,
    record_delivery_attempt,
    record_end_to_end_latency,
    record_graylog_delivery_latency,
)

logger = logging.getLogger("soar.delivery_client")


class GraylogDeliveryClient:
    """
    Delivers GELF 1.1 micro-batches over HTTP POST to Graylog with configurable
    Exponential Backoff + Jitter retry policy.
    During backoff, pauses assigned partitions via `consumer.pause(assigned_partitions)`
    and keeps the consumer group session alive by calling `consumer.poll(0)` ONLY while
    paused (a paused consumer's poll returns no messages, preventing silent drops),
    then resumes partitions after delivery.
    """

    def __init__(
        self,
        sleep_fn: Optional[Callable[[float], None]] = None,
        jitter_fn: Optional[Callable[[float, float], float]] = None,
    ) -> None:
        self._sleep_fn: Callable[[float], None] = sleep_fn or (lambda s: time.sleep(s))
        self._jitter_fn: Callable[[float, float], float] = jitter_fn or (
            lambda a, b: random.uniform(a, b)
        )

    def deliver_batch(
        self,
        *,
        gelf_batch: List[Dict[str, Any]],
        http_client: httpx.Client,
        gelf_url: str,
        retry_policy: RetryPolicy,
        dry_run: bool,
        is_running_fn: Callable[[], bool],
        on_dead_letter: Callable[..., Any],
        batch_id: Optional[str] = None,
        consumer: Optional[Any] = None,
        get_assigned_partitions_fn: Optional[Callable[[], List[TopicPartition]]] = None,
        should_abort_fn: Optional[Callable[[], bool]] = None,
        messages: Optional[List[Any]] = None,
    ) -> DeliveryOutcome:
        """
        Ships `gelf_batch` to `gelf_url` over HTTP POST.
        Retries on HTTP non-2xx or `httpx.RequestError` according to `retry_policy`.
        While backing off, pauses assigned partitions and polls ONLY while paused.
        """
        if dry_run:
            for item in gelf_batch:
                if item.get("_honeytoken_alert"):
                    logger.warning(
                        "[DRY-RUN GRAYLOG] Honeytoken Alert Delivered: %s",
                        item["short_message"],
                    )
            return DeliveryOutcome.DELIVERED

        def _resolve_assigned_partitions() -> List[TopicPartition]:
            if get_assigned_partitions_fn is not None:
                return list(get_assigned_partitions_fn())
            if consumer is not None:
                assignment_fn = getattr(consumer, "assignment", None)
                if callable(assignment_fn):
                    raw = assignment_fn()
                    if isinstance(raw, (list, tuple, set)):
                        return list(raw)
            return []

        ndjson_payload = serialize_ndjson_batch(gelf_batch)
        attempt = 0
        paused = False
        paused_keys: Set[Tuple[str, int]] = set()

        record_batch_size(len(gelf_batch))
        post_kwargs: Dict[str, Any] = {"content": ndjson_payload}
        tp = create_consumer_traceparent(messages)
        if tp:
            post_kwargs["headers"] = {"traceparent": tp}

        try:
            while is_running_fn():
                if should_abort_fn is not None and should_abort_fn():
                    record_delivery_attempt("aborted")
                    return DeliveryOutcome.ABORTED

                attempt += 1
                t0 = time.monotonic()
                try:
                    response = http_client.post(
                        gelf_url,
                        **post_kwargs,
                    )
                    latency = max(0.0, time.monotonic() - t0)
                    record_graylog_delivery_latency(latency)

                    if 200 <= response.status_code < 300:
                        record_delivery_attempt("2xx")
                        record_end_to_end_latency(messages)
                        if attempt > 1:
                            logger.info(
                                "Graylog recovered! Batch of %d GELF logs accepted on attempt %d.",
                                len(gelf_batch),
                                attempt,
                                extra={
                                    "batch_id": batch_id,
                                    "retry_count": attempt - 1,
                                    "message_count": len(gelf_batch),
                                },
                            )
                        return DeliveryOutcome.DELIVERED

                    if 500 <= response.status_code < 600:
                        record_delivery_attempt("5xx")
                    elif 400 <= response.status_code < 500:
                        record_delivery_attempt("4xx")
                    else:
                        record_delivery_attempt("error")
                    error_reason = f"HTTP {response.status_code}: {response.text[:200]}"
                except httpx.RequestError as exc:
                    latency = max(0.0, time.monotonic() - t0)
                    record_graylog_delivery_latency(latency)
                    record_delivery_attempt("error")
                    error_reason = f"Connection/Timeout error: {exc}"

                if retry_policy.max_retries > 0 and attempt >= retry_policy.max_retries:
                    logger.error(
                        "Exceeded MAX_DELIVERY_RETRIES (%d) due to %s. Persisting batch to Dead Letter store.",
                        retry_policy.max_retries,
                        error_reason,
                        extra={
                            "batch_id": batch_id,
                            "retry_count": attempt,
                            "message_count": len(gelf_batch),
                        },
                    )
                    try:
                        try:
                            dlq_res = on_dead_letter(
                                gelf_batch, messages=messages, reason=error_reason
                            )
                        except TypeError:
                            dlq_res = on_dead_letter(gelf_batch)
                        if dlq_res is False:
                            logger.error(
                                "Dead letter publish failed (delivery report unconfirmed); aborting batch without commit."
                            )
                            record_delivery_attempt("aborted")
                            return DeliveryOutcome.ABORTED
                    except Exception as exc:
                        logger.error(
                            "Dead letter persistence raised exception (%s); aborting batch without commit.",
                            exc,
                        )
                        record_delivery_attempt("aborted")
                        return DeliveryOutcome.ABORTED
                    record_delivery_attempt("dlq")
                    return DeliveryOutcome.DEAD_LETTERED

                jitter_val = self._jitter_fn(
                    retry_policy.jitter_min, retry_policy.jitter_max
                )
                sleep_duration = retry_policy.compute_backoff(
                    attempt, jitter_value=jitter_val
                )

                logger.warning(
                    "[BACKPRESSURE HOLD] Graylog delivery failed (attempt=%d, batch_size=%d, reason=%s). "
                    "Offsets NOT committed. Retrying in %.2fs...",
                    attempt,
                    len(gelf_batch),
                    error_reason,
                    sleep_duration,
                    extra={
                        "batch_id": batch_id,
                        "retry_count": attempt,
                        "message_count": len(gelf_batch),
                    },
                )

                assigned_partitions = _resolve_assigned_partitions()
                if consumer is not None and assigned_partitions:
                    if not paused:
                        consumer.pause(assigned_partitions)
                        paused = True
                        paused_keys = {
                            (tp.topic, int(tp.partition)) for tp in assigned_partitions
                        }
                    else:
                        unpaused = [
                            tp
                            for tp in assigned_partitions
                            if (tp.topic, int(tp.partition)) not in paused_keys
                        ]
                        if unpaused:
                            consumer.pause(unpaused)
                            for tp in unpaused:
                                paused_keys.add((tp.topic, int(tp.partition)))

                # Sleep in small increments so SIGTERM/SIGINT remains responsive.
                # Keep the group session alive by polling ONLY while paused.
                slept = 0.0
                while slept < sleep_duration and is_running_fn():
                    if should_abort_fn is not None and should_abort_fn():
                        break
                    if paused and consumer is not None:
                        current_assigned = _resolve_assigned_partitions()
                        if current_assigned:
                            newly_assigned = [
                                tp
                                for tp in current_assigned
                                if (tp.topic, int(tp.partition)) not in paused_keys
                            ]
                            if newly_assigned:
                                consumer.pause(newly_assigned)
                                for tp in newly_assigned:
                                    paused_keys.add((tp.topic, int(tp.partition)))
                            consumer.poll(0)
                        else:
                            paused = False
                        if should_abort_fn is not None and should_abort_fn():
                            break
                    step = min(retry_policy.sleep_step_seconds, sleep_duration - slept)
                    self._sleep_fn(step)
                    slept += step

                if should_abort_fn is not None and should_abort_fn():
                    record_delivery_attempt("aborted")
                    return DeliveryOutcome.ABORTED

            record_delivery_attempt("aborted")
            return DeliveryOutcome.ABORTED
        finally:
            if paused and consumer is not None:
                resume_targets = _resolve_assigned_partitions()
                if resume_targets:
                    consumer.resume(resume_targets)

