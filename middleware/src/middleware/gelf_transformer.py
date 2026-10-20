import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from config import BROKER_TOPIC, GELF_HOST

logger = logging.getLogger("soar.gelf_transformer")


def _build_gelf_envelope(
    *,
    host: str,
    short_message: str,
    timestamp: float,
    level: int,
    partition: int,
    offset: int,
    client_ip: str,
    event_type: str,
    target_resource: str,
    status_code: int,
    serialized_raw_payload: str,
    is_honeytoken: bool,
    event_id: Optional[str] = None,
    topic: str = BROKER_TOPIC,
) -> Dict[str, Any]:
    """Constructs a canonical GELF 1.1 dictionary with deterministic `_event_id` and `_broker_topic`."""
    effective_event_id = event_id if event_id is not None else f"{partition}:{offset}"
    return {
        "version": "1.1",
        "host": host,
        "short_message": short_message,
        "timestamp": timestamp,
        "level": level,
        "_event_id": effective_event_id,
        "_client_ip": client_ip,
        "_event_type": event_type,
        "_target_resource": target_resource,
        "_status_code": status_code,
        "_raw_payload": serialized_raw_payload,
        "_honeytoken_alert": is_honeytoken,
        "_broker_topic": topic,
        "_broker_partition": partition,
        "_broker_offset": offset,
    }


def transform_to_gelf(
    raw_event: Any,
    partition: int = 0,
    offset: int = 0,
    host: str = GELF_HOST,
    topic: Optional[str] = None,
    broker_topic: Optional[str] = None,
    broker_partition: Optional[int] = None,
    broker_offset: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Transforms a standardized security JSON log into a Graylog Extended Log Format
    (GELF 1.1) payload while strictly preserving the original Unix epoch timestamp
    for accurate Kill-Chain correlation and embedding a deterministic `_event_id`
    (`"{partition}:{offset}"`) for idempotent deduplication across retries.
    """
    if isinstance(raw_event, (bytes, str)):
        raw_event = json.loads(raw_event)
    elif not isinstance(raw_event, dict):
        raw_event = dict(raw_event)

    eff_partition = (
        broker_partition
        if broker_partition is not None
        else partition
    )
    eff_offset = (
        broker_offset
        if broker_offset is not None
        else offset
    )
    eff_topic = (
        broker_topic
        if broker_topic is not None
        else topic
    )

    client_ip = str(raw_event.get("client_ip", "0.0.0.0"))
    event_type = str(raw_event.get("event_type", "UNKNOWN")).upper()
    target_resource = str(raw_event.get("target_resource", "/"))
    status_code = int(raw_event.get("status_code", 0))
    severity = int(raw_event.get("severity", 6))
    original_timestamp = round(float(raw_event.get("timestamp", time.time())), 3)
    raw_payload = raw_event.get("raw_payload", {})

    if isinstance(raw_payload, (dict, list)):
        serialized_raw_payload = json.dumps(
            raw_payload, separators=(",", ":"), ensure_ascii=False
        )
    else:
        serialized_raw_payload = str(raw_payload)

    is_honeytoken = event_type == "HONEYTOKEN_ACCESS"
    short_message = f"[{event_type}] {client_ip} -> {target_resource} ({status_code})"
    raw_event_id = raw_event.get("_event_id")
    event_id = str(raw_event_id).strip() if raw_event_id is not None and str(raw_event_id).strip() else None

    effective_topic = (
        eff_topic
        if eff_topic is not None
        else (
            raw_event.get("_broker_topic")
            or raw_event.get("broker_topic")
            or raw_event.get("topic")
            or BROKER_TOPIC
        )
    )

    return _build_gelf_envelope(
        host=host,
        short_message=short_message,
        timestamp=original_timestamp,
        level=severity,
        partition=eff_partition,
        offset=eff_offset,
        client_ip=client_ip,
        event_type=event_type,
        target_resource=target_resource,
        status_code=status_code,
        serialized_raw_payload=serialized_raw_payload,
        is_honeytoken=is_honeytoken,
        event_id=event_id,
        topic=effective_topic,
    )


def serialize_ndjson_batch(gelf_batch: List[Dict[str, Any]]) -> bytes:
    """Serializes a list of GELF 1.1 dicts into a newline-delimited UTF-8 byte payload."""
    return "\n".join(
        json.dumps(item, separators=(",", ":"), ensure_ascii=False)
        for item in gelf_batch
    ).encode("utf-8")


class GelfTransformer:
    """
    Stateless batch transformer that converts raw Broker `Message` objects into
    GELF 1.1 dictionaries, wrapping malformed payloads in a structured fallback
    envelope so poison messages never block partition progress or drop silently.
    """

    def __init__(self, host: str = GELF_HOST) -> None:
        self.host = host

    @staticmethod
    def is_poison(msg: Any) -> Tuple[bool, Optional[str]]:
        """
        Determines if a message is unparseable poison (not valid JSON object).
        Returns (is_poison, error_reason).
        """
        try:
            val_fn = getattr(msg, "value", None)
            raw_bytes = val_fn() if callable(val_fn) else msg
            if raw_bytes is None:
                return True, "Message value is None"
            if not isinstance(raw_bytes, (bytes, bytearray)):
                raw_bytes = str(raw_bytes).encode("utf-8")
            decoded = json.loads(raw_bytes.decode("utf-8"))
            if not isinstance(decoded, dict):
                return True, "Decoded JSON payload is not an object"
            return False, None
        except Exception as exc:
            return True, str(exc)

    def transform_message(self, msg: Any) -> Dict[str, Any]:
        partition = int(msg.partition())
        offset = int(msg.offset())
        topic_fn = getattr(msg, "topic", None)
        msg_topic = topic_fn() if callable(topic_fn) else None
        try:
            raw_bytes = msg.value()
            decoded = json.loads(raw_bytes.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise ValueError("Decoded JSON payload is not an object")
            return transform_to_gelf(
                decoded,
                partition=partition,
                offset=offset,
                host=self.host,
                topic=msg_topic,
            )
        except Exception as exc:
            logger.error(
                "Malformed message at partition=%d offset=%d (%s); wrapping raw payload into GELF.",
                partition,
                offset,
                exc,
                extra={"partition": partition, "offset_range": f"{offset}-{offset}"},
            )
            raw_key = msg.key()
            raw_val = msg.value()
            return _build_gelf_envelope(
                host=self.host,
                short_message="[RAW_PARSE_FALLBACK] Unstructured log event",
                timestamp=round(time.time(), 3),
                level=4,
                partition=partition,
                offset=offset,
                client_ip=(
                    raw_key.decode("utf-8", errors="replace")
                    if raw_key
                    else "0.0.0.0"
                ),
                event_type="UNPARSED_EVENT",
                target_resource="unknown",
                status_code=0,
                serialized_raw_payload=(
                    raw_val.decode("utf-8", errors="replace") if raw_val else ""
                ),
                is_honeytoken=False,
                topic=msg_topic or BROKER_TOPIC,
            )

    def transform_batch(self, messages: List[Any]) -> List[Dict[str, Any]]:
        return [self.transform_message(msg) for msg in messages]
