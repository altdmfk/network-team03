import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from middleware.redaction import redact_sensitive_data

_CORRELATION_FIELDS = (
    "batch_id",
    "partition",
    "offset_range",
    "retry_count",
    "message_count",
    "client_ip",
    "event_type",
)


class StructuredJsonFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON objects with ISO-8601 UTC timestamps
    and optional correlation fields (batch_id, partition, offset_range, retry_count).
    Ensures sensitive fields are redacted before serialization.
    """

    def format(self, record: logging.LogRecord) -> str:
        raw_msg = record.getMessage()
        # Redact message if it contains embedded JSON
        safe_msg = redact_sensitive_data(raw_msg)
        payload: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": safe_msg,
        }
        for key in _CORRELATION_FIELDS:
            val = getattr(record, key, None)
            if val is not None:
                payload[key] = redact_sensitive_data(val)

        extra_context = getattr(record, "correlation", None)
        if isinstance(extra_context, dict):
            for k, v in extra_context.items():
                if v is not None:
                    payload[k] = redact_sensitive_data(v)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def configure_logging(
    logger_name: str,
    level: int = logging.INFO,
    log_format: Optional[str] = None,
) -> logging.Logger:
    """
    Configures root/module logging. Supports `LOG_FORMAT=json` for structured production
    logging and `LOG_FORMAT=text` (default) for human-readable CLI/demo output.
    """
    resolved_format = (log_format or os.getenv("LOG_FORMAT", "text")).strip().lower()
    root_logger = logging.getLogger()

    if not root_logger.handlers:
        handler = logging.StreamHandler()
        if resolved_format == "json":
            handler.setFormatter(StructuredJsonFormatter())
        else:
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s")
            )
        root_logger.addHandler(handler)
        root_logger.setLevel(level)
    elif resolved_format == "json":
        for handler in root_logger.handlers:
            if not isinstance(handler.formatter, StructuredJsonFormatter):
                handler.setFormatter(StructuredJsonFormatter())

    logger = logging.getLogger(logger_name)
    logger.setLevel(level)
    return logger
