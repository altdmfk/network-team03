import json
import logging
import os
import threading
from typing import Any, Callable, Dict, List, Optional

import httpx

from middleware.dlq_publisher import DeadLetterSink
from middleware.gelf_transformer import serialize_ndjson_batch

logger = logging.getLogger("soar.dlq_store")


class JsonlDeadLetterStore(DeadLetterSink):
    """
    Thread-safe local JSONL Dead-Letter Queue (`dead_letter_logs.jsonl`) store and
    auto-replay engine. Uses fsync on append and atomic `.tmp` + `fsync` + `os.replace`
    when rewriting un-replayed records. Implements DeadLetterSink.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

    @staticmethod
    def _ensure_parent_dir(file_path: str) -> None:
        parent_dir = os.path.dirname(os.path.abspath(file_path))
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

    @staticmethod
    def _write_jsonl_lines_fsync(
        file_path: str, records: List[Dict[str, Any]], mode: str
    ) -> None:
        JsonlDeadLetterStore._ensure_parent_dir(file_path)
        with open(file_path, mode, encoding="utf-8") as handle:
            for item in records:
                handle.write(
                    json.dumps(item, separators=(",", ":"), ensure_ascii=False) + "\n"
                )
            handle.flush()
            os.fsync(handle.fileno())

    def write_batch(self, dlq_path: str, gelf_batch: List[Dict[str, Any]]) -> None:
        """Appends an undeliverable GELF batch to `dlq_path` with `os.fsync` durability."""
        with self._lock:
            self._write_jsonl_lines_fsync(dlq_path, gelf_batch, mode="a")
        logger.critical(
            "Wrote %d undeliverable GELF logs to local Dead Letter File: %s",
            len(gelf_batch),
            dlq_path,
            extra={"message_count": len(gelf_batch)},
        )

    def write_dead_letter(
        self,
        *,
        messages: Optional[List[Any]] = None,
        gelf_batch: Optional[List[Dict[str, Any]]] = None,
        reason: str = "Retries exhausted",
        retry_count: int = 0,
        dlq_path: Optional[str] = None,
    ) -> bool:
        """
        Durably writes undeliverable messages/records to the local JSONL file.
        Returns True on success.
        """
        target_path = dlq_path or "./state/dead_letter_logs.jsonl"
        records: List[Dict[str, Any]] = []
        if gelf_batch:
            records = list(gelf_batch)
        elif messages:
            for msg in messages:
                val = msg.value() if hasattr(msg, "value") and callable(msg.value) else msg
                try:
                    records.append(json.loads(val.decode("utf-8")))
                except Exception:
                    records.append({"raw": str(val), "reason": reason})
        if not records:
            return True
        self.write_batch(target_path, records)
        return True

    def rewrite_remaining(
        self, dlq_path: str, remaining_records: List[Dict[str, Any]]
    ) -> None:
        """
        Atomically updates `dlq_path` via a `.tmp` file replacement (or removes
        `dlq_path` when all records have been replayed).
        """
        tmp_path = f"{dlq_path}.tmp"
        with self._lock:
            if not remaining_records:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except OSError:
                    pass
                try:
                    if os.path.exists(dlq_path):
                        os.remove(dlq_path)
                except OSError as exc:
                    logger.warning(
                        "Failed to remove empty DLQ file %s: %s", dlq_path, exc
                    )
                return

            self._write_jsonl_lines_fsync(tmp_path, remaining_records, mode="w")
            os.replace(tmp_path, dlq_path)

    def read_records(self, dlq_path: str) -> List[Dict[str, Any]]:
        """Reads all valid JSONL objects from `dlq_path`, skipping blank or corrupt lines."""
        records: List[Dict[str, Any]] = []
        with self._lock:
            with open(dlq_path, "r", encoding="utf-8") as dlq_file:
                for raw_line in dlq_file:
                    stripped = raw_line.strip()
                    if not stripped:
                        continue
                    try:
                        records.append(json.loads(stripped))
                    except json.JSONDecodeError as exc:
                        logger.warning(
                            "Skipping malformed JSON line in DLQ file %s: %s",
                            dlq_path,
                            exc,
                        )
        return records

    def replay(
        self,
        *,
        dlq_path: str,
        batch_size: int,
        acquire_tokens_fn: Callable[[float], float],
        http_client: httpx.Client,
        gelf_url: str,
        dry_run: bool,
        is_running_fn: Callable[[], bool],
        on_chunk_replayed: Callable[[int], Any],
    ) -> int:
        """
        Reads `dlq_path` and ships queued records to Graylog in chunks of `batch_size`.
        On each HTTP 2xx chunk, atomically rewrites remaining records on disk and invokes
        `on_chunk_replayed(chunk_len)`. Stops immediately on first failure so remaining
        records stay safely queued on disk.
        """
        if not dlq_path or not os.path.exists(dlq_path):
            return 0
        try:
            if os.path.getsize(dlq_path) <= 0:
                return 0
        except OSError:
            return 0

        try:
            records = self.read_records(dlq_path)
        except OSError as exc:
            logger.warning("Unable to read DLQ file %s for replay: %s", dlq_path, exc)
            return 0

        if not records:
            self.rewrite_remaining(dlq_path, [])
            return 0

        replayed_total = 0
        total_records = len(records)
        idx = 0

        while idx < total_records and is_running_fn():
            chunk = records[idx : idx + batch_size]
            chunk_len = len(chunk)
            acquire_tokens_fn(float(chunk_len))

            if dry_run:
                delivered = True
            else:
                ndjson_payload = serialize_ndjson_batch(chunk)
                try:
                    response = http_client.post(
                        gelf_url,
                        content=ndjson_payload,
                    )
                    delivered = 200 <= response.status_code < 300
                    if not delivered:
                        logger.warning(
                            "DLQ replay paused (HTTP %d from Graylog); %d records remain queued on disk.",
                            response.status_code,
                            total_records - idx,
                        )
                except httpx.RequestError as exc:
                    delivered = False
                    logger.warning(
                        "DLQ replay paused (%s); %d records remain queued on disk.",
                        exc,
                        total_records - idx,
                    )

            if not delivered:
                break

            idx += chunk_len
            replayed_total += chunk_len
            remaining_records = records[idx:]
            self.rewrite_remaining(dlq_path, remaining_records)
            on_chunk_replayed(chunk_len)
            logger.info(
                "Replayed %d recovered DLQ logs to Graylog (%d remaining in DLQ).",
                chunk_len,
                len(remaining_records),
                extra={"message_count": chunk_len},
            )

        return replayed_total
