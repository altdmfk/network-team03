"""
Lightweight Disk-Backed Partitioned Log Broker Engine.

Drop-in, zero-dependency, process-safe log buffering middleware
with an optimized SQLite WAL (Write-Ahead Logging) partitioned storage engine.

Core Architectural Guarantees:
1. Strict FIFO ordering per client_ip via deterministic CRC32 partition hashing:
   `partition = zlib.crc32(key_bytes) % num_partitions`
2. Strictly monotonic, 0-based contiguous offset integers per (topic, partition) so that:
   `_event_id = f"{partition}:{offset}"` and watermark calculations (`high_watermark - committed_offset`)
   work identically across partitions.
3. Zero-loss paused backoff support: When partitions are paused via `consumer.pause(partitions)`,
   `consumer.poll(0)` NEVER dequeues any messages from paused partitions.
4. Process-safe concurrency using SQLite WAL mode (`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`)
   with `BEGIN IMMEDIATE` transactions and busy handlers for multi-process writer safety.
5. High-throughput burst ingestion (5,000+ EPS) via in-memory queue buffering and batched WAL commits.
6. Immediate backpressure via `BufferError` when in-memory queue size or unconsumed lag exceeds bounds.
"""

from __future__ import annotations

import collections
import json
import logging
import os
import queue
import random
import sqlite3
import threading
import time
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)
import zlib

logger = logging.getLogger("soar.lightweight_broker")

# Broker sentinel offset for uncommitted partitions
OFFSET_INVALID: int = -1001

# Standard topics required by SOAR pipeline
DEFAULT_TOPICS: Tuple[str, ...] = (
    "security-logs",
    "security-logs.priority",
    "security-logs.dlq",
    "security-logs.retry.1m",
    "security-logs.retry.10m",
    "security-logs.poison",
)
DEFAULT_NUM_PARTITIONS: int = 3


# ---------------------------------------------------------------------------
# Broker Error Definitions
# ---------------------------------------------------------------------------
class BrokerError:
    """Lightweight compatibility wrapper mimicking error codes."""

    _NO_ERROR = 0
    _PARTITION_EOF = -191
    _REVOKED_PARTITIONS = -175
    _ALL_BROKERS_DOWN = -187
    _WAIT_COORD = -181
    _IN_PROGRESS = -176
    TOPIC_ALREADY_EXISTS = 36
    UNKNOWN_TOPIC_OR_PART = 3
    OFFSET_OUT_OF_RANGE = 1
    INVALID_MSG = 2
    REBALANCE_IN_PROGRESS = 27
    ILLEGAL_GENERATION = 22
    UNKNOWN_MEMBER_ID = 25
    NOT_COORDINATOR_FOR_GROUP = 16

    def __init__(self, code: int = 0, reason: str = "") -> None:
        self._code = code
        self._reason = reason

    def code(self) -> int:
        return self._code

    def name(self) -> str:
        for attr, val in BrokerError.__dict__.items():
            if val == self._code and not attr.startswith("__"):
                return attr
        return f"ERROR_{self._code}"

    def str(self) -> str:
        return self._reason or self.name()

    def __repr__(self) -> str:
        return f"BrokerError(code={self._code}, name={self.name()})"

    def __bool__(self) -> bool:
        return self._code != BrokerError._NO_ERROR


class CallableTuple(tuple):
    """Tuple that can also be called as a method for compatibility with args()."""

    def __call__(self) -> "CallableTuple":
        return self


class BrokerException(Exception):
    """Broker exception wrapper."""

    def __init__(self, error: Any = None) -> None:
        if isinstance(error, BrokerError):
            self._error = error
        elif isinstance(error, int):
            self._error = BrokerError(code=error)
        elif error is None:
            self._error = BrokerError(code=0)
        else:
            self._error = error
        super().__init__(self._error)

    @property
    def args(self) -> CallableTuple:
        return CallableTuple((self._error,))

    @args.setter
    def args(self, val: Any) -> None:
        pass


# ---------------------------------------------------------------------------
# TopicPartition Abstraction
# ---------------------------------------------------------------------------
class TopicPartition:
    """Represents a topic and partition with an optional offset and error status."""

    def __init__(
        self,
        topic: str,
        partition: int = -1,
        offset: int = OFFSET_INVALID,
        error: Optional[Any] = None,
    ) -> None:
        self.topic = str(topic)
        self.partition = int(partition)
        self.offset = int(offset) if offset is not None else OFFSET_INVALID
        self.error = error

    def __repr__(self) -> str:
        return (
            f"TopicPartition(topic='{self.topic}', partition={self.partition}, "
            f"offset={self.offset}"
            + (f", error={self.error}" if self.error else "")
            + ")"
        )

    def __eq__(self, other: Any) -> bool:
        if other is None:
            return False
        return (
            getattr(other, "topic", None) == self.topic
            and getattr(other, "partition", None) == self.partition
            and getattr(other, "offset", None) == self.offset
        )

    def __hash__(self) -> int:
        return hash((self.topic, self.partition, self.offset))

    def __lt__(self, other: Any) -> bool:
        return (self.topic, self.partition, self.offset) < (
            getattr(other, "topic", ""),
            int(getattr(other, "partition", 0)),
            int(getattr(other, "offset", 0)),
        )


# ---------------------------------------------------------------------------
# Broker Message Abstraction
# ---------------------------------------------------------------------------
class LightweightMessage:
    """
    Message object implementing broker Message interface methods:
    `.topic()`, `.partition()`, `.offset()`, `.value()`, `.key()`, `.headers()`,
    `.error()`, `.timestamp()`.
    """

    def __init__(
        self,
        topic: str,
        partition: int,
        offset: int,
        value: Union[bytes, bytearray, str, None],
        key: Optional[Union[bytes, bytearray, str]] = None,
        headers: Optional[List[Tuple[str, bytes]]] = None,
        timestamp_ms: Optional[int] = None,
        error: Optional[Any] = None,
    ) -> None:
        self._topic = str(topic)
        self._partition = int(partition)
        self._offset = int(offset)
        if isinstance(value, (bytes, bytearray)):
            self._value: Optional[bytes] = bytes(value)
        elif isinstance(value, str):
            self._value = value.encode("utf-8")
        elif value is None:
            self._value = None
        else:
            self._value = str(value).encode("utf-8")

        if isinstance(key, (bytes, bytearray)):
            self._key: Optional[bytes] = bytes(key)
        elif isinstance(key, str):
            self._key = key.encode("utf-8")
        else:
            self._key = None

        self._headers = headers
        self._timestamp_ms = (
            int(timestamp_ms) if timestamp_ms is not None else int(time.time() * 1000)
        )
        self._error = error

    def topic(self) -> str:
        return self._topic

    def partition(self) -> int:
        return self._partition

    def offset(self) -> int:
        return self._offset

    def value(self) -> Optional[bytes]:
        return self._value

    def key(self) -> Optional[bytes]:
        return self._key

    def headers(self) -> Optional[List[Tuple[str, bytes]]]:
        return self._headers

    def error(self) -> Optional[Any]:
        return self._error

    def timestamp(self) -> Tuple[int, int]:
        # Return (TIMESTAMP_CREATE_TIME=1, timestamp_ms)
        return (1, self._timestamp_ms)

    def timestamp_ms(self) -> int:
        return self._timestamp_ms

    def __repr__(self) -> str:
        val_len = len(self._value) if self._value else 0
        return (
            f"LightweightMessage(topic='{self._topic}', partition={self._partition}, "
            f"offset={self._offset}, key={self._key!r}, val_len={val_len})"
        )


# ---------------------------------------------------------------------------
# Header Serialization Helpers
# ---------------------------------------------------------------------------
def serialize_headers(headers: Optional[List[Tuple[str, bytes]]]) -> Optional[str]:
    """Serializes a list of (str, bytes) header tuples into a JSON string preserving binary data."""
    if headers is None:
        return None
    packed: List[List[str]] = []
    for k, v in headers:
        k_str = str(k)
        if isinstance(v, (bytes, bytearray)):
            v_hex = bytes(v).hex()
        elif isinstance(v, str):
            v_hex = v.encode("utf-8").hex()
        elif v is None:
            v_hex = ""
        else:
            v_hex = str(v).encode("utf-8").hex()
        packed.append([k_str, v_hex])
    return json.dumps(packed, separators=(",", ":"))


def deserialize_headers(data: Optional[str]) -> Optional[List[Tuple[str, bytes]]]:
    """Deserializes JSON header string back to list of (str, bytes)."""
    if not data:
        return None
    try:
        packed = json.loads(data)
        if not isinstance(packed, list):
            return None
        result: List[Tuple[str, bytes]] = []
        for item in packed:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                k, v_hex = item
                result.append((str(k), bytes.fromhex(str(v_hex))))
        return result
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Deterministic CRC32 Partition Router
# ---------------------------------------------------------------------------
def compute_partition(
    key: Optional[Union[bytes, bytearray, str]], num_partitions: int
) -> Optional[int]:
    """
    Computes deterministic partition index using:
    `partition = zlib.crc32(key_bytes) % num_partitions`
    Preserves strict Kill-Chain FIFO ordering per client_ip.
    """
    if key is None or num_partitions <= 0:
        return None
    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
    else:
        key_bytes = bytes(key)
    return (zlib.crc32(key_bytes) & 0xFFFFFFFF) % num_partitions


# ---------------------------------------------------------------------------
# Disk-Backed SQLite WAL Storage Engine
# ---------------------------------------------------------------------------
class SQLiteBrokerStorage:
    """
    Process-safe, disk-backed partitioned log storage engine using SQLite in WAL mode
    with explicit BEGIN IMMEDIATE transactions and per-thread connections.
    """

    def __init__(
        self,
        db_path: str,
        timeout: float = 15.0,
        default_partitions: int = DEFAULT_NUM_PARTITIONS,
    ) -> None:
        self.db_path = os.path.abspath(db_path)
        self.timeout = float(timeout)
        self.default_partitions = int(default_partitions)
        self._local = threading.local()
        self._lock = threading.Lock()

        # Ensure target directory exists
        parent_dir = os.path.dirname(self.db_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Returns a thread-local SQLite connection configured for WAL mode and high throughput."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                self.db_path,
                timeout=self.timeout,
                isolation_level=None,  # Autocommit mode: we control transactions explicitly
                check_same_thread=True,
            )
            # 1. Set busy_timeout FIRST so any subsequent PRAGMA or lock waits instead of failing
            conn.execute(f"PRAGMA busy_timeout = {int(self.timeout * 1000)};")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA cache_size = -64000;")  # 64MB cache
            conn.execute("PRAGMA temp_store = MEMORY;")

            # 2. Check journal mode and convert to WAL only if not already WAL
            try:
                row = conn.execute("PRAGMA journal_mode;").fetchone()
                if not row or str(row[0]).lower() != "wal":
                    conn.execute("PRAGMA journal_mode = WAL;")
            except sqlite3.OperationalError:
                pass

            self._local.conn = conn
        return conn

    def _execute_with_retry(
        self,
        func: Callable[[sqlite3.Connection], Any],
        max_retries: int = 10,
    ) -> Any:
        """Executes a database function with exponential backoff on busy/locked errors."""
        last_exc: Optional[Exception] = None
        for attempt in range(max_retries):
            conn = self.get_connection()
            try:
                return func(conn)
            except sqlite3.OperationalError as exc:
                err_msg = str(exc).lower()
                if "locked" in err_msg or "busy" in err_msg:
                    last_exc = exc
                    if attempt < max_retries - 1:
                        sleep_time = 0.01 * (2**attempt) + random.uniform(0.005, 0.02)
                        time.sleep(sleep_time)
                        continue
                raise
        if last_exc:
            raise last_exc

    def _init_db(self) -> None:
        """Initializes tables, metadata, and indexes if they do not exist."""

        def _do_init(conn: sqlite3.Connection) -> None:
            # Check if schema is already initialized to avoid write lock contention
            check = conn.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='messages';"
            ).fetchone()
            if check and check[0] > 0:
                return

            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS topics_meta (
                        topic TEXT PRIMARY KEY,
                        num_partitions INTEGER NOT NULL,
                        config TEXT
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS partition_meta (
                        topic TEXT NOT NULL,
                        partition INTEGER NOT NULL,
                        next_offset INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (topic, partition)
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS messages (
                        topic TEXT NOT NULL,
                        partition INTEGER NOT NULL,
                        offset INTEGER NOT NULL,
                        key BLOB,
                        value BLOB NOT NULL,
                        headers TEXT,
                        timestamp_ms INTEGER NOT NULL,
                        created_at REAL NOT NULL,
                        PRIMARY KEY (topic, partition, offset)
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_messages_topic_part_offset
                    ON messages(topic, partition, offset);
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS consumer_offsets (
                        group_id TEXT NOT NULL,
                        topic TEXT NOT NULL,
                        partition INTEGER NOT NULL,
                        committed_offset INTEGER NOT NULL,
                        committed_at REAL NOT NULL,
                        PRIMARY KEY (group_id, topic, partition)
                    );
                    """
                )

                # Initialize default topics if not already registered
                for topic in DEFAULT_TOPICS:
                    conn.execute(
                        "INSERT OR IGNORE INTO topics_meta (topic, num_partitions, config) VALUES (?, ?, ?);",
                        (topic, self.default_partitions, "{}"),
                    )
                    for p in range(self.default_partitions):
                        conn.execute(
                            "INSERT OR IGNORE INTO partition_meta (topic, partition, next_offset) VALUES (?, ?, 0);",
                            (topic, p),
                        )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

        self._execute_with_retry(_do_init)

    def get_topic_partitions(self, topic: str) -> int:
        """Returns the configured partition count for a topic, creating default meta if missing."""
        conn = self.get_connection()
        cursor = conn.execute(
            "SELECT num_partitions FROM topics_meta WHERE topic = ?;", (topic,)
        )
        row = cursor.fetchone()
        if row:
            return int(row[0])

        # Auto-create topic with default partitions
        self.ensure_topic(topic, self.default_partitions)
        return self.default_partitions

    def ensure_topic(
        self,
        topic: str,
        num_partitions: int = DEFAULT_NUM_PARTITIONS,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Registers a topic and initializes partition offset trackers."""

        def _do_ensure(conn: sqlite3.Connection) -> None:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO topics_meta (topic, num_partitions, config) VALUES (?, ?, ?);",
                    (topic, int(num_partitions), json.dumps(config or {})),
                )
                for p in range(int(num_partitions)):
                    conn.execute(
                        "INSERT OR IGNORE INTO partition_meta (topic, partition, next_offset) VALUES (?, ?, 0);",
                        (topic, p),
                    )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

        self._execute_with_retry(_do_ensure)

    def list_topics(self) -> Dict[str, int]:
        """Returns all registered topics and their partition counts."""
        conn = self.get_connection()
        cursor = conn.execute("SELECT topic, num_partitions FROM topics_meta;")
        return {str(row[0]): int(row[1]) for row in cursor.fetchall()}

    def store_batch(
        self,
        items: List[
            Tuple[
                str,
                int,
                Optional[bytes],
                bytes,
                Optional[List[Tuple[str, bytes]]],
                int,
            ]
        ],
    ) -> List[LightweightMessage]:
        """
        Atomically appends a batch of messages inside a single `BEGIN IMMEDIATE` transaction.
        Assigns strictly monotonic 0-based contiguous offsets per (topic, partition).
        Returns a list of created `LightweightMessage` instances.
        """
        if not items:
            return []

        # Group items by (topic, partition) to compute contiguous offset slices
        by_tp: Dict[
            Tuple[str, int],
            List[
                Tuple[
                    int,
                    str,
                    int,
                    Optional[bytes],
                    bytes,
                    Optional[List[Tuple[str, bytes]]],
                    int,
                ]
            ],
        ] = collections.defaultdict(list)
        for orig_idx, (topic, partition, key, val, hdrs, ts_ms) in enumerate(items):
            by_tp[(topic, partition)].append(
                (orig_idx, topic, partition, key, val, hdrs, ts_ms)
            )

        now = time.time()
        stored_messages: List[Tuple[int, LightweightMessage]] = []

        def _do_store(conn: sqlite3.Connection) -> None:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                insert_rows: List[
                    Tuple[
                        str,
                        int,
                        int,
                        Optional[bytes],
                        bytes,
                        Optional[str],
                        int,
                        float,
                    ]
                ] = []

                for (topic, partition), tp_items in by_tp.items():
                    # 1. Fetch current next_offset
                    cursor = conn.execute(
                        "SELECT next_offset FROM partition_meta WHERE topic = ? AND partition = ?;",
                        (topic, partition),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        # Auto-initialize partition_meta and topics_meta
                        base_offset = 0
                        conn.execute(
                            "INSERT OR IGNORE INTO topics_meta (topic, num_partitions, config) VALUES (?, ?, ?);",
                            (topic, max(self.default_partitions, partition + 1), "{}"),
                        )
                        conn.execute(
                            "INSERT INTO partition_meta (topic, partition, next_offset) VALUES (?, ?, ?);",
                            (topic, partition, len(tp_items)),
                        )
                    else:
                        base_offset = int(row[0])
                        conn.execute(
                            "UPDATE partition_meta SET next_offset = ? WHERE topic = ? AND partition = ?;",
                            (base_offset + len(tp_items), topic, partition),
                        )

                    # 2. Assign strictly contiguous offsets
                    for offset_idx, (
                        orig_idx,
                        t,
                        p,
                        k,
                        v,
                        hdrs,
                        ts_ms,
                    ) in enumerate(tp_items):
                        assigned_offset = base_offset + offset_idx
                        hdrs_str = serialize_headers(hdrs)
                        insert_rows.append(
                            (
                                t,
                                p,
                                assigned_offset,
                                k,
                                v,
                                hdrs_str,
                                ts_ms,
                                now,
                            )
                        )
                        stored_messages.append(
                            (
                                orig_idx,
                                LightweightMessage(
                                    topic=t,
                                    partition=p,
                                    offset=assigned_offset,
                                    value=v,
                                    key=k,
                                    headers=hdrs,
                                    timestamp_ms=ts_ms,
                                ),
                            )
                        )

                # 3. Batch insert messages
                conn.executemany(
                    """
                    INSERT INTO messages (topic, partition, offset, key, value, headers, timestamp_ms, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    insert_rows,
                )
                conn.execute("COMMIT;")
            except Exception:
                stored_messages.clear()
                conn.execute("ROLLBACK;")
                raise

        self._execute_with_retry(_do_store)
        stored_messages.sort(key=lambda pair: pair[0])
        return [msg for _, msg in stored_messages]

    def get_message(
        self, topic: str, partition: int, offset: int
    ) -> Optional[LightweightMessage]:
        """Fetches a single message by exact (topic, partition, offset)."""
        conn = self.get_connection()
        cursor = conn.execute(
            """
            SELECT topic, partition, offset, key, value, headers, timestamp_ms
            FROM messages
            WHERE topic = ? AND partition = ? AND offset = ?;
            """,
            (topic, int(partition), int(offset)),
        )
        row = cursor.fetchone()
        if not row:
            return None
        t, p, off, k, v, hdrs_str, ts_ms = row
        return LightweightMessage(
            topic=t,
            partition=p,
            offset=off,
            value=v,
            key=k,
            headers=deserialize_headers(hdrs_str),
            timestamp_ms=ts_ms,
        )

    def fetch_messages_batch(
        self, topic: str, partition: int, start_offset: int, limit: int = 100
    ) -> List[LightweightMessage]:
        """Fetches up to `limit` messages starting at `start_offset`."""
        conn = self.get_connection()
        cursor = conn.execute(
            """
            SELECT topic, partition, offset, key, value, headers, timestamp_ms
            FROM messages
            WHERE topic = ? AND partition = ? AND offset >= ?
            ORDER BY offset ASC
            LIMIT ?;
            """,
            (topic, int(partition), int(start_offset), int(limit)),
        )
        messages: List[LightweightMessage] = []
        for row in cursor.fetchall():
            t, p, off, k, v, hdrs_str, ts_ms = row
            messages.append(
                LightweightMessage(
                    topic=t,
                    partition=p,
                    offset=off,
                    value=v,
                    key=k,
                    headers=deserialize_headers(hdrs_str),
                    timestamp_ms=ts_ms,
                )
            )
        return messages

    def get_watermark_offsets(self, topic: str, partition: int) -> Tuple[int, int]:
        """
        Returns (low_watermark, high_watermark) for (topic, partition).
        - low_watermark: earliest available offset (0 or MIN(offset)).
        - high_watermark: offset of next message to be written (latest + 1, or next_offset).
        """
        conn = self.get_connection()
        cursor = conn.execute(
            "SELECT next_offset FROM partition_meta WHERE topic = ? AND partition = ?;",
            (topic, int(partition)),
        )
        row = cursor.fetchone()
        high = int(row[0]) if row is not None else 0

        cursor = conn.execute(
            "SELECT MIN(offset) FROM messages WHERE topic = ? AND partition = ?;",
            (topic, int(partition)),
        )
        row = cursor.fetchone()
        low = int(row[0]) if (row is not None and row[0] is not None) else 0
        return (low, high)

    def get_committed_offset(
        self, group_id: str, topic: str, partition: int
    ) -> Optional[int]:
        """Returns the committed offset for (group_id, topic, partition), or None if uncommitted."""
        conn = self.get_connection()
        cursor = conn.execute(
            "SELECT committed_offset FROM consumer_offsets WHERE group_id = ? AND topic = ? AND partition = ?;",
            (group_id, topic, int(partition)),
        )
        row = cursor.fetchone()
        if row is not None:
            return int(row[0])
        return None

    def commit_offsets(
        self,
        group_id: str,
        offsets: Iterable[TopicPartition],
        asynchronous: bool = False,
    ) -> None:
        """Saves committed offsets for a consumer group."""
        offset_list = list(offsets)
        if not offset_list:
            return

        now = time.time()
        rows = [
            (group_id, tp.topic, int(tp.partition), int(tp.offset), now)
            for tp in offset_list
        ]

        def _do_commit(conn: sqlite3.Connection) -> None:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.executemany(
                    """
                    INSERT INTO consumer_offsets (group_id, topic, partition, committed_offset, committed_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(group_id, topic, partition)
                    DO UPDATE SET committed_offset = excluded.committed_offset,
                                  committed_at = excluded.committed_at;
                    """,
                    rows,
                )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

        self._execute_with_retry(_do_commit)

    def get_total_unconsumed_lag(
        self, group_id: Optional[str] = None, topic: Optional[str] = None
    ) -> int:
        """
        Calculates total unconsumed lag across partitions.
        `lag = sum(high_watermark - max(committed_offset, low_watermark))`
        """
        conn = self.get_connection()
        if topic is not None:
            part_cursor = conn.execute(
                "SELECT topic, partition, next_offset FROM partition_meta WHERE topic = ?;",
                (topic,),
            )
        else:
            part_cursor = conn.execute(
                "SELECT topic, partition, next_offset FROM partition_meta;"
            )

        partitions = part_cursor.fetchall()
        total_lag = 0

        for t, p, high in partitions:
            high_offset = int(high)
            committed_offset = 0
            if group_id:
                comm_cursor = conn.execute(
                    "SELECT committed_offset FROM consumer_offsets WHERE group_id = ? AND topic = ? AND partition = ?;",
                    (group_id, t, int(p)),
                )
                comm_row = comm_cursor.fetchone()
                if comm_row:
                    committed_offset = int(comm_row[0])
            else:
                # If group_id is not specified, use minimum committed across any consumer group
                comm_cursor = conn.execute(
                    "SELECT MIN(committed_offset) FROM consumer_offsets WHERE topic = ? AND partition = ?;",
                    (t, int(p)),
                )
                comm_row = comm_cursor.fetchone()
                if comm_row and comm_row[0] is not None:
                    committed_offset = int(comm_row[0])

            effective_committed = max(0, min(committed_offset, high_offset))
            total_lag += max(0, high_offset - effective_committed)

        return total_lag

    def reset_all(self) -> None:
        """Truncates all stored messages, resets next_offsets, and clears consumer commits."""
        def _do_reset(conn: sqlite3.Connection) -> None:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.execute("DELETE FROM messages;")
                conn.execute("DELETE FROM consumer_offsets;")
                conn.execute("UPDATE partition_meta SET next_offset = 0;")
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

        self._execute_with_retry(_do_reset)

    def close(self) -> None:
        """Closes thread-local connection if present."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None


# ---------------------------------------------------------------------------
# Default Database Path Resolver
# ---------------------------------------------------------------------------
def resolve_default_broker_db_path() -> str:
    """Resolves default SQLite database path using environment or standard state location."""
    env_path = os.environ.get("LIGHTWEIGHT_BROKER_DB_PATH")
    if env_path:
        return env_path
    # Check if /app/state exists (Docker runtime)
    if os.path.isdir("/app/state"):
        return "/app/state/broker.db"
    # Fallback to local project ./state/broker.db
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "state", "broker.db")


# ---------------------------------------------------------------------------
# Producer Interface (LightweightProducer)
# ---------------------------------------------------------------------------
class LightweightProducer:
    """
    High-throughput non-blocking producer interface.

    Features:
    - `produce(topic, value, key=None, headers=None, on_delivery=None)`
    - `poll(timeout=0)` and `flush(timeout=None)`
    - Bounded in-memory queue (`max_queue_size`) & unconsumed lag checks raising `BufferError`
      immediately to trigger downstream HTTP 503 backpressure.
    - Asynchronous background WAL batch appender sustaining 5,000+ EPS bursts.
    """

    def __init__(
        self,
        config: Optional[Union[Dict[str, Any], Mapping[str, Any]]] = None,
        db_path: Optional[str] = None,
        max_queue_size: int = 10000,
        max_unconsumed_lag: Optional[int] = None,
        batch_size: int = 250,
        linger_ms: float = 2.0,
        num_partitions: int = DEFAULT_NUM_PARTITIONS,
        storage: Optional[SQLiteBrokerStorage] = None,
    ) -> None:
        cfg = dict(config or {})

        # Resolve db_path
        resolved_db = (
            cfg.get("broker.db.path")
            or cfg.get("state.db.path")
            or db_path
            or resolve_default_broker_db_path()
        )
        self.db_path = str(resolved_db)
        self.num_partitions = int(
            cfg.get(
                "num_partitions", cfg.get("broker_partitions", num_partitions)
            )
        )
        self.max_queue_size = int(
            cfg.get(
                "queue.buffering.max.messages",
                cfg.get("max_queue_size", max_queue_size),
            )
        )
        raw_max_lag = cfg.get("max_unconsumed_lag", max_unconsumed_lag)
        self.max_unconsumed_lag = (
            int(raw_max_lag) if raw_max_lag is not None else None
        )
        self.batch_size = int(
            cfg.get("batch.num.messages", cfg.get("batch_size", batch_size))
        )
        self.linger_ms = float(
            cfg.get(
                "linger.ms", cfg.get("batch_linger_ms", linger_ms)
            )
        )

        self._storage = storage or SQLiteBrokerStorage(
            self.db_path, default_partitions=self.num_partitions
        )

        self._queue: queue.Queue[
            Tuple[
                str,
                int,
                Optional[bytes],
                bytes,
                Optional[List[Tuple[str, bytes]]],
                int,
                Optional[Callable[[Optional[Any], Any], None]],
            ]
        ] = queue.Queue(maxsize=self.max_queue_size)

        self._callback_queue: queue.Queue[
            Tuple[
                Optional[Callable[[Optional[Any], Any], None]],
                Optional[Any],
                Optional[LightweightMessage],
            ]
        ] = queue.Queue()

        self._round_robin_counters: Dict[str, int] = collections.defaultdict(
            int
        )
        self._round_robin_lock = threading.Lock()

        self._unwritten_count: int = 0
        self._unwritten_lock = threading.Lock()
        self._unwritten_cond = threading.Condition(self._unwritten_lock)

        self._stop_event = threading.Event()
        self._writer_thread = threading.Thread(
            target=self._background_writer_loop,
            daemon=True,
            name="lightweight-broker-writer",
        )
        self._writer_thread.start()

    def _get_num_partitions(self, topic: str) -> int:
        return self._storage.get_topic_partitions(topic)

    def produce(
        self,
        topic: str,
        value: Union[bytes, bytearray, str],
        key: Optional[Union[bytes, bytearray, str]] = None,
        headers: Optional[List[Tuple[str, bytes]]] = None,
        partition: Optional[int] = None,
        on_delivery: Optional[Callable[[Optional[Any], Any], None]] = None,
        timestamp: Optional[Union[int, float]] = None,
        timestamp_ms: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        """
        Enqueues a message for asynchronous WAL persistence.
        Raises `BufferError` if the queue is full or unconsumed lag exceeds bounds.
        """
        if self._stop_event.is_set():
            raise RuntimeError("Producer has been stopped.")

        # 1 & 2. Backpressure checks: queue capacity and unconsumed lag threshold
        with self._unwritten_cond:
            if self._unwritten_count >= self.max_queue_size:
                raise BufferError(
                    f"Local broker queue is full ({self._unwritten_count}/{self.max_queue_size})."
                )
            if self.max_unconsumed_lag is not None:
                current_lag = (
                    self._storage.get_total_unconsumed_lag(topic=topic)
                    + self._unwritten_count
                )
                if current_lag >= self.max_unconsumed_lag:
                    raise BufferError(
                        f"Broker unconsumed lag exceeded limit ({current_lag}/{self.max_unconsumed_lag})."
                    )
            self._unwritten_count += 1

        # 3. Partition routing
        n_parts = self._get_num_partitions(topic)
        if partition is not None:
            target_partition = int(partition)
        elif key is not None:
            target_partition = compute_partition(key, n_parts) or 0
        else:
            with self._round_robin_lock:
                target_partition = self._round_robin_counters[topic] % n_parts
                self._round_robin_counters[topic] += 1

        # 4. Standardize value and key bytes
        val_bytes = (
            bytes(value)
            if isinstance(value, (bytes, bytearray))
            else str(value).encode("utf-8")
        )
        key_bytes = (
            bytes(key)
            if isinstance(key, (bytes, bytearray))
            else (key.encode("utf-8") if key is not None else None)
        )

        # 5. Timestamp resolution
        eff_ts = timestamp_ms if timestamp_ms is not None else timestamp
        if eff_ts is not None:
            # If timestamp is in seconds (float), convert to ms
            ts_val = float(eff_ts)
            ts_ms = (
                int(round(ts_val * 1000)) if ts_val < 1e11 else int(round(ts_val))
            )
        else:
            ts_ms = int(time.time() * 1000)

        item = (
            str(topic),
            target_partition,
            key_bytes,
            val_bytes,
            headers,
            ts_ms,
            on_delivery,
        )

        try:
            self._queue.put_nowait(item)
        except queue.Full:
            with self._unwritten_cond:
                self._unwritten_count -= 1
                self._unwritten_cond.notify_all()
            raise BufferError("Local broker queue is full.")

    def poll(self, timeout: float = 0.0) -> int:
        """
        Dispatches queued delivery callbacks.
        Returns the number of callbacks dispatched.
        """
        dispatched = 0
        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            try:
                cb, err, msg = self._callback_queue.get_nowait()
                dispatched += 1
                if cb is not None and callable(cb):
                    try:
                        cb(err, msg)
                    except Exception as exc:
                        logger.error("Error in on_delivery callback: %s", exc)
            except queue.Empty:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(remaining, 0.002))
        return dispatched

    def flush(self, timeout: Optional[float] = None) -> int:
        """
        Waits for all buffered messages to be committed to SQLite and all callbacks to be dispatched.
        Returns 0 on success, or the number of remaining messages if timed out.
        """
        deadline = (
            time.monotonic() + float(timeout) if timeout is not None else None
        )

        # 1. Wait for queue to be drained and pending writes to finish
        with self._unwritten_cond:
            while self._unwritten_count > 0:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return self._unwritten_count
                    self._unwritten_cond.wait(timeout=min(remaining, 0.005))
                else:
                    self._unwritten_cond.wait(timeout=0.005)

        # 2. Dispatch all pending callbacks
        while True:
            try:
                cb, err, msg = self._callback_queue.get_nowait()
                if cb is not None and callable(cb):
                    try:
                        cb(err, msg)
                    except Exception as exc:
                        logger.error(
                            "Error in on_delivery callback during flush: %s", exc
                        )
            except queue.Empty:
                break

        return 0

    def _background_writer_loop(self) -> None:
        """Continuously batches in-memory items and writes them to SQLite in WAL mode."""
        while not self._stop_event.is_set() or not self._queue.empty():
            batch: List[
                Tuple[
                    str,
                    int,
                    Optional[bytes],
                    bytes,
                    Optional[List[Tuple[str, bytes]]],
                    int,
                    Optional[Callable[[Optional[Any], Any], None]],
                ]
            ] = []

            try:
                first_item = self._queue.get(timeout=0.005)
                batch.append(first_item)
            except queue.Empty:
                continue

            # Accumulate up to batch_size or linger window
            linger_deadline = time.monotonic() + (self.linger_ms / 1000.0)
            while len(batch) < self.batch_size:
                try:
                    remaining_time = max(0.0, linger_deadline - time.monotonic())
                    item = self._queue.get(timeout=remaining_time)
                    batch.append(item)
                except queue.Empty:
                    break

            write_items = [
                (t, p, k, v, hdrs, ts_ms)
                for (t, p, k, v, hdrs, ts_ms, _cb) in batch
            ]
            callbacks = [cb for (_, _, _, _, _, _, cb) in batch]

            try:
                messages = self._storage.store_batch(write_items)
                for cb, msg in zip(callbacks, messages):
                    self._callback_queue.put((cb, None, msg))
            except Exception as exc:
                logger.error("Failed to commit batch to SQLite WAL: %s", exc)
                for cb in callbacks:
                    self._callback_queue.put((cb, exc, None))
            finally:
                with self._unwritten_cond:
                    self._unwritten_count -= len(batch)
                    self._unwritten_cond.notify_all()

    def __len__(self) -> int:
        with self._unwritten_lock:
            return self._unwritten_count

    def purge(self) -> None:
        """Discards all queued in-memory items and pending callbacks."""
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break
        while not self._callback_queue.empty():
            try:
                self._callback_queue.get_nowait()
            except queue.Empty:
                break
        with self._unwritten_cond:
            self._unwritten_count = 0
            self._unwritten_cond.notify_all()

    def close(self, timeout: Optional[float] = 10.0) -> None:
        """Flushes remaining messages and stops the background writer thread."""
        self.flush(timeout=timeout)
        self._stop_event.set()
        if self._writer_thread.is_alive():
            self._writer_thread.join(timeout=2.0)
        self._storage.close()


# ---------------------------------------------------------------------------
# Consumer Interface (LightweightConsumer)
# ---------------------------------------------------------------------------
class LightweightConsumer:
    """
    Consumer interface for reading partitioned topic logs.

    Features:
    - `subscribe(topics, on_assign=None, on_revoke=None, on_lost=None)`
    - `poll(timeout=0.1)` and `consume(num_messages, timeout=0.1)`
    - `pause(partitions)` & `resume(partitions)`:
      Crucially, `poll(0)` NEVER dequeues messages from paused partitions!
    - Explicit offset management: `commit()`, `committed()`, `seek()`, `position()`
    - Watermark & lag inspection: `get_watermark_offsets(partition)`
    """

    def __init__(
        self,
        config: Optional[Union[Dict[str, Any], Mapping[str, Any]]] = None,
        db_path: Optional[str] = None,
        group_id: str = "default-group",
        auto_offset_reset: str = "earliest",
        enable_auto_commit: bool = False,
        num_partitions: int = DEFAULT_NUM_PARTITIONS,
        storage: Optional[SQLiteBrokerStorage] = None,
    ) -> None:
        cfg = dict(config or {})

        resolved_db = (
            cfg.get("broker.db.path")
            or cfg.get("state.db.path")
            or db_path
            or resolve_default_broker_db_path()
        )
        self.db_path = str(resolved_db)
        self.group_id = str(cfg.get("group.id", group_id))
        self.auto_offset_reset = str(
            cfg.get("auto.offset.reset", auto_offset_reset)
        ).lower()
        self.enable_auto_commit = bool(
            cfg.get("enable.auto.commit", enable_auto_commit)
        )
        self.num_partitions = int(
            cfg.get(
                "num_partitions", cfg.get("broker_partitions", num_partitions)
            )
        )

        self._storage = storage or SQLiteBrokerStorage(
            self.db_path, default_partitions=self.num_partitions
        )

        self._assigned: Set[Tuple[str, int]] = set()
        self._paused: Set[Tuple[str, int]] = set()
        self._positions: Dict[Tuple[str, int], int] = {}
        self._rr_index: int = 0
        self._subscribed_topics: List[str] = []

        self._on_assign: Optional[Callable[[Any, List[TopicPartition]], None]] = (
            None
        )
        self._on_revoke: Optional[Callable[[Any, List[TopicPartition]], None]] = (
            None
        )
        self._on_lost: Optional[Callable[[Any, List[TopicPartition]], None]] = None
        self._closed: bool = False

    def subscribe(
        self,
        topics: Sequence[str],
        on_assign: Optional[Callable[[Any, List[TopicPartition]], None]] = None,
        on_revoke: Optional[Callable[[Any, List[TopicPartition]], None]] = None,
        on_lost: Optional[Callable[[Any, List[TopicPartition]], None]] = None,
    ) -> None:
        """Subscribes to topics and initializes partition assignments & positions."""
        self._subscribed_topics = list(topics)
        self._on_assign = on_assign
        self._on_revoke = on_revoke
        self._on_lost = on_lost

        new_assignment: Set[Tuple[str, int]] = set()
        for topic in self._subscribed_topics:
            n_parts = self._storage.get_topic_partitions(topic)
            for p in range(n_parts):
                new_assignment.add((topic, p))

        self._assigned = new_assignment
        self._paused.clear()

        # Initialize current fetch positions
        for t, p in self._assigned:
            comm = self._storage.get_committed_offset(self.group_id, t, p)
            if comm is not None and comm >= 0:
                self._positions[(t, p)] = comm
            else:
                low, high = self._storage.get_watermark_offsets(t, p)
                if self.auto_offset_reset == "latest":
                    self._positions[(t, p)] = high
                else:
                    self._positions[(t, p)] = low

        # Trigger on_assign callback if provided
        if self._on_assign and callable(self._on_assign):
            assigned_tps = [
                TopicPartition(t, p) for t, p in sorted(self._assigned)
            ]
            self._on_assign(self, assigned_tps)

    def assign(self, partitions: Sequence[TopicPartition]) -> None:
        """Explicitly assigns a specific list of TopicPartition objects."""
        self._assigned = {
            (tp.topic, int(tp.partition)) for tp in partitions
        }
        self._paused.clear()
        for t, p in self._assigned:
            if (t, p) not in self._positions:
                comm = self._storage.get_committed_offset(self.group_id, t, p)
                if comm is not None and comm >= 0:
                    self._positions[(t, p)] = comm
                else:
                    low, high = self._storage.get_watermark_offsets(t, p)
                    self._positions[(t, p)] = (
                        high if self.auto_offset_reset == "latest" else low
                    )

    def assignment(self) -> List[TopicPartition]:
        """Returns currently assigned partitions as TopicPartition instances."""
        return [TopicPartition(t, p) for t, p in sorted(self._assigned)]

    def pause(self, partitions: Sequence[TopicPartition]) -> None:
        """
        Pauses fetching from specified partitions.
        `poll(0)` will NEVER dequeue messages from paused partitions.
        """
        for tp in partitions:
            self._paused.add((tp.topic, int(tp.partition)))

    def resume(self, partitions: Sequence[TopicPartition]) -> None:
        """Resumes fetching from specified partitions."""
        for tp in partitions:
            self._paused.discard((tp.topic, int(tp.partition)))

    def seek(self, partition: TopicPartition) -> None:
        """Sets the current fetch offset position for a partition."""
        t = partition.topic
        p = int(partition.partition)
        off = int(partition.offset)
        self._positions[(t, p)] = off

    def position(
        self, partitions: Sequence[TopicPartition]
    ) -> List[TopicPartition]:
        """Returns the current fetch offset position for each requested partition."""
        result: List[TopicPartition] = []
        for tp in partitions:
            pos = self._positions.get(
                (tp.topic, int(tp.partition)), OFFSET_INVALID
            )
            result.append(TopicPartition(tp.topic, tp.partition, offset=pos))
        return result

    def poll(self, timeout: float = 0.1) -> Optional[LightweightMessage]:
        """
        Polls for a single message from assigned, unpaused partitions.
        When all partitions are paused or no messages are available, returns None.
        """
        if self._closed or not self._assigned:
            return None

        deadline = time.monotonic() + max(0.0, float(timeout))

        while True:
            # Active (unpaused) partitions
            eligible = [
                tp for tp in sorted(self._assigned) if tp not in self._paused
            ]
            if not eligible:
                # All assigned partitions are paused or none assigned: do NOT dequeue any messages!
                if timeout > 0:
                    remaining = deadline - time.monotonic()
                    if remaining > 0:
                        time.sleep(min(remaining, 0.01))
                return None

            n = len(eligible)
            start_idx = self._rr_index % n

            for i in range(n):
                idx = (start_idx + i) % n
                topic, part = eligible[idx]
                curr_offset = self._positions.get((topic, part), 0)

                low, high = self._storage.get_watermark_offsets(topic, part)
                if (curr_offset > high or curr_offset < low) and high > low:
                    curr_offset = low if self.auto_offset_reset == "earliest" else high
                    self._positions[(topic, part)] = curr_offset
                elif high == 0 and curr_offset > 0:
                    curr_offset = 0
                    self._positions[(topic, part)] = 0

                msg = self._storage.get_message(topic, part, curr_offset)
                if msg is not None:
                    # Advance local fetch position
                    self._positions[(topic, part)] = msg.offset() + 1
                    self._rr_index = (idx + 1) % n

                    if self.enable_auto_commit:
                        self.commit(
                            [
                                TopicPartition(
                                    topic, part, offset=msg.offset() + 1
                                )
                            ],
                            asynchronous=True,
                        )
                    return msg

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(remaining, 0.005))

        return None

    def consume(
        self, num_messages: int = 1, timeout: float = 0.1
    ) -> List[LightweightMessage]:
        """Polls up to `num_messages` across assigned unpaused partitions within timeout."""
        items: List[LightweightMessage] = []
        deadline = time.monotonic() + max(0.0, float(timeout))

        while len(items) < num_messages:
            remaining = max(0.0, deadline - time.monotonic())
            msg = self.poll(timeout=remaining)
            if msg is not None:
                items.append(msg)
            else:
                if remaining <= 0 or not any(
                    tp not in self._paused for tp in self._assigned
                ):
                    break

        return items

    def commit(
        self,
        offsets: Optional[Sequence[TopicPartition]] = None,
        asynchronous: bool = False,
    ) -> List[TopicPartition]:
        """
        Commits offsets explicitly to SQLite storage.
        If `offsets` is None, commits the current fetch positions of all assigned partitions.
        """
        if offsets is not None:
            commit_targets = list(offsets)
        else:
            commit_targets = [
                TopicPartition(t, p, offset=self._positions.get((t, p), 0))
                for t, p in sorted(self._assigned)
            ]

        self._storage.commit_offsets(
            self.group_id, commit_targets, asynchronous=asynchronous
        )
        return commit_targets

    def committed(
        self, partitions: Sequence[TopicPartition], timeout: Optional[float] = None
    ) -> List[TopicPartition]:
        """Returns committed offsets for requested partitions, or OFFSET_INVALID if uncommitted."""
        result: List[TopicPartition] = []
        for tp in partitions:
            comm = self._storage.get_committed_offset(
                self.group_id, tp.topic, int(tp.partition)
            )
            offset = comm if comm is not None else OFFSET_INVALID
            result.append(TopicPartition(tp.topic, tp.partition, offset=offset))
        return result

    def get_watermark_offsets(
        self,
        partition: Union[TopicPartition, Tuple[str, int]],
        timeout: Optional[float] = None,
        cached: bool = False,
    ) -> Tuple[int, int]:
        """Returns (low_watermark, high_watermark) for a partition."""
        if hasattr(partition, "topic") and hasattr(partition, "partition"):
            t = str(partition.topic)
            p = int(partition.partition)
        else:
            t = str(partition[0])
            p = int(partition[1])
        return self._storage.get_watermark_offsets(t, p)

    def close(self) -> None:
        """Closes consumer, invokes on_revoke callback, and cleans up resources."""
        if self._closed:
            return
        if self._on_revoke and callable(self._on_revoke) and self._assigned:
            try:
                assigned_tps = [
                    TopicPartition(t, p) for t, p in sorted(self._assigned)
                ]
                self._on_revoke(self, assigned_tps)
            except Exception as exc:
                logger.warning("Error during on_revoke in close(): %s", exc)
        self._closed = True
        self._storage.close()


# ---------------------------------------------------------------------------
# Admin Client Interface (LightweightAdminClient)
# ---------------------------------------------------------------------------
class PartitionMetadata:
    def __init__(self, id: int, leader: int = 0) -> None:
        self.id = id
        self.leader = leader


class TopicMetadata:
    def __init__(self, topic: str, partitions: Dict[int, PartitionMetadata]) -> None:
        self.topic = topic
        self.partitions = partitions


class ClusterMetadata:
    def __init__(self, topics: Dict[str, TopicMetadata]) -> None:
        self.topics = topics


class AdminFuture:
    """Mock concurrent future returned by AdminClient operations."""

    def __init__(self, result_val: Any = None, exc: Optional[Exception] = None) -> None:
        self._result = result_val
        self._exc = exc

    def result(self, timeout: Optional[float] = None) -> Any:
        if self._exc is not None:
            raise self._exc
        return self._result


class GroupResult:
    def __init__(self, topic_partitions: List[TopicPartition]) -> None:
        self.topic_partitions = topic_partitions


class NewTopic:
    def __init__(
        self,
        topic: str,
        num_partitions: int = DEFAULT_NUM_PARTITIONS,
        replication_factor: int = 1,
        config: Optional[Dict[str, str]] = None,
    ) -> None:
        self.topic = topic
        self.num_partitions = num_partitions
        self.replication_factor = replication_factor
        self.config = config or {}


class ConfigResource:
    def __init__(
        self,
        resource_type: Any,
        name: str,
        set_config: Optional[Dict[str, str]] = None,
    ) -> None:
        self.resource_type = resource_type
        self.name = name
        self.set_config = set_config or {}


class ResourceType:
    TOPIC = 2
    BROKER = 4


class ConsumerGroupTopicPartitions:
    def __init__(
        self, group_id: str, topic_partitions: Optional[List[TopicPartition]] = None
    ) -> None:
        self.group_id = group_id
        self.topic_partitions = topic_partitions or []


class LightweightAdminClient:
    """
    Admin client interface for broker topic and partition management.
    Supports topic creation, topic listing, altering configs, and consumer group offset inspection.
    """

    def __init__(
        self,
        config: Optional[Union[Dict[str, Any], Mapping[str, Any]]] = None,
        db_path: Optional[str] = None,
        storage: Optional[SQLiteBrokerStorage] = None,
    ) -> None:
        cfg = dict(config or {})
        resolved_db = (
            cfg.get("broker.db.path")
            or cfg.get("state.db.path")
            or db_path
            or resolve_default_broker_db_path()
        )
        self._storage = storage or SQLiteBrokerStorage(str(resolved_db))

    def list_topics(self, timeout: Optional[float] = None) -> ClusterMetadata:
        """Returns metadata for all registered topics."""
        topics_dict = self._storage.list_topics()
        meta_dict: Dict[str, TopicMetadata] = {}
        for t, n_parts in topics_dict.items():
            parts = {p: PartitionMetadata(id=p) for p in range(n_parts)}
            meta_dict[t] = TopicMetadata(topic=t, partitions=parts)
        return ClusterMetadata(topics=meta_dict)

    def create_topics(
        self,
        new_topics: Sequence[NewTopic],
        operation_timeout: Optional[float] = None,
    ) -> Dict[str, AdminFuture]:
        """Creates topics in SQLite metadata and returns a map of {topic: Future}."""
        futures: Dict[str, AdminFuture] = {}
        current_topics = self._storage.list_topics()

        for nt in new_topics:
            t_name = nt.topic
            if t_name in current_topics:
                err = BrokerError(
                    BrokerError.TOPIC_ALREADY_EXISTS,
                    f"Topic '{t_name}' already exists.",
                )
                futures[t_name] = AdminFuture(exc=BrokerException(err))
            else:
                try:
                    self._storage.ensure_topic(
                        t_name,
                        num_partitions=nt.num_partitions,
                        config=nt.config,
                    )
                    futures[t_name] = AdminFuture(result_val=t_name)
                except Exception as exc:
                    futures[t_name] = AdminFuture(exc=exc)

        return futures

    def alter_configs(
        self, resources: Sequence[ConfigResource]
    ) -> Dict[ConfigResource, AdminFuture]:
        """Mock implementation of altering configs."""
        return {res: AdminFuture(result_val=None) for res in resources}

    def list_consumer_group_offsets(
        self, group_req: Sequence[ConsumerGroupTopicPartitions]
    ) -> Dict[str, AdminFuture]:
        """Inspects committed offsets for a consumer group."""
        futures: Dict[str, AdminFuture] = {}
        for req in group_req:
            group_id = req.group_id
            tps_with_offsets: List[TopicPartition] = []
            for tp in req.topic_partitions:
                comm = self._storage.get_committed_offset(
                    group_id, tp.topic, int(tp.partition)
                )
                tps_with_offsets.append(
                    TopicPartition(
                        tp.topic,
                        tp.partition,
                        offset=comm if comm is not None else OFFSET_INVALID,
                    )
                )
            futures[group_id] = AdminFuture(
                result_val=GroupResult(topic_partitions=tps_with_offsets)
            )
        return futures

    def close(self) -> None:
        self._storage.close()
