import logging
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Union

from config import METRICS_DB_PATH

logger = logging.getLogger("soar.metrics_store")


class SharedMetricsStore:
    """
    Unified thread-safe and cross-process metrics coordinator backed by SQLite WAL.
    Maintains atomic in-memory counters and pending delta buffers on the hot path,
    flushing accumulated deltas and 1-second throughput buckets to a persistent
    thread-local SQLite WAL connection to avoid event-loop blocking and connection
    thrashing during traffic spikes.
    """

    METRIC_KEYS = (
        "total_received",
        "total_broker_acked",
        "total_forwarded_to_graylog",
        "permanently_dropped_logs",
        "dlq_quarantined_logs",
        "dlq_replayed_logs",
        "poison_messages",
        "invariant_violations",
        "peak_queue_lag",
        "peak_inbound_eps",
        "peak_outbound_eps",
    )

    THROUGHPUT_RETENTION_SECONDS = 30
    SLIDING_WINDOW_SECONDS = 3

    def __init__(self, db_path: str = METRICS_DB_PATH) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._local = threading.local()
        self._connections: List[sqlite3.Connection] = []

        self._counters: Dict[str, int] = {key: 0 for key in self.METRIC_KEYS}
        self._pending_deltas: Dict[str, int] = {key: 0 for key in self.METRIC_KEYS}

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """
        Returns a persistent thread-local SQLite connection initialized once per thread
        with WAL mode and NORMAL synchronization.
        """
        conn: Optional[sqlite3.Connection] = getattr(self._local, "conn", None)
        if conn is not None:
            return conn

        parent_dir = os.path.dirname(os.path.abspath(self.db_path))
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        conn = sqlite3.connect(
            self.db_path,
            timeout=10.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")

        self._local.conn = conn
        with self._lock:
            self._connections.append(conn)
        return conn

    def _init_db(self) -> None:
        conn = self._get_connection()
        with self._lock:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pipeline_metrics (
                    metric_key TEXT PRIMARY KEY,
                    metric_value INTEGER NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS throughput_events (
                    bucket_sec INTEGER,
                    direction TEXT,
                    count INTEGER,
                    PRIMARY KEY (bucket_sec, direction)
                );
                """
            )
            now = time.time()
            for key in self.METRIC_KEYS:
                conn.execute(
                    """
                    INSERT INTO pipeline_metrics (metric_key, metric_value, updated_at)
                    VALUES (?, 0, ?)
                    ON CONFLICT(metric_key) DO NOTHING;
                    """,
                    (key, now),
                )
            cursor = conn.execute(
                "SELECT metric_key, metric_value FROM pipeline_metrics;"
            )
            rows = {k: int(v) for k, v in cursor.fetchall()}
            for key in self.METRIC_KEYS:
                self._counters[key] = rows.get(key, 0)

    def increment_received(self, count: int = 1, flush: bool = False) -> int:
        """
        Ultra-fast in-memory atomic update on the HTTP ingest hot path.
        Pending deltas are flushed in the background poller thread and before snapshot reads.
        """
        if count <= 0:
            with self._lock:
                return self._counters["total_received"]
        with self._lock:
            self._counters["total_received"] += count
            self._pending_deltas["total_received"] += count
            current = self._counters["total_received"]
        if flush:
            self.flush()
        return current

    def increment_broker_acked(self, count: int = 1, flush: bool = False) -> int:
        if count <= 0:
            with self._lock:
                return self._counters["total_broker_acked"]
        with self._lock:
            self._counters["total_broker_acked"] += count
            self._pending_deltas["total_broker_acked"] += count
            current = self._counters["total_broker_acked"]
        if flush:
            self.flush()
        return current

    def increment_forwarded(
        self,
        count: int = 1,
        flush: bool = True,
        priority_count: int = 0,
        standard_count: int = 0,
    ) -> int:
        total_inc = (
            (priority_count + standard_count)
            if (priority_count > 0 or standard_count > 0) and count == 1
            else count
        )
        if total_inc <= 0:
            with self._lock:
                return self._counters["total_forwarded_to_graylog"]
        with self._lock:
            self._counters["total_forwarded_to_graylog"] += total_inc
            self._pending_deltas["total_forwarded_to_graylog"] += total_inc
            eff_p = priority_count
            eff_s = (
                standard_count
                if (priority_count > 0 or standard_count > 0)
                else total_inc
            )
            if eff_p > 0:
                self._pending_deltas["outbound_priority"] = (
                    self._pending_deltas.get("outbound_priority", 0) + eff_p
                )
            if eff_s > 0:
                self._pending_deltas["outbound_standard"] = (
                    self._pending_deltas.get("outbound_standard", 0) + eff_s
                )
            current = self._counters["total_forwarded_to_graylog"]
        if flush:
            self.flush()
        return current

    def increment_permanently_dropped(
        self, count: int = 1, flush: bool = False
    ) -> int:
        """Increments producer-side permanent drops (delivery callback errors, BufferError exhaustion)."""
        if count <= 0:
            with self._lock:
                return self._counters["permanently_dropped_logs"]
        with self._lock:
            self._counters["permanently_dropped_logs"] += count
            self._pending_deltas["permanently_dropped_logs"] += count
            current = self._counters["permanently_dropped_logs"]
        if flush:
            self.flush()
        return current

    def increment_dlq_quarantined(self, count: int = 1, flush: bool = True) -> int:
        """Increments count of logs currently quarantined in the DLQ awaiting replay."""
        if count <= 0:
            with self._lock:
                return self._counters["dlq_quarantined_logs"]
        with self._lock:
            self._counters["dlq_quarantined_logs"] += count
            self._pending_deltas["dlq_quarantined_logs"] += count
            current = self._counters["dlq_quarantined_logs"]
        if flush:
            self.flush()
        return current

    def increment_dropped(self, count: int = 1, flush: bool = False) -> int:
        """Backward-compatible producer drop increment delegating to `increment_permanently_dropped`."""
        return self.increment_permanently_dropped(count=count, flush=flush)

    def increment_poison_messages(self, count: int = 1, flush: bool = True) -> int:
        """Increments count of malformed/poison messages quarantined to security-logs.poison."""
        if count <= 0:
            with self._lock:
                return self._counters["poison_messages"]
        with self._lock:
            self._counters["poison_messages"] += count
            self._pending_deltas["poison_messages"] += count
            current = self._counters["poison_messages"]
        if flush:
            self.flush()
        return current

    def increment_invariant_violations(
        self, count: int = 1, flush: bool = True
    ) -> int:
        if count <= 0:
            with self._lock:
                return self._counters["invariant_violations"]
        with self._lock:
            self._counters["invariant_violations"] += count
            self._pending_deltas["invariant_violations"] += count
            current = self._counters["invariant_violations"]
        if flush:
            self.flush()
        return current

    def update_peak_lag(self, current_lag: int) -> int:
        """
        Persists the high-water mark of `current_queue_lag` observed during a traffic
        spike into SQLite WAL via `MAX(metric_value, ?)`.
        """
        safe_lag = max(0, int(current_lag))
        now = time.time()
        with self._lock:
            if safe_lag > self._counters["peak_queue_lag"]:
                self._counters["peak_queue_lag"] = safe_lag
        try:
            conn = self._get_connection()
            conn.execute(
                """
                UPDATE pipeline_metrics
                SET metric_value = MAX(metric_value, ?), updated_at = ?
                WHERE metric_key = 'peak_queue_lag';
                """,
                (safe_lag, now),
            )
            cursor = conn.execute(
                "SELECT metric_value FROM pipeline_metrics WHERE metric_key = 'peak_queue_lag';"
            )
            row = cursor.fetchone()
            if row is not None:
                db_peak = max(safe_lag, int(row[0]))
                with self._lock:
                    self._counters["peak_queue_lag"] = max(
                        self._counters["peak_queue_lag"], db_peak
                    )
                    return self._counters["peak_queue_lag"]
        except sqlite3.Error as exc:
            logger.warning("SQLite update_peak_lag warning: %s", exc)

        with self._lock:
            return self._counters["peak_queue_lag"]

    def _execute_in_transaction(self, conn: sqlite3.Connection, statements: List[ Any ]) -> None:
        """Executes a batch of `(sql, params)` statements atomically inside `BEGIN IMMEDIATE ... COMMIT`."""
        conn.execute("BEGIN IMMEDIATE;")
        try:
            for sql, params in statements:
                conn.execute(sql, params)
            conn.execute("COMMIT;")
        except Exception:
            try:
                conn.execute("ROLLBACK;")
            except sqlite3.Error:
                pass
            raise

    def _record_invariant_violation_locked(
        self,
        conn: sqlite3.Connection,
        counter_name: str,
        current_value: int,
        decrement_by: int,
        resulting_value: int,
        now: float,
    ) -> None:
        logger.error(
            "Metrics ledger invariant violation on counter '%s': current_value=%d, "
            "decrement_by=%d, resulting_value=%d (< 0). Transaction rolled back.",
            counter_name,
            current_value,
            decrement_by,
            resulting_value,
        )
        self._execute_in_transaction(
            conn,
            [
                (
                    """
                    UPDATE pipeline_metrics
                    SET metric_value = metric_value + 1, updated_at = ?
                    WHERE metric_key = 'invariant_violations';
                    """,
                    (now,),
                ),
            ],
        )
        self._counters["invariant_violations"] += 1

    def decrement_counter(self, key: str, count: int = 1) -> int:
        """
        Atomically decrements `key` by `count` in SQLite.
        If the decrement would go below zero, rolls back the transaction, logs an ERROR
        with the counter name and values, and increments `invariant_violations`.
        """
        if key not in self.METRIC_KEYS:
            raise KeyError(f"Unknown metric key: {key}")
        if count <= 0:
            with self._lock:
                return self._counters[key]

        self.flush()
        now = time.time()
        conn = self._get_connection()
        with self._lock:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                cursor = conn.execute(
                    "SELECT metric_value FROM pipeline_metrics WHERE metric_key = ?;",
                    (key,),
                )
                row = cursor.fetchone()
                current_val = int(row[0]) if row is not None else self._counters[key]

                conn.execute(
                    """
                    UPDATE pipeline_metrics
                    SET metric_value = metric_value - ?, updated_at = ?
                    WHERE metric_key = ?;
                    """,
                    (count, now, key),
                )
                post_cursor = conn.execute(
                    "SELECT metric_value FROM pipeline_metrics WHERE metric_key = ?;",
                    (key,),
                )
                post_row = post_cursor.fetchone()
                new_val = (
                    int(post_row[0]) if post_row is not None else current_val - count
                )

                if new_val < 0:
                    conn.execute("ROLLBACK;")
                    self._record_invariant_violation_locked(
                        conn=conn,
                        counter_name=key,
                        current_value=current_val,
                        decrement_by=count,
                        resulting_value=new_val,
                        now=now,
                    )
                    return self._counters[key]

                conn.execute("COMMIT;")
                self._counters[key] = new_val
                return new_val
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except sqlite3.Error:
                    pass
                raise

    def reconcile_dlq_replay(
        self, replayed_count: int, increment_forwarded: bool = True
    ) -> Dict[str, Any]:
        """
        Atomically decrements `dlq_quarantined_logs` by `replayed_count` and
        increments `dlq_replayed_logs` by `replayed_count`. If `increment_forwarded`
        is True, also increments `total_forwarded_to_graylog`.
        Never touches `permanently_dropped_logs`.
        If decrementing `dlq_quarantined_logs` would go below zero, rolls back the
        transaction, logs an ERROR with the counter name and values, and increments
        `invariant_violations`.
        """
        if replayed_count <= 0:
            return self.read_snapshot()

        self.flush()
        now = time.time()
        bucket_sec = int(now)

        try:
            conn = self._get_connection()
            with self._lock:
                conn.execute("BEGIN IMMEDIATE;")
                try:
                    cursor = conn.execute(
                        "SELECT metric_value FROM pipeline_metrics WHERE metric_key = 'dlq_quarantined_logs';"
                    )
                    row = cursor.fetchone()
                    current_quarantined = (
                        int(row[0])
                        if row is not None
                        else int(self._counters["dlq_quarantined_logs"])
                    )

                    if increment_forwarded:
                        conn.execute(
                            """
                            UPDATE pipeline_metrics
                            SET metric_value = metric_value + ?, updated_at = ?
                            WHERE metric_key = 'total_forwarded_to_graylog';
                            """,
                            (replayed_count, now),
                        )
                    conn.execute(
                        """
                        UPDATE pipeline_metrics
                        SET metric_value = metric_value + ?, updated_at = ?
                        WHERE metric_key = 'dlq_replayed_logs';
                        """,
                        (replayed_count, now),
                    )
                    conn.execute(
                        """
                        UPDATE pipeline_metrics
                        SET metric_value = metric_value - ?, updated_at = ?
                        WHERE metric_key = 'dlq_quarantined_logs';
                        """,
                        (replayed_count, now),
                    )

                    post_cursor = conn.execute(
                        "SELECT metric_value FROM pipeline_metrics WHERE metric_key = 'dlq_quarantined_logs';"
                    )
                    post_row = post_cursor.fetchone()
                    new_quarantined = (
                        int(post_row[0])
                        if post_row is not None
                        else current_quarantined - replayed_count
                    )

                    if new_quarantined < 0:
                        conn.execute("ROLLBACK;")
                        self._record_invariant_violation_locked(
                            conn=conn,
                            counter_name="dlq_quarantined_logs",
                            current_value=current_quarantined,
                            decrement_by=replayed_count,
                            resulting_value=new_quarantined,
                            now=now,
                        )
                    else:
                        conn.execute(
                            """
                            INSERT INTO throughput_events (bucket_sec, direction, count)
                            VALUES (?, 'outbound', ?)
                            ON CONFLICT(bucket_sec, direction)
                            DO UPDATE SET count = count + excluded.count;
                            """,
                            (bucket_sec, replayed_count),
                        )
                        conn.execute(
                            """
                            UPDATE pipeline_metrics
                            SET metric_value = MAX(
                                metric_value,
                                COALESCE((SELECT MAX(count) FROM throughput_events WHERE direction = 'outbound'), 0)
                            ),
                            updated_at = ?
                            WHERE metric_key = 'peak_outbound_eps';
                            """,
                            (now,),
                        )
                        conn.execute(
                            "DELETE FROM throughput_events WHERE bucket_sec < ?;",
                            (bucket_sec - self.THROUGHPUT_RETENTION_SECONDS,),
                        )
                        conn.execute("COMMIT;")
                        self._counters["total_forwarded_to_graylog"] += replayed_count
                        self._counters["dlq_replayed_logs"] += replayed_count
                        self._counters["dlq_quarantined_logs"] = new_quarantined
                except Exception:
                    try:
                        conn.execute("ROLLBACK;")
                    except sqlite3.Error:
                        pass
                    raise
        except sqlite3.Error as exc:
            logger.warning("SQLite reconcile_dlq_replay warning: %s", exc)
            with self._lock:
                current_quarantined = self._counters["dlq_quarantined_logs"]
                new_quarantined = current_quarantined - replayed_count
                if new_quarantined < 0:
                    logger.error(
                        "Metrics ledger invariant violation on counter 'dlq_quarantined_logs': "
                        "current_value=%d, decrement_by=%d, resulting_value=%d (< 0). "
                        "In-memory update rolled back.",
                        current_quarantined,
                        replayed_count,
                        new_quarantined,
                    )
                    self._counters["invariant_violations"] += 1
                    self._pending_deltas["invariant_violations"] += 1
                else:
                    if increment_forwarded:
                        self._counters["total_forwarded_to_graylog"] += replayed_count
                        self._pending_deltas["total_forwarded_to_graylog"] += replayed_count
                    self._counters["dlq_replayed_logs"] += replayed_count
                    self._pending_deltas["dlq_replayed_logs"] += replayed_count
                    self._counters["dlq_quarantined_logs"] = new_quarantined
                    self._pending_deltas["dlq_quarantined_logs"] -= replayed_count

        return self.read_snapshot()

    def reset_all(self) -> None:
        """
        Resets all counters in `pipeline_metrics` to 0, clears `throughput_events`,
        and resets in-memory counters so demo runs start from a clean slate.
        """
        now = time.time()
        with self._lock:
            for key in self.METRIC_KEYS:
                self._counters[key] = 0
                self._pending_deltas[key] = 0
            try:
                conn = self._get_connection()
                self._execute_in_transaction(
                    conn,
                    [
                        (
                            "UPDATE pipeline_metrics SET metric_value = 0, updated_at = ?;",
                            (now,),
                        ),
                        ("DELETE FROM throughput_events;", ()),
                    ],
                )
            except sqlite3.Error as exc:
                logger.warning("SQLite reset_all warning: %s", exc)

    def flush(self) -> None:
        """
        Atomically drains accumulated in-memory deltas and writes them to SQLite
        using the persistent thread-local connection inside a single transaction.
        Also records `inbound` and `outbound` 1-second epoch buckets into
        `throughput_events` and prunes buckets older than 30 seconds.
        """
        with self._lock:
            deltas_to_flush = {
                k: v for k, v in self._pending_deltas.items() if v != 0
            }
            if not deltas_to_flush:
                return
            for k in deltas_to_flush:
                self._pending_deltas[k] = 0

        now = time.time()
        bucket_sec = int(now)
        try:
            conn = self._get_connection()
            statements: List[Any] = []
            for key, delta in deltas_to_flush.items():
                statements.append(
                    (
                        """
                        UPDATE pipeline_metrics
                        SET metric_value = metric_value + ?, updated_at = ?
                        WHERE metric_key = ?;
                        """,
                        (delta, now, key),
                    )
                )

            inbound_delta = deltas_to_flush.get("total_received", 0)
            if inbound_delta > 0:
                statements.append(
                    (
                        """
                        INSERT INTO throughput_events (bucket_sec, direction, count)
                        VALUES (?, 'inbound', ?)
                        ON CONFLICT(bucket_sec, direction)
                        DO UPDATE SET count = count + excluded.count;
                        """,
                        (bucket_sec, inbound_delta),
                    )
                )
                statements.append(
                    (
                        """
                        UPDATE pipeline_metrics
                        SET metric_value = MAX(
                            metric_value,
                            COALESCE((SELECT MAX(count) FROM throughput_events WHERE direction = 'inbound'), 0)
                        ),
                        updated_at = ?
                        WHERE metric_key = 'peak_inbound_eps';
                        """,
                        (now,),
                    )
                )

            outbound_delta = deltas_to_flush.get("total_forwarded_to_graylog", 0)
            p_outbound = deltas_to_flush.get("outbound_priority", 0)
            s_outbound = deltas_to_flush.get("outbound_standard", 0)
            if p_outbound == 0 and s_outbound == 0 and outbound_delta > 0:
                s_outbound = outbound_delta

            if outbound_delta > 0:
                statements.append(
                    (
                        """
                        INSERT INTO throughput_events (bucket_sec, direction, count)
                        VALUES (?, 'outbound', ?)
                        ON CONFLICT(bucket_sec, direction)
                        DO UPDATE SET count = count + excluded.count;
                        """,
                        (bucket_sec, outbound_delta),
                    )
                )
                statements.append(
                    (
                        """
                        UPDATE pipeline_metrics
                        SET metric_value = MAX(
                            metric_value,
                            COALESCE((SELECT MAX(count) FROM throughput_events WHERE direction = 'outbound'), 0)
                        ),
                        updated_at = ?
                        WHERE metric_key = 'peak_outbound_eps';
                        """,
                        (now,),
                    )
                )

            if p_outbound > 0:
                statements.append(
                    (
                        """
                        INSERT INTO throughput_events (bucket_sec, direction, count)
                        VALUES (?, 'outbound:priority', ?)
                        ON CONFLICT(bucket_sec, direction)
                        DO UPDATE SET count = count + excluded.count;
                        """,
                        (bucket_sec, p_outbound),
                    )
                )

            if s_outbound > 0:
                statements.append(
                    (
                        """
                        INSERT INTO throughput_events (bucket_sec, direction, count)
                        VALUES (?, 'outbound:standard', ?)
                        ON CONFLICT(bucket_sec, direction)
                        DO UPDATE SET count = count + excluded.count;
                        """,
                        (bucket_sec, s_outbound),
                    )
                )

            statements.append(
                (
                    "DELETE FROM throughput_events WHERE bucket_sec < ?;",
                    (bucket_sec - self.THROUGHPUT_RETENTION_SECONDS,),
                )
            )
            self._execute_in_transaction(conn, statements)
        except sqlite3.Error as exc:
            logger.warning("SQLite metrics flush warning: %s", exc)
            with self._lock:
                for key, delta in deltas_to_flush.items():
                    self._pending_deltas[key] += delta

    @classmethod
    def _compute_sliding_eps(
        cls, bucket_counts: Dict[int, int], now_sec: int
    ) -> float:
        """
        Computes average logs/sec over the most recent active 1-3 second window.
        """
        window_start = now_sec - cls.SLIDING_WINDOW_SECONDS
        completed_counts = [
            count
            for sec, count in bucket_counts.items()
            if window_start <= sec <= now_sec - 1 and count > 0
        ]
        current_count = bucket_counts.get(now_sec, 0)

        if completed_counts:
            completed_avg = sum(completed_counts) / len(completed_counts)
            if current_count > completed_avg:
                active = completed_counts + [current_count]
                return round(sum(active) / len(active), 2)
            return round(completed_avg, 2)

        if current_count > 0:
            return round(float(current_count), 2)

        return 0.0

    def read_snapshot(self) -> Dict[str, Union[int, float]]:
        """
        Flushes pending deltas to SQLite and returns an up-to-date snapshot
        combining cross-process SQLite values, peak queue lag, DLQ replay counts,
        and sliding-window EPS telemetry.
        """
        self.flush()
        now_sec = int(time.time())
        inbound_buckets: Dict[int, int] = {}
        outbound_buckets: Dict[int, int] = {}
        priority_outbound_buckets: Dict[int, int] = {}
        standard_outbound_buckets: Dict[int, int] = {}
        max_inbound_table = 0
        max_outbound_table = 0

        try:
            conn = self._get_connection()
            cursor = conn.execute(
                "SELECT metric_key, metric_value FROM pipeline_metrics;"
            )
            db_rows = {k: int(v) for k, v in cursor.fetchall()}

            tp_cursor = conn.execute(
                """
                SELECT bucket_sec, direction, count
                FROM throughput_events
                WHERE bucket_sec >= ?;
                """,
                (now_sec - self.THROUGHPUT_RETENTION_SECONDS,),
            )
            for b_sec, direction, count in tp_cursor.fetchall():
                sec_val = int(b_sec)
                cnt_val = int(count)
                if direction == "inbound":
                    inbound_buckets[sec_val] = cnt_val
                    if cnt_val > max_inbound_table:
                        max_inbound_table = cnt_val
                elif direction == "outbound":
                    outbound_buckets[sec_val] = cnt_val
                    if cnt_val > max_outbound_table:
                        max_outbound_table = cnt_val
                elif direction == "outbound:priority":
                    priority_outbound_buckets[sec_val] = cnt_val
                elif direction == "outbound:standard":
                    standard_outbound_buckets[sec_val] = cnt_val
        except sqlite3.Error as exc:
            logger.warning(
                "SQLite snapshot read fallback to in-memory counters: %s", exc
            )
            db_rows = {}

        with self._lock:
            snapshot: Dict[str, Union[int, float]] = {}
            for key in self.METRIC_KEYS:
                if key in db_rows:
                    merged = db_rows[key] + self._pending_deltas.get(key, 0)
                else:
                    merged = self._counters[key]
                self._counters[key] = merged
                snapshot[key] = merged

            snapshot["dropped_logs"] = int(
                snapshot["permanently_dropped_logs"]
            ) + int(snapshot["dlq_quarantined_logs"])

            peak_in = max(int(snapshot.get("peak_inbound_eps", 0)), max_inbound_table)
            peak_out = max(int(snapshot.get("peak_outbound_eps", 0)), max_outbound_table)
            self._counters["peak_inbound_eps"] = peak_in
            self._counters["peak_outbound_eps"] = peak_out

            snapshot["inbound_eps"] = self._compute_sliding_eps(
                inbound_buckets, now_sec
            )
            snapshot["peak_inbound_eps"] = float(peak_in)
            snapshot["outbound_eps"] = self._compute_sliding_eps(
                outbound_buckets, now_sec
            )
            snapshot["peak_outbound_eps"] = float(peak_out)
            snapshot["priority_outbound_eps"] = self._compute_sliding_eps(
                priority_outbound_buckets, now_sec
            )
            snapshot["standard_outbound_eps"] = self._compute_sliding_eps(
                standard_outbound_buckets, now_sec
            )
            return snapshot

    def close(self) -> None:
        """Flushes any remaining deltas and closes all thread-local SQLite connections."""
        self.flush()
        with self._lock:
            for conn in self._connections:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            self._connections.clear()
            self._local = threading.local()

    def __enter__(self) -> "SharedMetricsStore":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


WorkerMetricsUpdater = SharedMetricsStore
