import asyncio
import json
import logging
import math
import threading
import time
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

import os
import sys

_sim_dir = os.path.dirname(os.path.abspath(__file__))
_mid_root = os.path.dirname(_sim_dir)
for _p in [os.path.join(_mid_root, "src"), _sim_dir, _mid_root]:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from config import (
    BROKER_PRIORITY_TOPIC,
    BROKER_TOPIC,
    EXPECTED_KILL_CHAIN,
    KILL_CHAIN_TARGET_IP,
    MOCK_GRAYLOG_HOST,
    MOCK_GRAYLOG_PORT,
)

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("soar.mock_graylog")

DEFAULT_GRAYLOG_MAX_INGEST_EPS: float = float(
    os.environ.get("GRAYLOG_MAX_INGEST_EPS", "650.0")
)
DEFAULT_GRAYLOG_QUEUE_CAPACITY: int = int(
    os.environ.get("GRAYLOG_QUEUE_CAPACITY", "1500")
)


class MockGraylogState:
    """Thread-safe state store for the Mock Graylog GELF HTTP Receiver."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.outage_mode: bool = False
        self.simulated_latency_sec: float = 0.0
        self.max_ingest_eps: float = DEFAULT_GRAYLOG_MAX_INGEST_EPS
        self.queue_capacity: int = DEFAULT_GRAYLOG_QUEUE_CAPACITY
        self.current_backlog: float = 0.0
        self.last_leak_time: float = time.time()
        self.dropped_overflow_events: int = 0
        self.total_received: int = 0
        self.unique_events: int = 0
        self.duplicate_events: int = 0
        self.total_gelf_received: int = 0
        self.total_batches_received: int = 0
        self.rejected_503_batches: int = 0
        self.duplicate_gelf_ignored: int = 0
        self.honeytoken_alerts_received: int = 0
        self.honeytoken_first_received_at: Optional[float] = None
        self.event_type_counts: Dict[str, int] = {}
        self.kill_chain_events: List[Dict[str, Any]] = []
        self._seen_event_ids: Set[str] = set()
        self.last_received_at: Optional[float] = None
        self.last_traceparent: Optional[str] = None
        self.standard_latencies: List[float] = []
        self.priority_latencies: List[float] = []

    def reset(self) -> None:
        with self._lock:
            self.outage_mode = False
            self.simulated_latency_sec = 0.0
            self.max_ingest_eps = DEFAULT_GRAYLOG_MAX_INGEST_EPS
            self.queue_capacity = DEFAULT_GRAYLOG_QUEUE_CAPACITY
            self.current_backlog = 0.0
            self.last_leak_time = time.time()
            self.dropped_overflow_events = 0
            self.total_received = 0
            self.unique_events = 0
            self.duplicate_events = 0
            self.total_gelf_received = 0
            self.total_batches_received = 0
            self.rejected_503_batches = 0
            self.duplicate_gelf_ignored = 0
            self.honeytoken_alerts_received = 0
            self.honeytoken_first_received_at = None
            self.event_type_counts.clear()
            self.kill_chain_events.clear()
            self._seen_event_ids.clear()
            self.last_received_at = None
            self.last_traceparent = None
            self.standard_latencies.clear()
            self.priority_latencies.clear()

    def _leak_locked(self, now: float) -> None:
        """Drains current backlog continuously based on elapsed time and max_ingest_eps."""
        if self.max_ingest_eps > 0 and self.current_backlog > 0:
            elapsed = max(0.0, now - self.last_leak_time)
            drained = elapsed * self.max_ingest_eps
            self.current_backlog = max(0.0, self.current_backlog - drained)
        self.last_leak_time = now

    def get_current_backlog(self) -> float:
        with self._lock:
            self._leak_locked(time.time())
            return self.current_backlog

    def check_and_enqueue(self, incoming_events: int) -> bool:
        """
        Simulates OpenSearch / Netty write queue saturation (Bounded Queue & EPS Cap).
        If (current_backlog + incoming_events) exceeds queue_capacity, rejects the batch,
        increments dropped_overflow_events and rejected_503_batches, and returns False.
        Otherwise adds incoming_events to backlog and returns True.
        """
        with self._lock:
            now = time.time()
            self._leak_locked(now)

            if self.queue_capacity > 0:
                if self.current_backlog + incoming_events > self.queue_capacity:
                    self.dropped_overflow_events += incoming_events
                    self.rejected_503_batches += 1
                    return False

            self.current_backlog += incoming_events
            return True

    def set_outage(self, enabled: bool) -> bool:
        with self._lock:
            self.outage_mode = enabled
            return self.outage_mode

    def toggle_outage(self) -> bool:
        with self._lock:
            self.outage_mode = not self.outage_mode
            return self.outage_mode

    def record_503_rejection(self) -> int:
        with self._lock:
            self.rejected_503_batches += 1
            return self.rejected_503_batches

    def ingest_gelf_records(self, records: List[Dict[str, Any]]) -> int:
        with self._lock:
            self.total_batches_received += 1
            self.last_received_at = time.time()

            for item in records:
                self.total_received += 1
                raw_event_id = item.get("_event_id")
                is_duplicate = False
                if raw_event_id is not None and str(raw_event_id).strip():
                    event_id = str(raw_event_id).strip()
                    topic = str(item.get("_broker_topic") or "").strip()
                    dedup_key = f"{topic}:{event_id}" if topic else event_id
                    if dedup_key in self._seen_event_ids:
                        is_duplicate = True
                        self.duplicate_events += 1
                        self.duplicate_gelf_ignored += 1
                    else:
                        self._seen_event_ids.add(dedup_key)

                if is_duplicate:
                    # Note: Commercial Graylog 6.1 does not deduplicate by _event_id natively.
                    # Mock Graylog tracks deduplication metrics while dropping duplicates for
                    # test and demo accounting consistency.
                    continue

                self.unique_events += 1
                self.total_gelf_received += 1
                event_type = str(item.get("_event_type", "UNKNOWN"))
                self.event_type_counts[event_type] = (
                    self.event_type_counts.get(event_type, 0) + 1
                )

                event_ts = float(item.get("timestamp", 0.0))
                now_ts = time.time()
                latency_sec = max(0.0, round(now_ts - event_ts, 4)) if event_ts > 0 else 0.0

                is_priority = (
                    item.get("_honeytoken_alert") is True
                    or str(item.get("_broker_topic") or "") == BROKER_PRIORITY_TOPIC
                    or event_type == "HONEYTOKEN_ACCESS"
                )
                if is_priority:
                    self.priority_latencies.append(latency_sec)
                else:
                    self.standard_latencies.append(latency_sec)

                if item.get("_honeytoken_alert") is True:
                    self.honeytoken_alerts_received += 1
                    if self.honeytoken_first_received_at is None:
                        self.honeytoken_first_received_at = time.time()
                    logger.warning(
                        "[SIEM ALERT] Honeytoken access received by Graylog: %s",
                        item.get("short_message"),
                    )

                if str(item.get("_client_ip")) == KILL_CHAIN_TARGET_IP:
                    b_topic = str(item.get("_broker_topic") or BROKER_TOPIC)
                    b_part = item.get("_broker_partition")
                    b_off = item.get("_broker_offset")
                    step_entry = {
                        "arrival_index": len(self.kill_chain_events) + 1,
                        "event_type": event_type,
                        "timestamp": float(item.get("timestamp", 0.0)),
                        "short_message": item.get("short_message", ""),
                        "broker_topic": b_topic,
                        "broker_partition": b_part,
                        "broker_offset": b_off,
                    }
                    self.kill_chain_events.append(step_entry)
                    logger.info(
                        "[KILL-CHAIN %s] Step #%d arrived: %s (ts=%.3f, topic=%s, partition=%s, offset=%s)",
                        KILL_CHAIN_TARGET_IP,
                        step_entry["arrival_index"],
                        event_type,
                        step_entry["timestamp"],
                        step_entry["broker_topic"],
                        step_entry["broker_partition"],
                        step_entry["broker_offset"],
                    )

            return len(records)

    def get_verification_report(self) -> Dict[str, Any]:
        with self._lock:
            observed_types = [e["event_type"] for e in self.kill_chain_events]
            timestamps = [e["timestamp"] for e in self.kill_chain_events]
            partitions = {
                e.get("broker_partition")
                for e in self.kill_chain_events
                if e.get("broker_partition") is not None
            }

            global_sequence_matches = observed_types[:3] == EXPECTED_KILL_CHAIN
            global_timestamps_monotonic = all(
                timestamps[i] <= timestamps[i + 1]
                for i in range(len(timestamps) - 1)
            )

            per_lane_events: Dict[str, List[Dict[str, Any]]] = {}
            for e in self.kill_chain_events:
                t = str(e.get("broker_topic") or BROKER_TOPIC)
                per_lane_events.setdefault(t, []).append(e)

            lanes_report: Dict[str, Any] = {}
            all_lanes_monotonic = True
            all_lanes_same_partition = True

            for topic_name, lane_evts in per_lane_events.items():
                lane_types = [e["event_type"] for e in lane_evts]
                lane_timestamps = [e["timestamp"] for e in lane_evts]
                lane_monotonic = all(
                    lane_timestamps[i] <= lane_timestamps[i + 1]
                    for i in range(len(lane_timestamps) - 1)
                )
                lane_partitions = {
                    e.get("broker_partition")
                    for e in lane_evts
                    if e.get("broker_partition") is not None
                }
                lane_same_partition = len(lane_partitions) <= 1

                if not lane_monotonic:
                    all_lanes_monotonic = False
                if not lane_same_partition:
                    all_lanes_same_partition = False

                lanes_report[topic_name] = {
                    "count": len(lane_evts),
                    "observed_sequence": lane_types,
                    "timestamps_monotonic": lane_monotonic,
                    "same_partition_verified": lane_same_partition,
                    "partitions": list(lane_partitions),
                }

            per_lane_ordering_verified = (
                all_lanes_monotonic and bool(self.kill_chain_events)
            )

            # If events arrived in a single lane, strict chronological order is exact global sequence match.
            # If events arrived across multiple lanes, each lane preserves strict ordering while cross-lane is best effort.
            if len(per_lane_events) > 1:
                strict_chronological_order_verified = per_lane_ordering_verified
                same_partition = all_lanes_same_partition
            else:
                strict_chronological_order_verified = bool(
                    global_sequence_matches and global_timestamps_monotonic
                )
                same_partition = len(partitions) == 1 if self.kill_chain_events else False

            self._leak_locked(time.time())
            return {
                "outage_mode": self.outage_mode,
                "simulated_latency_sec": self.simulated_latency_sec,
                "max_ingest_eps": self.max_ingest_eps,
                "queue_capacity": self.queue_capacity,
                "current_backlog": round(self.current_backlog, 2),
                "dropped_overflow_events": self.dropped_overflow_events,
                "total_received": self.total_received,
                "unique_events": self.unique_events,
                "duplicate_events": self.duplicate_events,
                "total_gelf_received": self.total_gelf_received,
                "total_batches_received": self.total_batches_received,
                "rejected_503_batches": self.rejected_503_batches,
                "duplicate_gelf_ignored": self.duplicate_gelf_ignored,
                "honeytoken_alerts_received": self.honeytoken_alerts_received,
                "honeytoken_first_received_at": self.honeytoken_first_received_at,
                "event_type_counts": dict(self.event_type_counts),
                "kill_chain_verification": {
                    "attacker_ip": KILL_CHAIN_TARGET_IP,
                    "expected_sequence": EXPECTED_KILL_CHAIN,
                    "observed_sequence": observed_types,
                    "strict_chronological_order_verified": bool(
                        strict_chronological_order_verified
                    ),
                    "per_lane_ordering_verified": bool(per_lane_ordering_verified),
                    "cross_lane_ordering": "best effort",
                    "same_partition_verified": same_partition,
                    "lanes": lanes_report,
                    "events": list(self.kill_chain_events),
                },
                "last_traceparent": self.last_traceparent,
                "latency_telemetry": {
                    "standard_lane": self._calculate_latency_stats(self.standard_latencies),
                    "priority_lane": self._calculate_latency_stats(self.priority_latencies),
                },
            }

    @staticmethod
    def _calculate_latency_stats(latencies: List[float]) -> Dict[str, Any]:
        """Calculates count, min, avg, p95, p99, and max latency statistics in seconds."""
        if not latencies:
            return {
                "count": 0,
                "min_sec": 0.0,
                "avg_sec": 0.0,
                "p95_sec": 0.0,
                "p99_sec": 0.0,
                "max_sec": 0.0,
            }
        arr = sorted(latencies)
        n = len(arr)

        def percentile(p: float) -> float:
            k = (n - 1) * p
            f = math.floor(k)
            c = math.ceil(k)
            if f == c:
                return arr[int(k)]
            return arr[int(f)] * (c - k) + arr[int(c)] * (k - f)

        return {
            "count": n,
            "min_sec": round(arr[0], 3),
            "avg_sec": round(sum(arr) / n, 3),
            "p95_sec": round(percentile(0.95), 3),
            "p99_sec": round(percentile(0.99), 3),
            "max_sec": round(arr[-1], 3),
        }


graylog_state = MockGraylogState()


async def _index_to_opensearch(records: List[Dict[str, Any]]) -> None:
    """Indexes accepted GELF records into OpenSearch for benchmark ground-truth verification."""
    if not records:
        return
    lines = []
    for r in records:
        doc = {
            "source": r.get("host") or r.get("source", "mock-graylog"),
            "message": r.get("short_message") or r.get("message", ""),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S.000", time.gmtime(r.get("timestamp", time.time()))),
        }
        for k, v in r.items():
            if k.startswith("_"):
                clean_k = k[1:]
                doc[clean_k] = v
            elif k not in doc:
                doc[k] = v
        lines.append(json.dumps({"index": {"_index": "graylog_deflector"}}))
        lines.append(json.dumps(doc))
    payload = "\n".join(lines) + "\n"
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", "-i", "gl-opensearch", "curl", "-s", "-X", "POST",
            "http://localhost:9200/_bulk", "-H", "Content-Type: application/x-ndjson",
            "--data-binary", "@-",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate(input=payload.encode("utf-8"))
    except Exception:
        pass


app = FastAPI(
    title="Mock Graylog GELF 1.1 HTTP Server",
    description=(
        "Simulates Graylog's HTTP GELF Input (port 12201), verifies per-IP Kill-Chain "
        "ordering and Honeytoken alerts, and supports on-demand HTTP 503 outage simulation."
    ),
    version="1.0.0",
)


@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check() -> Dict[str, Any]:
    return {
        "status": (
            "degraded_outage_simulation" if graylog_state.outage_mode else "healthy"
        ),
        "outage_mode": graylog_state.outage_mode,
        "total_gelf_received": graylog_state.total_gelf_received,
    }


@app.post("/gelf", status_code=status.HTTP_202_ACCEPTED)
async def receive_gelf(request: Request) -> JSONResponse:
    """
    Standard Graylog HTTP GELF endpoint (`POST /gelf`).
    Supports both single JSON GELF 1.1 messages and newline-delimited (NDJSON) GELF batches.
    Returns HTTP 503 when simulated downtime is active.
    """
    if graylog_state.outage_mode:
        rejected_count = graylog_state.record_503_rejection()
        logger.warning(
            "[OUTAGE SIMULATION ACTIVE] Rejecting GELF batch with HTTP 503 (rejected_batches=%d)",
            rejected_count,
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "Graylog Server Overloaded / Simulated Outage",
                "rejected_503_batches": rejected_count,
            },
        )

    if graylog_state.simulated_latency_sec > 0:
        await asyncio.sleep(graylog_state.simulated_latency_sec)

    tp = request.headers.get("traceparent")
    if tp:
        graylog_state.last_traceparent = tp

    raw_body = (await request.body()).decode("utf-8").strip()
    if not raw_body:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty GELF payload.",
        )

    parsed_records: List[Dict[str, Any]] = []
    for line in raw_body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid GELF JSON line: {exc}",
            ) from exc

        if record.get("version") != "1.1" or "short_message" not in record:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Payload violates GELF 1.1 specification (missing 'version': '1.1' or 'short_message').",
            )
        parsed_records.append(record)

    # Replicate commercial Graylog 6.1 GELF HTTP verified behavior:
    # Netty Jackson stream parser only deserializes the first single JSON object;
    # any subsequent records in an NDJSON batch are silently discarded.
    if len(parsed_records) > 1:
        dropped_in_batch = len(parsed_records) - 1
        logger.warning(
            "[GELF HTTP SPEC PARITY] NDJSON batch received with %d items. "
            "Graylog GELF HTTP parser processes only 1st item; dropping %d items.",
            len(parsed_records),
            dropped_in_batch,
        )
        parsed_records = [parsed_records[0]]

    incoming_events = len(parsed_records)
    if incoming_events == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty GELF payload.",
        )

    # Check simulated SIEM / OpenSearch ingestion queue saturation
    if not graylog_state.check_and_enqueue(incoming_events):
        logger.warning(
            "[SIEM QUEUE SATURATION] OpenSearch write queue full (backlog: %.1f, incoming: %d > capacity: %d). "
            "Rejecting %d events with HTTP 503 (EsRejectedExecutionException / Journal Queue Full)",
            graylog_state.get_current_backlog(),
            incoming_events,
            graylog_state.queue_capacity,
            incoming_events,
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "OpenSearch EsRejectedExecutionException / Journal Queue Full",
                "queue_capacity": graylog_state.queue_capacity,
                "current_backlog": round(graylog_state.get_current_backlog(), 1),
                "dropped_overflow_events": graylog_state.dropped_overflow_events,
                "rejected_503_batches": graylog_state.rejected_503_batches,
            },
        )

    accepted = graylog_state.ingest_gelf_records(parsed_records)
    asyncio.create_task(_index_to_opensearch(parsed_records))
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={"status": "accepted", "received": accepted},
    )


@app.get("/capacity", status_code=status.HTTP_200_OK)
async def get_capacity() -> Dict[str, Any]:
    """Returns current SIEM queue capacity and drain rate configuration."""
    with graylog_state._lock:
        graylog_state._leak_locked(time.time())
        return {
            "max_ingest_eps": graylog_state.max_ingest_eps,
            "queue_capacity": graylog_state.queue_capacity,
            "current_backlog": round(graylog_state.current_backlog, 2),
            "dropped_overflow_events": graylog_state.dropped_overflow_events,
        }


@app.post("/capacity", status_code=status.HTTP_200_OK)
async def configure_capacity(
    eps: Optional[float] = None,
    capacity: Optional[int] = None,
    request: Request = None,
) -> Dict[str, Any]:
    """Configures simulated SIEM indexing EPS cap and burst queue capacity."""
    if request is not None:
        try:
            body = await request.json()
            if isinstance(body, dict):
                if "eps" in body:
                    eps = float(body["eps"])
                elif "max_ingest_eps" in body:
                    eps = float(body["max_ingest_eps"])
                if "capacity" in body:
                    capacity = int(body["capacity"])
                elif "queue_capacity" in body:
                    capacity = int(body["queue_capacity"])
        except Exception:
            pass

    with graylog_state._lock:
        if eps is not None:
            graylog_state.max_ingest_eps = max(0.0, float(eps))
        if capacity is not None:
            graylog_state.queue_capacity = max(0, int(capacity))
        graylog_state._leak_locked(time.time())
        logger.info(
            "Mock Graylog capacity updated -> max_ingest_eps=%.1f, queue_capacity=%d",
            graylog_state.max_ingest_eps,
            graylog_state.queue_capacity,
        )
        return {
            "max_ingest_eps": graylog_state.max_ingest_eps,
            "queue_capacity": graylog_state.queue_capacity,
            "current_backlog": round(graylog_state.current_backlog, 2),
            "dropped_overflow_events": graylog_state.dropped_overflow_events,
        }


@app.post("/capacity/{eps}/{capacity}", status_code=status.HTTP_200_OK)
async def configure_capacity_path(eps: float, capacity: int) -> Dict[str, Any]:
    return await configure_capacity(eps=eps, capacity=capacity)


@app.post("/toggle-outage", status_code=status.HTTP_200_OK)
async def toggle_outage() -> Dict[str, Any]:
    """Toggles simulated HTTP 503 downtime on or off."""
    active = graylog_state.toggle_outage()
    logger.warning("Mock Graylog outage mode toggled -> outage_mode=%s", active)
    return {"outage_mode": active}


@app.post("/outage/{mode}", status_code=status.HTTP_200_OK)
async def set_outage_mode(mode: str) -> Dict[str, Any]:
    """Explicitly enables (`on`/`true`) or disables (`off`/`false`) HTTP 503 outage simulation."""
    normalized = mode.strip().lower()
    if normalized in ("on", "true", "1", "enable"):
        active = graylog_state.set_outage(True)
    elif normalized in ("off", "false", "0", "disable"):
        active = graylog_state.set_outage(False)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mode must be 'on' or 'off'.",
        )
    logger.warning("Mock Graylog outage mode explicitly set -> outage_mode=%s", active)
    return {"outage_mode": active}


@app.get("/status", status_code=status.HTTP_200_OK)
async def get_status() -> Dict[str, Any]:
    """Returns real-time GELF reception counters and Kill-Chain ordering verification."""
    return graylog_state.get_verification_report()


@app.get("/stats", status_code=status.HTTP_200_OK)
async def get_stats() -> Dict[str, Any]:
    """
    Returns separate total, unique, duplicate event metrics, and SIEM capacity telemetry.
    Clarifies that commercial Graylog 6.1 does not natively deduplicate by _event_id,
    while Mock Graylog tracks these metrics for middleware idempotency verification.
    """
    with graylog_state._lock:
        graylog_state._leak_locked(time.time())
        return {
            "total_received": graylog_state.total_received,
            "unique_events": graylog_state.unique_events,
            "duplicate_events": graylog_state.duplicate_events,
            "total_batches_received": graylog_state.total_batches_received,
            "rejected_503_batches": graylog_state.rejected_503_batches,
            "dropped_overflow_events": graylog_state.dropped_overflow_events,
            "max_ingest_eps": graylog_state.max_ingest_eps,
            "queue_capacity": graylog_state.queue_capacity,
            "current_backlog": round(graylog_state.current_backlog, 2),
            "simulated_latency_sec": graylog_state.simulated_latency_sec,
            "honeytoken_alerts_received": graylog_state.honeytoken_alerts_received,
            "event_type_counts": dict(graylog_state.event_type_counts),
            "latency_telemetry": {
                "standard_lane": graylog_state._calculate_latency_stats(
                    graylog_state.standard_latencies
                ),
                "priority_lane": graylog_state._calculate_latency_stats(
                    graylog_state.priority_latencies
                ),
            },
            "deduplication_note": (
                "Commercial Graylog 6.1 does not deduplicate by _event_id natively. "
                "Mock Graylog tracks unique vs. duplicate events for middleware idempotency verification."
            ),
        }


@app.post("/latency/{seconds}", status_code=status.HTTP_200_OK)
async def set_simulated_latency(seconds: float) -> Dict[str, Any]:
    """Sets simulated downstream processing delay in seconds for backpressure testing."""
    if seconds < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Latency must be non-negative.",
        )
    with graylog_state._lock:
        graylog_state.simulated_latency_sec = float(seconds)
    logger.info(
        "Mock Graylog simulated latency set to %.3fs",
        graylog_state.simulated_latency_sec,
    )
    return {"simulated_latency_sec": graylog_state.simulated_latency_sec}


@app.post("/reset", status_code=status.HTTP_200_OK)
async def reset_state() -> Dict[str, Any]:
    """Resets counters and recorded Kill-Chain events for a fresh demo run."""
    graylog_state.reset()
    logger.info("Mock Graylog server state reset.")
    return {
        "status": "reset",
        "total_gelf_received": 0,
        "dropped_overflow_events": 0,
        "current_backlog": 0.0,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "mock_graylog_server:app",
        host=MOCK_GRAYLOG_HOST,
        port=MOCK_GRAYLOG_PORT,
        reload=False,
    )
