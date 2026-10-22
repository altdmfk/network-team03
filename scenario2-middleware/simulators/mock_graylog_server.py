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


class MockGraylogState:
    """Thread-safe state store for the Mock Graylog GELF HTTP Receiver."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.outage_mode: bool = False
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
                raw_event_id = item.get("_event_id")
                if raw_event_id is not None and str(raw_event_id).strip():
                    event_id = str(raw_event_id).strip()
                    topic = str(item.get("_broker_topic") or "").strip()
                    dedup_key = f"{topic}:{event_id}" if topic else event_id
                    if dedup_key in self._seen_event_ids:
                        self.duplicate_gelf_ignored += 1
                        continue
                    self._seen_event_ids.add(dedup_key)

                self.total_gelf_received += 1
                event_type = str(item.get("_event_type", "UNKNOWN"))
                self.event_type_counts[event_type] = (
                    self.event_type_counts.get(event_type, 0) + 1
                )

                # End-to-end latency tracking per lane
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

            # Evaluate ordering per lane
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

            return {
                "outage_mode": self.outage_mode,
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

    accepted = graylog_state.ingest_gelf_records(parsed_records)
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={"status": "accepted", "received": accepted},
    )


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


@app.post("/reset", status_code=status.HTTP_200_OK)
async def reset_state() -> Dict[str, Any]:
    """Resets counters and recorded Kill-Chain events for a fresh demo run."""
    graylog_state.reset()
    logger.info("Mock Graylog server state reset.")
    return {"status": "reset", "total_gelf_received": 0}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "mock_graylog_server:app",
        host=MOCK_GRAYLOG_HOST,
        port=MOCK_GRAYLOG_PORT,
        reload=False,
    )
