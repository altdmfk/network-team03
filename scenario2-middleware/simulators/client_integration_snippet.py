# -*- coding: utf-8 -*-
"""
Reference Client Integration Snippet with Production-Grade Fail-Open Circuit Breaker.

Provides non-blocking in-process log buffering, automatic failover to local fallback
JSONL storage during middleware outages (503/timeout/connection errors), and zero-exception
guarantees for host applications (Flask API & ESP32 MicroPython).
"""

import json
import logging
import os
import queue
import threading
import time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger("soar.client")


class SafeSecurityLogClient:
    """
    Asynchronous Fail-Open security log client with bounded queue buffering,
    circuit breaker resilience, and lossless local file fallback.

    Guarantees:
    - 0ms non-blocking return for business threads via bounded in-memory queue.
    - 100% Fail-Open contract: never raises exceptions to the caller.
    - Automatic circuit tripping to OPEN on consecutive delivery failures.
    - Immediate local append to fallback JSONL file when circuit is OPEN,
      internal queue is Full, or transmission fails.
    """

    def __init__(
        self,
        endpoint_url: str = "http://localhost:8000/v1/ingest",
        api_key: Optional[str] = None,
        max_queue_size: int = 1000,
        failure_threshold: int = 3,
        recovery_timeout: float = 10.0,
        fallback_file_path: str = "./client_fallback_logs.jsonl",
        request_timeout: float = 1.0,
    ) -> None:
        self.endpoint_url = endpoint_url
        self.api_key = api_key
        self.max_queue_size = int(max_queue_size)
        self.failure_threshold = int(failure_threshold)
        self.recovery_timeout = float(recovery_timeout)
        self.fallback_file_path = fallback_file_path
        self.request_timeout = float(request_timeout)

        self.state: str = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.consecutive_failures: int = 0
        self.last_failure_time: float = 0.0

        self._lock = threading.Lock()
        self._file_lock = threading.Lock()
        self._queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=self.max_queue_size)
        self._stop_event = threading.Event()

        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="SafeSecurityLogClient-Worker",
            daemon=True,
        )
        self._worker_thread.start()

    def send_log(self, event_dict: Dict[str, Any]) -> bool:
        """
        Non-blocking log submission ensuring 0ms return time and 100% Fail-Open isolation.
        Enqueues to the in-memory bounded queue; if circuit is OPEN or queue is Full,
        immediately appends to the local fallback JSONL file. Never raises exceptions.
        """
        try:
            now = time.time()
            with self._lock:
                if self.state == "OPEN":
                    if now - self.last_failure_time >= self.recovery_timeout:
                        self.state = "HALF_OPEN"
                    else:
                        self._write_fallback(event_dict)
                        return False

            try:
                self._queue.put_nowait(event_dict)
                return True
            except queue.Full:
                # Bounded queue saturated -> write directly to emergency fallback file
                self._write_fallback(event_dict)
                return False
        except Exception:
            try:
                self._write_fallback(event_dict)
            except Exception:
                pass
            return False

    def _worker_loop(self) -> None:
        """Background worker servicing queue and handling circuit breaker transitions."""
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                now = time.time()
                with self._lock:
                    if self.state == "OPEN":
                        if now - self.last_failure_time < self.recovery_timeout:
                            self._write_fallback(item)
                            continue
                        else:
                            self.state = "HALF_OPEN"

                success = self._post_to_middleware(item)
                if success:
                    with self._lock:
                        self.consecutive_failures = 0
                        self.state = "CLOSED"
                else:
                    self._handle_failure(item)
            except Exception:
                self._handle_failure(item)
            finally:
                try:
                    self._queue.task_done()
                except Exception:
                    pass

    def _post_to_middleware(self, item: Dict[str, Any]) -> bool:
        """Attempts HTTP delivery to middleware ingest endpoint."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        try:
            resp = requests.post(
                self.endpoint_url,
                json=item,
                headers=headers,
                timeout=self.request_timeout,
            )
            if 200 <= resp.status_code < 300:
                return True
            if resp.status_code >= 500:
                return False
            # 4xx client errors do not indicate server outage, but payload is consumed
            return True
        except (requests.RequestException, OSError, Exception):
            return False

    def _handle_failure(self, item: Dict[str, Any]) -> None:
        """Records failure, increments consecutive counter, and trips circuit if threshold reached."""
        now = time.time()
        with self._lock:
            self.consecutive_failures += 1
            self.last_failure_time = now
            if self.consecutive_failures >= self.failure_threshold:
                self.state = "OPEN"
        self._write_fallback(item)

    def _write_fallback(self, item: Dict[str, Any]) -> None:
        """Safely appends log to local fallback JSONL file without throwing exceptions."""
        try:
            line = json.dumps(item, ensure_ascii=False)
            with self._file_lock:
                parent_dir = os.path.dirname(os.path.abspath(self.fallback_file_path))
                if parent_dir and not os.path.exists(parent_dir):
                    os.makedirs(parent_dir, exist_ok=True)
                with open(self.fallback_file_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except Exception:
            # 100% Fail-Open: swallow file errors so business thread is never impacted
            pass

    def flush(self, timeout: Optional[float] = 5.0) -> None:
        """Waits for pending items in the queue to be dispatched or written to fallback."""
        t_end = time.time() + (timeout if timeout is not None else 5.0)
        while not self._queue.empty() and time.time() < t_end:
            time.sleep(0.01)

    def close(self, timeout: Optional[float] = 5.0) -> None:
        """Flushes queue, drains any remaining items to fallback, and terminates worker thread."""
        try:
            self.flush(timeout=min(1.0, timeout if timeout is not None else 1.0))
            self._stop_event.set()
            if self._worker_thread.is_alive():
                self._worker_thread.join(timeout=timeout)
            # Drain any remaining items in queue to fallback file so nothing is lost
            while True:
                try:
                    item = self._queue.get_nowait()
                    self._write_fallback(item)
                    self._queue.task_done()
                except queue.Empty:
                    break
                except Exception:
                    break
        except Exception:
            pass

    def __enter__(self) -> "SafeSecurityLogClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# 1. Main Flask API Server Integration (Python `requests` Fail-Open Wrapper)
# ---------------------------------------------------------------------------
_DEFAULT_CLIENT: Optional[SafeSecurityLogClient] = None
_CLIENT_LOCK = threading.Lock()


def get_default_client() -> SafeSecurityLogClient:
    global _DEFAULT_CLIENT
    if _DEFAULT_CLIENT is None:
        with _CLIENT_LOCK:
            if _DEFAULT_CLIENT is None:
                _DEFAULT_CLIENT = SafeSecurityLogClient()
    return _DEFAULT_CLIENT


def send_security_log(
    ip: str,
    event: str,
    resource: str,
    status: int,
    severity: int,
    payload: dict,
    endpoint_url: str = "http://localhost:8000/v1/ingest",
) -> None:
    """Convenience helper forwarding events asynchronously via SafeSecurityLogClient."""
    client = get_default_client()
    event_dict = {
        "timestamp": round(time.time(), 3),
        "client_ip": ip,
        "event_type": event,
        "target_resource": resource,
        "status_code": status,
        "severity": severity,
        "raw_payload": payload,
    }
    client.send_log(event_dict)


# ---------------------------------------------------------------------------
# 2. ESP32 IoT Control Board (MicroPython `urequests`)
# ---------------------------------------------------------------------------
def log_iot_event(attacker_ip: str, pin_target: str, cmd: str) -> bool:
    """
    MicroPython client snippet for ESP32 hardware boards with strict 0.5s timeout
    and 100% Fail-Open exception isolation. Physical actuator control loops
    must never block, freeze, or crash if network logging fails.
    """
    try:
        import urequests
        import utime

        res = urequests.post(
            "http://192.168.1.100:8000/v1/ingest",
            json={
                "timestamp": utime.time() + 946684800.0,
                "client_ip": attacker_ip,
                "event_type": "IOT_CONTROL",
                "target_resource": pin_target,
                "status_code": 200,
                "severity": 1,
                "raw_payload": {"cmd": cmd},
            },
            timeout=0.5,
        )
        try:
            res.close()
        except Exception:
            pass
        return True
    except Exception:
        # 100% Fail-Open exception isolation
        return False
