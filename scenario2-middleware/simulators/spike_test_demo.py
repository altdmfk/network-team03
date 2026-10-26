import argparse
import asyncio
import sys
import time
from typing import Any, Dict, List, Optional

import httpx

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import os
_sim_dir = os.path.dirname(os.path.abspath(__file__))
_mid_root = os.path.dirname(_sim_dir)
for _p in [os.path.join(_mid_root, "src"), _sim_dir, _mid_root]:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from config import (
    HONEYTOKEN_LATENCY_BUDGET,
    INGESTOR_BASE_URL,
    BROKER_PRIORITY_TOPIC,
    KILL_CHAIN_TARGET_IP,
    MAX_LOGS_PER_SEC,
    MOCK_GRAYLOG_BASE_URL,
)

KILL_CHAIN_IP = KILL_CHAIN_TARGET_IP


def build_progress_bar(current: int, total: int, width: int = 24) -> str:
    if total <= 0:
        return "[" + ("-" * width) + "]"
    ratio = max(0.0, min(1.0, current / total))
    filled = int(round(ratio * width))
    return "[" + ("#" * filled) + ("-" * (width - filled)) + f"] {ratio * 100:5.1f}%"


async def inject_kill_chain_sequence(client: httpx.AsyncClient) -> int:
    """
    Scenario 4: Injects sequential Kill-Chain logs from attacker IP 10.0.0.99
    (PORT_SCAN -> BRUTE_FORCE -> IOT_CONTROL) with strictly increasing timestamps.
    """
    base_ts = round(time.time(), 3)
    kill_chain_steps = [
        {
            "timestamp": round(base_ts, 3),
            "client_ip": KILL_CHAIN_IP,
            "event_type": "PORT_SCAN",
            "target_resource": "/admin/ports/scan",
            "status_code": 403,
            "severity": 4,
            "raw_payload": {
                "step": 1,
                "tool": "nmap -sS -T4",
                "probed_ports": [22, 80, 443, 8000, 12201],
            },
        },
        {
            "timestamp": round(base_ts + 0.005, 3),
            "client_ip": KILL_CHAIN_IP,
            "event_type": "BRUTE_FORCE",
            "target_resource": "/api/v1/auth/login",
            "status_code": 200,
            "severity": 2,
            "raw_payload": {
                "step": 2,
                "tool": "hydra",
                "username": "operator_root",
                "result": "COMPROMISED_SESSION_TOKEN",
            },
        },
        {
            "timestamp": round(base_ts + 0.010, 3),
            "client_ip": KILL_CHAIN_IP,
            "event_type": "IOT_CONTROL",
            "target_resource": "/iot/esp32/relay/facility_gate_unlock",
            "status_code": 200,
            "severity": 1,
            "raw_payload": {
                "step": 3,
                "device_id": "esp32-gate-controller-01",
                "gpio_pin": 14,
                "command": "FORCE_OPEN",
            },
        },
    ]

    for step in kill_chain_steps:
        resp = await client.post(f"{INGESTOR_BASE_URL}/ingest", json=step)
        resp.raise_for_status()
    return len(kill_chain_steps)


async def inject_honeytoken_alert(client: httpx.AsyncClient) -> int:
    """
    Scenario 1: Injects a high-priority Honeytoken access event (`honeytoken_admin`).
    """
    honeytoken_event = {
        "timestamp": round(time.time(), 3),
        "client_ip": "172.16.42.108",
        "event_type": "HONEYTOKEN_ACCESS",
        "target_resource": "/api/v1/admin/honeytoken_admin/secrets",
        "status_code": 403,
        "severity": 1,
        "raw_payload": {
            "account": "honeytoken_admin",
            "api_key_id": "ak_deception_trap_9901",
            "action": "export_vault_keys",
        },
    }
    resp = await client.post(f"{INGESTOR_BASE_URL}/ingest", json=honeytoken_event)
    resp.raise_for_status()
    return 1


async def unleash_traffic_spike(
    client: httpx.AsyncClient, total_spike_logs: int = 5000, batch_chunk_size: int = 50
) -> int:
    """
    Scenarios 2 & 3: Blasts 5,000 logs (Nmap PORT_SCAN, Hydra BRUTE_FORCE, and
    403 IDOR_ATTEMPT / Leaked API Key calls) concurrently within 1-2 seconds.
    """
    attacker_pool = [f"192.168.10.{i}" for i in range(10, 90)]
    scenario_templates = [
        (
            "PORT_SCAN",
            "/api/v1/internal/debug",
            404,
            4,
            {"scanner": "nmap", "syn_flood": True},
        ),
        (
            "BRUTE_FORCE",
            "/api/v1/auth/token",
            401,
            3,
            {"tool": "hydra", "attempt": "ssh_dict"},
        ),
        (
            "IDOR_ATTEMPT",
            "/api/v1/users/1001/billing",
            403,
            2,
            {"api_key": "leaked_key_77a", "reason": "IDOR_FORBIDDEN"},
        ),
    ]

    batches: List[List[Dict[str, Any]]] = []
    now_base = time.time()
    created = 0

    while created < total_spike_logs:
        chunk_len = min(batch_chunk_size, total_spike_logs - created)
        chunk: List[Dict[str, Any]] = []
        for i in range(chunk_len):
            idx = created + i
            ev_type, resource, code, sev, raw = scenario_templates[
                idx % len(scenario_templates)
            ]
            chunk.append(
                {
                    "timestamp": round(now_base + (idx * 0.0001), 3),
                    "client_ip": attacker_pool[idx % len(attacker_pool)],
                    "event_type": ev_type,
                    "target_resource": resource,
                    "status_code": code,
                    "severity": sev,
                    "raw_payload": {**raw, "seq_id": idx + 1},
                }
            )
        batches.append(chunk)
        created += chunk_len

    semaphore = asyncio.Semaphore(32)

    async def send_chunk(chunk_payload: List[Dict[str, Any]]) -> int:
        async with semaphore:
            resp = await client.post(
                f"{INGESTOR_BASE_URL}/ingest/batch",
                json={"logs": chunk_payload},
            )
            resp.raise_for_status()
            return len(chunk_payload)

    results = await asyncio.gather(*(send_chunk(b) for b in batches))
    return sum(results)


def format_audit_invariant(
    total_sent: int,
    total_received: int,
    total_forwarded: int,
    permanently_dropped: int,
    dlq_quarantined: int,
    graylog_stored: int,
) -> str:
    return (
        f"Sent ({total_sent:,}) == Received ({total_received:,}) == "
        f"Forwarded ({total_forwarded:,}) + permanently_dropped ({permanently_dropped:,}) + "
        f"dlq_quarantined ({dlq_quarantined:,}) == Graylog Stored ({graylog_stored:,})"
    )


def verify_five_stage_audit_invariant(
    *,
    total_sent: int,
    total_received: int,
    total_forwarded: int,
    permanently_dropped: int,
    dlq_quarantined: int,
    graylog_stored: int,
    current_queue_lag: int = 0,
) -> str:
    """
    Verifies and prints the 5-stage end-to-end accounting invariant:
    `Sent == Received == Forwarded + permanently_dropped + dlq_quarantined == Graylog Stored`.
    """
    invariant_line = format_audit_invariant(
        total_sent=total_sent,
        total_received=total_received,
        total_forwarded=total_forwarded,
        permanently_dropped=permanently_dropped,
        dlq_quarantined=dlq_quarantined,
        graylog_stored=graylog_stored,
    )
    accounted_total = total_forwarded + permanently_dropped + dlq_quarantined
    assert (
        total_sent
        == total_received
        == (total_forwarded + permanently_dropped + dlq_quarantined)
        == graylog_stored
        and current_queue_lag == 0
    ), (
        f"Zero-Loss Assertion Failed! {invariant_line} "
        f"(accounted_total={accounted_total}, lag={current_queue_lag})"
    )
    return invariant_line


async def run_spike_verification(
    spike_count: int = 5000,
    simulate_outage: bool = False,
    timeout_seconds: int = 120,
    honeytoken_latency_budget: float = HONEYTOKEN_LATENCY_BUDGET,
) -> None:
    limits = httpx.Limits(max_keepalive_connections=40, max_connections=60)
    timeout = httpx.Timeout(15.0)

    async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
        print("=" * 112)
        print(
            " SOAR LIGHTWEIGHT WAL BROKER BUFFERING MIDDLEWARE - SCENARIO 2 MASSIVE LOG SPIKE & ZERO-LOSS VERIFICATION SUITE"
        )
        print("=" * 112)

        # 0. Reset Ingestor metrics & Mock Graylog state so counters and peak_queue_lag start at 0
        try:
            await client.post(f"{INGESTOR_BASE_URL}/metrics/reset")
        except Exception:
            pass

        mock_available = False
        try:
            r = await client.post(f"{MOCK_GRAYLOG_BASE_URL}/reset")
            mock_available = r.status_code == 200
        except Exception:
            mock_available = False

        # Capture baseline metrics (0 after reset, or fallback baseline if reset unavailable)
        baseline_resp = await client.get(f"{INGESTOR_BASE_URL}/metrics")
        baseline_resp.raise_for_status()
        baseline = baseline_resp.json()
        base_received = int(baseline.get("total_received", 0))
        base_forwarded = int(baseline.get("total_forwarded_to_graylog", 0))
        base_permanently_dropped = int(baseline.get("permanently_dropped_logs", 0))
        base_dlq_quarantined = int(baseline.get("dlq_quarantined_logs", 0))
        base_dropped = int(
            baseline.get(
                "dropped_logs", base_permanently_dropped + base_dlq_quarantined
            )
        )
        telemetry_block = baseline.get("broker_telemetry", {})
        base_broker_acked = int(
            telemetry_block.get("total_broker_acked", 0)
        )

        # 1. Inject Kill-Chain, Bulk-Scan Backlog, and Priority Honeytoken Alert
        print(
            f"[1/4] Injecting Kill-Chain Sequence for Attacker IP {KILL_CHAIN_IP} (PORT_SCAN -> BRUTE_FORCE -> IOT_CONTROL)..."
        )
        kc_sent = await inject_kill_chain_sequence(client)

        print(
            f"[2/4] Unleashing Bulk Scan Backlog Spike ({spike_count:,} logs via concurrent HTTP batches)..."
        )
        spike_start = time.perf_counter()
        spike_sent = await unleash_traffic_spike(client, total_spike_logs=spike_count)
        spike_elapsed = time.perf_counter() - spike_start
        print(
            f"      -> Injected {spike_sent:,} scan logs in {spike_elapsed:.2f}s (Backlog generated)."
        )

        print(
            "[3/4] Injecting High-Priority Honeytoken Alert behind the scan backlog (account='honeytoken_admin')..."
        )
        ht_send_time = time.perf_counter()
        ht_sent = await inject_honeytoken_alert(client)

        total_sent = kc_sent + ht_sent + spike_sent
        total_time = time.perf_counter() - spike_start
        ingestion_rate = total_sent / max(total_time, 0.001)
        print(
            f"      -> Blasted {total_sent:,} total logs in {total_time:.2f}s "
            f"(Burst Rate: {ingestion_rate:,.0f} logs/sec)\n"
        )

        # 2. Poll GET /metrics every 1s and print Live ASCII Dashboard
        print(
            "[4/4] Live Broker Queue Drain & Backpressure Throttling Monitor (Polling GET /metrics every 1.0s):"
        )
        print("-" * 112)
        print(
            f"{'Time':>5} | {'Sent':>7} | {'Ingested':>8} | "
            f"{'Broker Lag (Peak)':>18} | {'Outbound EPS (Cap)':>20} | "
            f"{'Graylog Stored':>14} | {'Dropped':>7} | {'Progress'}"
        )
        print("-" * 112)

        start_monitor = time.monotonic()
        outage_triggered = False
        outage_restored = False
        honeytoken_delivered_latency: Optional[float] = None

        total_received = 0
        total_forwarded = 0
        current_queue_lag = total_sent
        peak_lag = 0
        permanently_dropped = 0
        dlq_quarantined = 0
        dropped_logs = 0
        dlq_replayed = 0
        broker_acked = 0
        peak_inbound_eps = ingestion_rate
        peak_outbound_eps = 0.0
        max_logs_per_sec = float(MAX_LOGS_PER_SEC)

        while True:
            elapsed = time.monotonic() - start_monitor

            # Optional automated Graylog 503 outage simulation during drain
            if simulate_outage and mock_available:
                if not outage_triggered and elapsed >= 2.0:
                    await client.post(f"{MOCK_GRAYLOG_BASE_URL}/outage/on")
                    outage_triggered = True
                    print(
                        "  >>> [SIMULATED OUTAGE] Mock Graylog set to HTTP 503! "
                        "Consumer Worker exponential backoff engaged (Offsets held uncommitted)..."
                    )
                elif outage_triggered and not outage_restored and elapsed >= 6.5:
                    await client.post(f"{MOCK_GRAYLOG_BASE_URL}/outage/off")
                    outage_restored = True
                    print(
                        "  >>> [OUTAGE RECOVERED] Mock Graylog restored to HTTP 202! "
                        "Consumer Worker resuming throttled GELF delivery..."
                    )

            metrics_resp = await client.get(f"{INGESTOR_BASE_URL}/metrics")
            metrics_resp.raise_for_status()
            m = metrics_resp.json()

            total_received = int(m["total_received"]) - base_received
            total_forwarded = int(m["total_forwarded_to_graylog"]) - base_forwarded
            if "permanently_dropped_logs" in m or "dlq_quarantined_logs" in m:
                permanently_dropped = max(
                    0,
                    int(m.get("permanently_dropped_logs", 0))
                    - base_permanently_dropped,
                )
                dlq_quarantined = max(
                    0, int(m.get("dlq_quarantined_logs", 0)) - base_dlq_quarantined
                )
                dropped_logs = permanently_dropped + dlq_quarantined
            else:
                dropped_logs = max(0, int(m["dropped_logs"]) - base_dropped)
                permanently_dropped = dropped_logs
                dlq_quarantined = 0
            dlq_replayed = int(m.get("dlq_replayed_logs", 0))
            current_queue_lag = int(m["current_queue_lag"])
            peak_lag = max(peak_lag, int(m.get("peak_queue_lag", current_queue_lag)))

            tp = m.get("throughput_telemetry", {})
            outbound_eps = float(tp.get("outbound_eps", 0.0))
            peak_inbound_eps = max(
                peak_inbound_eps, float(tp.get("peak_inbound_eps", 0.0))
            )
            peak_outbound_eps = max(
                peak_outbound_eps, float(tp.get("peak_outbound_eps", 0.0))
            )
            max_logs_per_sec = float(
                tp.get("configured_max_logs_per_sec", MAX_LOGS_PER_SEC)
            )

            kt = m.get("broker_telemetry", {})
            broker_acked = max(
                total_received - int(kt.get("in_flight_producer_queue", 0)),
                int(kt.get("total_broker_acked", 0)) - base_broker_acked,
            )

            lag_cell = f"{current_queue_lag:,d} ({peak_lag:,d})"
            eps_cell = f"{outbound_eps:6.1f} ({max_logs_per_sec:5.0f}/s)"
            progress_bar = build_progress_bar(total_forwarded, total_sent, width=18)
            print(
                f"{elapsed:4.1f}s | {total_sent:7,d} | {total_received:8,d} | "
                f"{lag_cell:>18} | {eps_cell:>20} | "
                f"{total_forwarded:14,d} | {dropped_logs:7,d} | {progress_bar}"
            )

            if (
                total_forwarded + permanently_dropped + dlq_quarantined >= total_sent
                and current_queue_lag == 0
            ):
                break

            if elapsed > timeout_seconds:
                print(
                    "\n[ERROR] Verification timed out waiting for queue lag to drain to 0."
                )
                sys.exit(1)

            # High-resolution honeytoken arrival check while draining
            for _ in range(10):
                if honeytoken_delivered_latency is None and mock_available:
                    try:
                        st_resp = await client.get(f"{MOCK_GRAYLOG_BASE_URL}/status")
                        if st_resp.status_code == 200:
                            st_data = st_resp.json()
                            if st_data.get("honeytoken_alerts_received", 0) >= 1:
                                honeytoken_delivered_latency = time.perf_counter() - ht_send_time
                    except Exception:
                        pass
                await asyncio.sleep(0.1)

        print("-" * 112)

        # 3. Verify Kill-Chain, Honeytoken & Idempotent Deduplication on Mock Graylog if active
        graylog_stored = total_forwarded
        duplicates_ignored = 0
        if mock_available:
            status_resp = await client.get(f"{MOCK_GRAYLOG_BASE_URL}/status")
            if status_resp.status_code == 200:
                g_status = status_resp.json()
                graylog_stored = int(
                    g_status.get("total_gelf_received", total_forwarded)
                )
                duplicates_ignored = int(g_status.get("duplicate_gelf_ignored", 0))
                kc_report = g_status.get("kill_chain_verification", {})
                print("\n[SIEM CORRELATION & SCENARIO AUDIT FROM GRAYLOG SERVER]")
                print(
                    f"  • Honeytoken Alerts Received (_honeytoken_alert=true) : "
                    f"{g_status.get('honeytoken_alerts_received', 0)}"
                )
                if honeytoken_delivered_latency is not None:
                    lat_ok = honeytoken_delivered_latency <= honeytoken_latency_budget
                    print(
                        f"  • Honeytoken Priority Alert Latency                   : "
                        f"{honeytoken_delivered_latency:.3f}s (Budget: < {honeytoken_latency_budget:.1f}s) [{'PASS' if lat_ok else 'FAIL'}]"
                    )
                    assert lat_ok, (
                        f"Honeytoken latency {honeytoken_delivered_latency:.3f}s exceeded budget {honeytoken_latency_budget}s"
                    )
                print(
                    f"  • Kill-Chain Attacker IP ({KILL_CHAIN_IP}) Sequence   : "
                    f"{kc_report.get('observed_sequence')}"
                )
                print(
                    f"  • Strict Chronological Order Verified                 : "
                    f"{kc_report.get('strict_chronological_order_verified')}"
                )
                print(
                    f"  • Kill-Chain Cross-Lane Ordering Report               : "
                    f"{kc_report.get('cross_lane_ordering', 'best effort')}"
                )
                if "per_lane_ordering_verified" in kc_report:
                    print(
                        f"  • Kill-Chain Per-Lane Ordering Verified               : "
                        f"{kc_report.get('per_lane_ordering_verified')}"
                    )
                print(
                    f"  • Single Broker Partition Routing Verified             : "
                    f"{kc_report.get('same_partition_verified')}"
                )
                if simulate_outage:
                    print(
                        f"  • HTTP 503 Outage Batches Survived via Backoff        : "
                        f"{g_status.get('rejected_503_batches', 0)}"
                    )
                assert (
                    kc_report.get("strict_chronological_order_verified") is True
                    or kc_report.get("per_lane_ordering_verified") is True
                ), (
                    f"Kill-Chain order verification failed: {kc_report}"
                )
                assert g_status.get("honeytoken_alerts_received", 0) >= 1, (
                    "Honeytoken alert was not received by Graylog!"
                )

        # 4. Print 5-Stage End-to-End Zero-Loss & Backpressure Audit Report
        print("\n[5-STAGE END-TO-END ZERO-LOSS & BACKPRESSURE AUDIT REPORT]")
        print(
            f"  1. [Stage 1] Attack Load Generator Sent       : {total_sent:,} logs (Burst Rate: {ingestion_rate:,.0f} logs/sec)"
        )
        print(
            f"  2. [Stage 2] HTTP Ingestor Accepted           : {total_received:,} logs (Peak Inbound: {peak_inbound_eps:,.0f} logs/sec, permanently_dropped: {permanently_dropped:,})"
        )
        print(
            f"  3. [Stage 3] Lightweight WAL Broker Buffered      : {broker_acked:,} logs (Peak Queue Lag Buffered: {peak_lag:,} logs)"
        )
        print(
            f"  4. [Stage 4] Consumer Worker Throttled Commit : {total_forwarded:,} logs (Peak Outbound: {peak_outbound_eps:,.0f} / Limit: {max_logs_per_sec:,.0f} logs/sec, dlq_quarantined: {dlq_quarantined:,})"
        )
        print(
            f"  5. [Stage 5] Graylog GELF Server Stored       : {graylog_stored:,} logs (Duplicates Deduped: {duplicates_ignored}, DLQ Replayed: {dlq_replayed})"
        )

        # End-to-End Tail Latency Quantitative Report
        lat_telemetry = g_status.get("latency_telemetry", {})
        std_lat = lat_telemetry.get("standard_lane", {})
        prio_lat = lat_telemetry.get("priority_lane", {})

        std_avg = std_lat.get("avg_sec", 0.0)
        std_p95 = std_lat.get("p95_sec", 0.0)
        std_p99 = std_lat.get("p99_sec", 0.0)
        std_max = std_lat.get("max_sec", 0.0)

        print(
            f"  • Standard Lane E2E Latency (Throttled) : avg={std_avg:.2f}s | p95={std_p95:.2f}s | p99={std_p99:.2f}s | max={std_max:.2f}s"
        )
        ht_lat = (
            honeytoken_delivered_latency
            if honeytoken_delivered_latency is not None
            else prio_lat.get("avg_sec", 0.0)
        )
        lat_ok = ht_lat <= honeytoken_latency_budget
        print(
            f"  • Priority Lane (Honeytoken) Latency    : {ht_lat:.3f}s (Budget: < {honeytoken_latency_budget:.1f}s) [{'PASS' if lat_ok else 'FAIL'}]"
        )
        print(
            f"  • Engineering Trade-off Summary         : SIEM 보호를 위해 일반 로그 지연시간(p99)을 의도적으로 평탄화({max_logs_per_sec:.0f} EPS)하되, 70:30 우선순위 레인으로 긴급 침해 경보 골든타임(< {honeytoken_latency_budget:.1f}s)을 사수함."
        )

        # 5. Final Zero Log Loss Assertions
        invariant_line = verify_five_stage_audit_invariant(
            total_sent=total_sent,
            total_received=total_received,
            total_forwarded=total_forwarded,
            permanently_dropped=permanently_dropped,
            dlq_quarantined=dlq_quarantined,
            graylog_stored=graylog_stored,
            current_queue_lag=current_queue_lag,
        )

        print("\n" + "=" * 112)
        print(
            " [PASS] SCENARIO 2 VERIFIED: 100% SPIKE BUFFERED & 0.0000% LOG LOSS"
        )
        print(f"        {invariant_line}")
        print("=" * 112)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOAR Broker Middleware Traffic Spike Simulator & Zero-Loss Verifier"
    )
    parser.add_argument(
        "--spike-count",
        type=int,
        default=5000,
        help="Number of high-velocity spike logs to blast (default: 5000)",
    )
    parser.add_argument(
        "--simulate-outage",
        action="store_true",
        help="Automatically trigger a temporary Graylog HTTP 503 outage mid-drain to test backoff recovery",
    )
    parser.add_argument(
        "--honeytoken-latency-budget",
        type=float,
        default=HONEYTOKEN_LATENCY_BUDGET,
        help=f"Latency budget in seconds for honeytoken alert delivery (default: {HONEYTOKEN_LATENCY_BUDGET}s)",
    )
    args = parser.parse_args()
    asyncio.run(
        run_spike_verification(
            spike_count=args.spike_count,
            simulate_outage=args.simulate_outage,
            honeytoken_latency_budget=args.honeytoken_latency_budget,
        )
    )


if __name__ == "__main__":
    main()
