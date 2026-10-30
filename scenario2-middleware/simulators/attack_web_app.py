"""Web-App / API Server Attack Simulator for Scenario 2 Middleware.

Sends attack traffic through the Main API server (http://127.0.0.1:5000/api/data),
verifies that API security events are generated, buffered by Middleware (:8000),
throttled by Consumer Worker (:9100), and delivered to Graylog (:12201).
"""

import argparse
import asyncio
import time
from typing import Any, Dict, List
import httpx

API_SERVER_URL = "http://127.0.0.1:5000"
MIDDLEWARE_URL = "http://127.0.0.1:8000"


async def send_attack(client: httpx.AsyncClient, index: int, attack_type: str) -> Dict[str, Any]:
    url = f"{API_SERVER_URL}/api/data"
    headers: Dict[str, str] = {}

    if attack_type == "not_allowed_ip":
        headers = {
            "X-API-Key": "test-key-01",
            "X-Demo-Client-IP": f"10.10.{index // 256}.{index % 254 + 1}",
            "User-Agent": f"AttackerBot/{index}",
        }
    elif attack_type == "suspicious_scanner":
        headers = {
            "X-API-Key": "test-key-01",
            "X-Demo-Client-IP": "127.0.0.1",
            "User-Agent": "sqlmap/1.6.4#stable (https://sqlmap.org)",
        }
    elif attack_type == "invalid_key":
        headers = {
            "X-API-Key": f"stolen-fake-key-{index:04d}",
            "X-Demo-Client-IP": f"192.168.10.{index % 254 + 1}",
            "User-Agent": "Hydra/9.5 brute-force",
        }
    else:  # normal
        headers = {
            "X-API-Key": "test-key-01",
            "X-Demo-Client-IP": "127.0.0.1",
            "User-Agent": "AuthorizedClient/1.0",
        }

    t0 = time.perf_counter()
    try:
        resp = await client.get(url, headers=headers)
        elapsed = time.perf_counter() - t0
        return {
            "index": index,
            "type": attack_type,
            "status_code": resp.status_code,
            "elapsed": elapsed,
            "success": True,
        }
    except Exception as exc:
        return {
            "index": index,
            "type": attack_type,
            "status_code": 0,
            "elapsed": 0.0,
            "error": str(exc),
            "success": False,
        }


async def run_web_app_attack(count: int = 10, concurrency: int = 5):
    print("=" * 80)
    print(f"[*] EngineSquare Web-App Attack Test: {count:,} Requests via {API_SERVER_URL}")
    print("=" * 80)

    # 1. Check API server health
    async with httpx.AsyncClient(timeout=3.0) as client:
        try:
            r = await client.get(f"{API_SERVER_URL}/health")
            if r.status_code != 200:
                print(f"[!] API Server returned status {r.status_code}. Is python app.py running?")
                return
        except Exception as exc:
            print(f"[!] Cannot connect to API server at {API_SERVER_URL}: {exc}")
            print("    Please run: python app.py in a separate terminal!")
            return

        # Baseline metrics from Middleware
        try:
            base_m = (await client.get(f"{MIDDLEWARE_URL}/v1/metrics")).json()
            base_received = base_m.get("total_received", 0)
            base_forwarded = base_m.get("total_forwarded_to_graylog", 0)
        except Exception:
            base_received = 0
            base_forwarded = 0

    # 2. Build attack batch
    attack_types = ["not_allowed_ip", "suspicious_scanner", "invalid_key", "not_allowed_ip"]
    tasks_args = []
    for i in range(count):
        atype = attack_types[i % len(attack_types)]
        tasks_args.append((i + 1, atype))

    # 3. Fire requests with semaphore
    semaphore = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency * 2)

    async def worker(idx: int, atype: str) -> Dict[str, Any]:
        async with semaphore:
            return await send_attack(client, idx, atype)

    t_start = time.perf_counter()
    async with httpx.AsyncClient(limits=limits, timeout=10.0) as client:
        results = await asyncio.gather(*(worker(idx, atype) for idx, atype in tasks_args))
    t_total = time.perf_counter() - t_start

    # 4. Summarize attack results
    status_counts: Dict[int, int] = {}
    for res in results:
        code = res["status_code"]
        status_counts[code] = status_counts.get(code, 0) + 1

    print(f"\n[+] Blasted {count:,} attack requests to Web-App in {t_total:.2f}s ({count / max(t_total, 0.001):.1f} req/s)")
    print(f"    - Response Breakdown: {status_counts}")
    for res in results[:5]:
        print(f"      req #{res['index']:02d}: type={res['type']:<18} status={res['status_code']} ({res['elapsed']*1000:.1f}ms)")
    if count > 5:
        print(f"      ... ({count - 5} more requests)")

    # 5. Wait briefly for Middleware drain & verify
    print("\n[*] Checking Middleware buffer & Graylog forwarding...")
    await asyncio.sleep(1.5)

    async with httpx.AsyncClient(timeout=3.0) as client:
        try:
            curr_m = (await client.get(f"{MIDDLEWARE_URL}/v1/metrics")).json()
            curr_received = curr_m.get("total_received", 0)
            curr_forwarded = curr_m.get("total_forwarded_to_graylog", 0)
            diff_received = curr_received - base_received
            diff_forwarded = curr_forwarded - base_forwarded
            lag = curr_m.get("current_queue_lag", 0)

            print(f"    - Middleware Ingested New Logs : {diff_received:,} / {count:,}")
            print(f"    - Forwarded to Graylog         : {diff_forwarded:,} / {count:,}")
            print(f"    - Current Broker Queue Lag     : {lag}")
            if diff_forwarded == count:
                print("\n" + "=" * 80)
                print(f" [PASS] All {count:,} attack events cleanly buffered & forwarded to Graylog!")
                print("=" * 80)
            else:
                print(f"\n[i] In transit or partially forwarded: {diff_forwarded}/{count}")
        except Exception as exc:
            print(f"[!] Could not read middleware metrics: {exc}")


def main():
    parser = argparse.ArgumentParser(description="Web-App Attack Simulator for Scenario 2 Middleware")
    parser.add_argument("--count", type=int, default=10, help="Number of attack requests (default: 10)")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrent HTTP requests (default: 5)")
    args = parser.parse_args()

    asyncio.run(run_web_app_attack(count=args.count, concurrency=args.concurrency))


if __name__ == "__main__":
    main()
