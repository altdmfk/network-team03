import argparse
import asyncio
import json
import os
import sys
import time
from typing import Any, Dict, List

import httpx

_sim_dir = os.path.dirname(os.path.abspath(__file__))
_mid_root = os.path.dirname(_sim_dir)
for _p in [os.path.join(_mid_root, "src"), _sim_dir, _mid_root]:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from auth_helper import generate_hmac_signature_headers

try:
    from config import BATCH_SIZE, INGEST_API_KEYS

    DEFAULT_API_KEYS: List[str] = (
        list(INGEST_API_KEYS) if INGEST_API_KEYS else ["prod-ingest-key-1", "prod-ingest-key-2"]
    )
    DEFAULT_BATCH_SIZE = int(BATCH_SIZE)
except ImportError:
    DEFAULT_API_KEYS = ["prod-ingest-key-1", "prod-ingest-key-2"]
    DEFAULT_BATCH_SIZE = 100

INGESTOR_URL = os.environ.get("INGESTOR_URL", "http://127.0.0.1:8000/v1/ingest/batch")


def generate_batch(start_idx: int, size: int) -> List[Dict[str, Any]]:
    base_ts = time.time()
    return [
        {
            "timestamp": round(base_ts + (i * 0.0001), 3),
            "client_ip": f"10.0.{(start_idx + i) // 250}.{(start_idx + i) % 250 + 1}",
            "event_type": "PORT_SCAN" if i % 2 == 0 else "BRUTE_FORCE",
            "target_resource": f"/api/resource/{start_idx + i}",
            "status_code": 200,
            "severity": 3,
            "raw_payload": {"seq": start_idx + i, "data": "load_test_payload"},
        }
        for i in range(size)
    ]


async def run_load_test_iteration(
    run_id: int,
    total_logs: int = 20000,
    batch_size: int = DEFAULT_BATCH_SIZE,
    concurrency: int = 30,
    api_keys: List[str] = DEFAULT_API_KEYS,
) -> Dict[str, Any]:
    print("\n" + "=" * 70)
    print(
        f" [LOAD TEST] Iteration {run_id}: Sending {total_logs:,} logs "
        f"(batch_size={batch_size}, concurrency={concurrency})"
    )
    print("=" * 70)

    num_batches = total_logs // batch_size
    batches = [generate_batch(i * batch_size, batch_size) for i in range(num_batches)]

    semaphore = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_connections=concurrency + 5, max_keepalive_connections=concurrency)
    timeout = httpx.Timeout(15.0, connect=5.0)

    read_errors = 0
    other_errors = 0
    accepted_logs = 0

    t0 = time.perf_counter()

    async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
        async def send_batch(idx: int, batch: List[Dict[str, Any]]) -> None:
            nonlocal read_errors, other_errors, accepted_logs
            async with semaphore:
                # 토큰 버킷 부하 분산을 위해 허용된 수집 API 키를 라운드로빈으로 순환 사용하며 HMAC 서명 생성
                key = api_keys[idx % len(api_keys)]
                body_bytes = json.dumps(
                    {"logs": batch}, separators=(",", ":"), ensure_ascii=False
                ).encode("utf-8")
                headers = {
                    "Content-Type": "application/json",
                    **generate_hmac_signature_headers(key, body_bytes),
                }
                while True:
                    try:
                        resp = await client.post(
                            INGESTOR_URL,
                            content=body_bytes,
                            headers=headers,
                        )
                        if resp.status_code == 202:
                            accepted_logs += len(batch)
                            return
                        if resp.status_code == 429:
                            retry_after = float(resp.headers.get("Retry-After", "1.0"))
                            await asyncio.sleep(retry_after)
                            continue
                        other_errors += 1
                        print(f"  [WARN] Batch {idx} returned HTTP {resp.status_code}")
                        return
                    except (httpx.ReadError, httpx.ReadTimeout) as re:
                        read_errors += 1
                        print(f"  [ERROR] Batch {idx} ReadError: {re}")
                        return
                    except httpx.HTTPError as exc:
                        other_errors += 1
                        print(f"  [ERROR] Batch {idx} HTTPError: {exc}")
                        return

        await asyncio.gather(*(send_batch(i, b) for i, b in enumerate(batches)))

    elapsed = time.perf_counter() - t0
    eps = accepted_logs / max(elapsed, 0.001)

    print(f"[*] Iteration {run_id} Results:")
    print(f"    - Elapsed Time  : {elapsed:.2f}s ({eps:,.0f} logs/sec)")
    print(f"    - Accepted Logs : {accepted_logs:,} / {total_logs:,}")
    print(f"    - ReadErrors    : {read_errors}")
    print(f"    - Other Errors  : {other_errors}")

    assert read_errors == 0, f"Iteration {run_id} failed with {read_errors} ReadErrors!"
    assert accepted_logs == total_logs, (
        f"Iteration {run_id} only accepted {accepted_logs}/{total_logs} logs!"
    )

    return {
        "run_id": run_id,
        "elapsed": elapsed,
        "accepted": accepted_logs,
        "read_errors": read_errors,
        "other_errors": other_errors,
    }


async def run_all(
    total_logs: int = 20000,
    batch_size: int = DEFAULT_BATCH_SIZE,
    concurrency: int = 30,
    runs: int = 2,
    pause_sec: float = 1.0,
) -> None:
    print("=" * 70)
    print(f" STARTING CONTINUOUS LOAD TEST: {total_logs:,} LOGS x {runs} RUNS")
    print("=" * 70)

    results = []
    for run_id in range(1, runs + 1):
        res = await run_load_test_iteration(
            run_id=run_id,
            total_logs=total_logs,
            batch_size=batch_size,
            concurrency=concurrency,
        )
        results.append(res)
        if run_id < runs:
            # 반복 실행 간 백그라운드 lag 캐시 갱신 동작 확인을 위한 대기
            await asyncio.sleep(pause_sec)

    print("\n" + "#" * 70)
    print(f" [SUCCESS] {total_logs:,} x {runs} LOAD TEST COMPLETED WITH 0 READERRORS!")
    for res in results:
        print(
            f"   Run {res['run_id']}: {res['accepted']:,} logs in {res['elapsed']:.2f}s, "
            f"ReadErrors: {res['read_errors']}"
        )
    print("#" * 70)


def main() -> None:
    parser = argparse.ArgumentParser(description="Continuous Load Test for SOAR Ingestor")
    parser.add_argument("--logs", "-c", type=int, default=20000, help="Logs per iteration (default: 20000)")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help=f"Batch size (default: {DEFAULT_BATCH_SIZE})")
    parser.add_argument("--concurrency", type=int, default=30, help="Concurrent HTTP requests (default: 30)")
    parser.add_argument("--runs", type=int, default=2, help="Number of iterations (default: 2)")
    args = parser.parse_args()

    asyncio.run(
        run_all(
            total_logs=args.logs,
            batch_size=args.batch_size,
            concurrency=args.concurrency,
            runs=args.runs,
        )
    )


if __name__ == "__main__":
    main()
