import asyncio
import time
from typing import Any, Dict, List
import httpx

INGESTOR_URL = "http://localhost:8000/v1/ingest/batch"
HEADERS = {"X-API-Key": "prod-ingest-key-1"}


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
    run_id: int, total_logs: int = 20000, batch_size: int = 100, concurrency: int = 15
) -> Dict[str, Any]:
    print(f"\n" + "=" * 70)
    print(f" [LOAD TEST] Iteration {run_id}: Sending {total_logs:,} logs (batch_size={batch_size}, concurrency={concurrency})")
    print("=" * 70)

    num_batches = total_logs // batch_size
    batches = [
        generate_batch(i * batch_size, batch_size)
        for i in range(num_batches)
    ]

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
                # Rotate between allowed ingest keys to distribute token bucket load
                key = "prod-ingest-key-1" if idx % 2 == 0 else "prod-ingest-key-2"
                headers = {"X-API-Key": key}
                while True:
                    try:
                        resp = await client.post(
                            INGESTOR_URL,
                            json={"logs": batch},
                            headers=headers,
                        )
                        if resp.status_code == 202:
                            accepted_logs += len(batch)
                            return
                        elif resp.status_code == 429:
                            retry_after = float(resp.headers.get("Retry-After", "1.0"))
                            await asyncio.sleep(retry_after)
                            continue
                        else:
                            other_errors += 1
                            print(f"  [WARN] Batch {idx} returned HTTP {resp.status_code}")
                            return
                    except (httpx.ReadError, httpx.ReadTimeout) as re:
                        read_errors += 1
                        print(f"  [ERROR] Batch {idx} ReadError: {re}")
                        return
                    except Exception as exc:
                        other_errors += 1
                        print(f"  [ERROR] Batch {idx} Exception: {exc}")
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
    assert accepted_logs == total_logs, f"Iteration {run_id} only accepted {accepted_logs}/{total_logs} logs!"

    return {
        "run_id": run_id,
        "elapsed": elapsed,
        "accepted": accepted_logs,
        "read_errors": read_errors,
        "other_errors": other_errors,
    }


async def main():
    print("=" * 70)
    print(" STARTING CONTINUOUS LOAD TEST: 20,000 LOGS x 2 RUNS")
    print("=" * 70)

    # Run 1
    res1 = await run_load_test_iteration(run_id=1, total_logs=20000, batch_size=100, concurrency=30)

    # Brief 1s pause between runs to test background cache refresh in between
    await asyncio.sleep(1.0)

    # Run 2
    res2 = await run_load_test_iteration(run_id=2, total_logs=20000, batch_size=100, concurrency=30)

    print("\n" + "#" * 70)
    print(" [SUCCESS] 20,000 x 2 LOAD TEST COMPLETED WITH 0 READERRORS!")
    print(f"   Run 1: {res1['accepted']:,} logs in {res1['elapsed']:.2f}s, ReadErrors: {res1['read_errors']}")
    print(f"   Run 2: {res2['accepted']:,} logs in {res2['elapsed']:.2f}s, ReadErrors: {res2['read_errors']}")
    print("#" * 70)


if __name__ == "__main__":
    asyncio.run(main())
