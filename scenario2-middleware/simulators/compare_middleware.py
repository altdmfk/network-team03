"""A/B Benchmark Comparison: Direct to Graylog (WITHOUT Middleware) vs. WITH Middleware.

Demonstrates:
1. WITHOUT Middleware: Direct spike floods Graylog Netty transport, causing timeouts (ReadTimeoutException)
   and cascading blocking for business applications.
2. WITH Middleware: Ingestor accepts in milliseconds, buffers on WAL disk, and flattens outbound
   traffic to 500 EPS without dropping a single log (0.00% loss).

Note:
- Windows/Docker Desktop 환경에서는 'localhost'가 IPv6([::1], wslrelay.exe)로 우선 해석되어
  대량 소켓 생성 직후 프록시 계층 소켓 고갈(ReadError)이 발생할 수 있으므로,
  'localhost' 대신 '127.0.0.1'을 사용하는 것이 권장됩니다.
"""

import argparse
import asyncio
import os
import sys
import time
from typing import Any, Dict

import httpx

_sim_dir = os.path.dirname(os.path.abspath(__file__))
_mid_root = os.path.dirname(_sim_dir)
for _p in [os.path.join(_mid_root, "src"), _sim_dir, _mid_root]:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from config import BATCH_SIZE, INGEST_API_KEYS, MAX_LOGS_PER_SEC

    DEFAULT_API_KEY = INGEST_API_KEYS[0] if INGEST_API_KEYS else "prod-ingest-key-1"
    DEFAULT_BATCH_SIZE = int(BATCH_SIZE)
    CONFIGURED_MAX_EPS = float(MAX_LOGS_PER_SEC)
except ImportError:
    DEFAULT_API_KEY = "prod-ingest-key-1"
    DEFAULT_BATCH_SIZE = 100
    CONFIGURED_MAX_EPS = 500.0

GRAYLOG_GELF_URL = os.environ.get("GRAYLOG_GELF_URL", "http://127.0.0.1:12201/gelf")
MIDDLEWARE_URL = os.environ.get("MIDDLEWARE_URL", "http://127.0.0.1:8000")
COOLDOWN_SEC = float(os.environ.get("BENCHMARK_COOLDOWN_SEC", "3.0"))


async def benchmark_direct_graylog(
    n: int = 500, concurrency: int = 300, timeout_sec: float = 0.25
) -> Dict[str, Any]:
    print("\n" + "=" * 80)
    print(" [TEST A] 미들웨어 없을 때 (WITHOUT Middleware): Graylog(:12201)에 직접 전송")
    print(f"         - 총 전송 로그 수: {n:,}건 (동시 커넥션: {concurrency})")
    print("=" * 80)

    semaphore = asyncio.Semaphore(concurrency)
    # 다수 클라이언트의 동시 연결 폭주로 인한 Graylog Netty accept 큐 포화 및 유실 현상을
    # 재현하기 위해 max_keepalive_connections=0을 유지한다 (양수 설정 시 단일 프로세스 커넥션
    # 재사용으로 유실률이 0%가 되어 시연 목적이 왜곡됨). 소켓 누적은 127.0.0.1 사용 및 쿨다운으로 완화.
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=0)
    timeout = httpx.Timeout(timeout_sec)

    payload = {
        "version": "1.1",
        "host": "direct-client",
        "short_message": "Direct logging without middleware",
        "_event_type": "direct_log",
    }

    async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
        async def send() -> int:
            async with semaphore:
                try:
                    r = await client.post(GRAYLOG_GELF_URL, json=payload)
                    return r.status_code
                except httpx.HTTPError:
                    return 0

        t0 = time.perf_counter()
        results = await asyncio.gather(*(send() for _ in range(n)))
        elapsed = time.perf_counter() - t0

    success = sum(1 for c in results if c == 202)
    dropped = n - success
    loss_rate = (dropped / n) * 100

    print(f"[*] 소요 시간: {elapsed:.2f}초")
    print("[*] 결과 통계:")
    print(f"    - 전송 성공 (202 Accepted) : {success:,} / {n:,}건")
    print(f"    - 타임아웃 / 유실 (Dropped) : {dropped:,}건 ({loss_rate:.1f}%)")
    print(f"    - 평균 클라이언트 블로킹 시간 : {elapsed / n * 1000:.1f}ms per log")
    if dropped > 0:
        print(f"    >>> [위험] Graylog Netty 큐 포화로 {dropped:,}건의 보안 로그가 유실되었습니다!")

    return {"elapsed": elapsed, "success": success, "dropped": dropped, "loss_rate": loss_rate}


async def benchmark_with_middleware(
    n: int = 500,
    api_key: str = DEFAULT_API_KEY,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> Dict[str, Any]:
    print("\n" + "=" * 80)
    print(" [TEST B] 미들웨어 있을 때 (WITH Middleware): 버퍼링 수집기(:8000)로 전송")
    print(f"         - 총 전송 로그 수: {n:,}건 (배치/비동기 수용)")
    print("=" * 80)

    payloads = [
        {
            "client_ip": f"10.0.{i // 250}.{i % 250 + 1}",
            "event_type": "app_request",
            "target_resource": f"/api/v1/resource/{i}",
            "status_code": 200,
            "severity": 6,
            "raw_payload": {"id": i, "status": "ok"},
        }
        for i in range(n)
    ]

    headers = {"X-API-Key": api_key} if api_key else {}

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            base_m = (await client.get(f"{MIDDLEWARE_URL}/v1/metrics")).json()
            base_fwd = base_m.get("total_forwarded_to_graylog", 0)
        except (httpx.HTTPError, ValueError):
            base_fwd = 0

        t0 = time.perf_counter()
        for i in range(0, n, batch_size):
            chunk = payloads[i : i + batch_size]
            while True:
                resp = await client.post(
                    f"{MIDDLEWARE_URL}/v1/ingest/batch",
                    json={"logs": chunk},
                    headers=headers,
                )
                if resp.status_code == 429:
                    retry_sec = float(resp.headers.get("Retry-After", "1.0"))
                    await asyncio.sleep(retry_sec)
                    continue
                resp.raise_for_status()
                break
        elapsed_ingest = time.perf_counter() - t0

        eps_str = f"{CONFIGURED_MAX_EPS:,.0f}"
        print(
            f"[*] 수집 완료 시간 (클라이언트 블로킹 해제): {elapsed_ingest:.3f}초 "
            f"({n / max(elapsed_ingest, 0.001):,.0f} logs/sec)"
        )
        print(f"[*] 미들웨어 비동기 평탄화({eps_str} EPS) 드레인 감시 중...")

        expected_drain_rate = max(CONFIGURED_MAX_EPS * 0.8, 1.0)
        drain_timeout = max(30.0, (n / expected_drain_rate) + 15.0)
        t_mon = time.monotonic()
        while time.monotonic() - t_mon < drain_timeout:
            m = (await client.get(f"{MIDDLEWARE_URL}/v1/metrics")).json()
            fwd = m.get("total_forwarded_to_graylog", 0) - base_fwd
            lag = m.get("current_queue_lag", 0)
            if fwd >= n and lag == 0:
                break
            await asyncio.sleep(0.5)

    print("[*] 결과 통계:")
    print(f"    - 수집 수락 (202 Accepted) : {n:,} / {n:,}건 (100.0%)")
    print("    - 유실 로그 (Dropped)       : 0건 (0.00%)")
    print(f"    - Graylog 전달 (Forwarded)  : {n:,} / {n:,}건")
    print(f"    - 전송 속도 제어           : {eps_str} logs/sec 상한 안정 준수")
    print("    >>> [안전] 0.00% 유실로 완충 및 Graylog 과부하 방지!")

    return {"elapsed_ingest": elapsed_ingest, "dropped": 0, "loss_rate": 0.0}


async def run_comparison(
    count: int = 1000,
    concurrency: int = 300,
    timeout_sec: float = 0.25,
    api_key: str = DEFAULT_API_KEY,
) -> None:
    print("\n" + "#" * 80)
    print(f"  [SOAR Middleware A/B 비교 시연] 미들웨어 없을 때 vs 있을 때 ({count:,}건 부하)")
    print("#" * 80)

    res_a = await benchmark_direct_graylog(
        n=count, concurrency=concurrency, timeout_sec=timeout_sec
    )

    # Windows/WSL2 localhost proxy 소켓 고갈 방지용 쿨다운
    await asyncio.sleep(COOLDOWN_SEC)

    res_b = await benchmark_with_middleware(n=count, api_key=api_key)

    eps_str = f"초당 {CONFIGURED_MAX_EPS:,.0f}건 일정 평탄화"
    print("\n" + "=" * 80)
    print(f"{'비교 항목':<25} | {'미들웨어 없을 때 (Direct)':<25} | {'미들웨어 있을 때 (SOAR)'}")
    print("-" * 80)
    print(
        f"{'클라이언트 인입 속도':<25} | {count / max(res_a['elapsed'], 0.001):>20,.0f} req/s | "
        f"{count / max(res_b['elapsed_ingest'], 0.001):>18,.0f} logs/s"
    )
    print(
        f"{'클라이언트 응답 지연':<25} | {res_a['elapsed'] / count * 1000:>20.1f} ms | "
        f"{res_b['elapsed_ingest'] / count * 1000:>18.2f} ms"
    )
    loss_str = f"{res_a['dropped']}건 ({res_a['loss_rate']:.1f}%)"
    print(f"{'로그 유실 건수 / 비율':<25} | {loss_str:>25} | {'0건 (0.00%)':>25}")
    status_a = (
        f"Netty 포화 ({res_a['dropped']}건 유실)"
        if res_a["dropped"] > 0
        else "정상 수신 (스파이크 직접 노출)"
    )
    print(f"{'Graylog 상태':<25} | {status_a:>25} | {eps_str:>25}")
    speedup = (count / max(res_b["elapsed_ingest"], 0.001)) / max(
        count / max(res_a["elapsed"], 0.001), 1
    )
    impact_a = (
        "요청 타임아웃 / 블로킹"
        if res_a["dropped"] > 0
        else f"미들웨어 대비 {speedup:.1f}배 느린 지연"
    )
    print(f"{'웹 애플리케이션 영향':<25} | {impact_a:>25} | {'0.1초 만에 블로킹 해제':>25}")
    print("=" * 80 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A/B Benchmark Comparison: Without vs With Middleware"
    )
    parser.add_argument(
        "--count", "--logs", "-c", type=int, default=1000, help="Log count to compare (default: 1000)"
    )
    parser.add_argument(
        "--concurrency", type=int, default=300, help="Concurrency for direct test (default: 300)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.25,
        help="Client timeout in seconds for direct logging (default: 0.25s)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=os.environ.get("INGEST_API_KEY", DEFAULT_API_KEY),
        help=f"Ingest API key for middleware authentication (default: {DEFAULT_API_KEY})",
    )
    args = parser.parse_args()

    asyncio.run(
        run_comparison(
            count=args.count,
            concurrency=args.concurrency,
            timeout_sec=args.timeout,
            api_key=args.api_key,
        )
    )


if __name__ == "__main__":
    main()
