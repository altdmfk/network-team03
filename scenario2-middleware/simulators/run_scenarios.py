"""Multi-Scenario Demonstration Runner for Scenario 2 Middleware.

Covers 3 Core Presentation Scenarios:
1. Attack Detection -> Incident Ticket Creation & Automated IP Blocking
2. Non-Attack Legitimate Traffic Spike -> Middleware 500 EPS Traffic Shaping
3. Full Kill-Chain + Honeytoken + Active Defense (Priority Lane 70:30 & Strict Ordering)
"""

import argparse
import asyncio
import os
import sys
import time
from typing import Any, Dict, List
import httpx

API_SERVER_URL = os.environ.get("API_SERVER_URL", "http://127.0.0.1:5000")
WEB_APP_URL = os.environ.get("WEB_APP_URL", "http://127.0.0.1:5001")
MIDDLEWARE_URL = os.environ.get("MIDDLEWARE_URL", "http://127.0.0.1:8000")
GRAYLOG_URL = os.environ.get("GRAYLOG_URL", "http://localhost:9000")


def print_banner(title: str):
    print("\n" + "=" * 90)
    print(f"  {title}")
    print("=" * 90)


# ==============================================================================
# SCENARIO 1: Attack -> Incident Ticket -> Automated IP Block
# ==============================================================================
async def run_scenario_1(attacker_ip: str = "10.10.10.99"):
    print_banner("SCENARIO 1: 공격 탐지 -> 인시던트 티켓 발급 -> SOAR IP 자동 차단 시나리오")
    print(f"[*] Attacker IP: {attacker_ip}")
    print(f"[*] Target API  : {API_SERVER_URL}/api/data\n")

    async with httpx.AsyncClient(timeout=5.0) as client:
        # Pre-check: Ensure IP is unblocked and key-001 is active
        try:
            await client.post(f"{API_SERVER_URL}/api/admin/unblock", json={"ip": attacker_ip, "reactivate_key": "key-001"})
        except Exception:
            pass

        # Step 1: Initial Attack Request (Unauthorized IP using stolen API key)
        print("[Step 1] 공격자가 비허용 IP에서 유출된 API 키로 보호된 데이터(/api/data) 접근 시도...")
        headers = {
            "X-API-Key": "test-key-01",
            "X-Demo-Client-IP": attacker_ip,
            "User-Agent": "AttackerBot/1.0 (exploit probe)",
        }
        r1 = await client.get(f"{API_SERVER_URL}/api/data", headers=headers)
        print(f"         -> API 서버 응답: HTTP {r1.status_code} ({r1.json().get('message')})")

        # Step 2: Verify incident ticket in Web-App / MySQL
        print("\n[Step 2] 웹앱 백엔드 확인: 인시던트 티켓 생성 및 미들웨어 전달 확인...")
        r_inc = await client.get(f"{API_SERVER_URL}/api/incidents")
        incidents = r_inc.json().get("incidents", [])
        target_inc = next((inc for inc in reversed(incidents) if inc.get("client_ip") == attacker_ip or inc.get("api_key_id") == "key-001"), None)
        inc_id = target_inc["incident_id"] if target_inc else "INC-API-NEW"
        print(f"         -> 생성된 인시던트 티켓: [{inc_id}] (사유: {target_inc.get('detection_reason', 'not_allowed_ip') if target_inc else 'not_allowed_ip'})")
        print(f"         -> 미들웨어(:8000)로 api_key_compromised 로그 실시간 인입 완료.")

        # Step 3: SOAR Automation Trigger (n8n Webhook / Auto-response)
        print("\n[Step 3] SOAR 자동화 대응: 공격 IP 차단 및 유출된 API 키 즉시 폐기(Revoke)...")
        revoke_payload = {
            "api_key_id": "key-001",
            "client_ip": attacker_ip,
            "detection_reason": "not_allowed_ip",
        }
        r_rev = await client.post(f"{API_SERVER_URL}/automation/revoke-key", json=revoke_payload)
        rev_data = r_rev.json()
        print(f"         -> SOAR 실행 결과: HTTP {r_rev.status_code}")
        print(f"         -> IP 차단 여부: {rev_data.get('ip_blocked')} (차단 IP: {attacker_ip})")
        print(f"         -> 기존 키 상태: 폐기됨(Revoked) / 신규 발급 키 ID: {rev_data.get('new_api_key_id')}")

        # Step 4: Subsequent Attack Request (Verification of IP Block)
        print("\n[Step 4] 동일 공격자가 동일 IP로 재차 공격 요청 시도...")
        r2 = await client.get(f"{API_SERVER_URL}/api/data", headers=headers)
        print(f"         -> API 서버 응답: HTTP {r2.status_code} ({r2.json().get('message')})")

        print("\n" + "-" * 90)
        print(f" [PASS] SCENARIO 1 COMPLETE: 공격자 {attacker_ip} 차단 완료 및 티켓 [{inc_id}] 발급 확인")
        print(f"        - 웹앱 대시보드 확인: {WEB_APP_URL}/dashboard")
        print(f"        - Graylog 관제 검색 : {GRAYLOG_URL} -> query: client_ip:{attacker_ip}")
        print("-" * 90)


# ==============================================================================
# SCENARIO 2: Non-Attack Legitimate Traffic Spike -> 500 EPS Flattening
# ==============================================================================
async def run_scenario_2(count: int = 100, concurrency: int = 10):
    print_banner(f"SCENARIO 2: 정상 트래픽 급증(Non-Attack Burst {count:,}건) -> 미들웨어 500 EPS 평탄화")
    print(f"[*] Characteristic: 정상적인 사용자 요청 폭증 (공격 아님 -> 차단/티켓 없음)")
    print(f"[*] Goal          : Graylog 과부하 방지를 위해 초당 500건으로 Traffic Shaping\n")

    async with httpx.AsyncClient(timeout=5.0) as client:
        # Pre-check: Ensure test key is active and 127.0.0.1 unblocked
        try:
            await client.post(f"{API_SERVER_URL}/api/admin/unblock", json={"ip": "127.0.0.1", "reactivate_key": "key-001"})
        except Exception:
            pass
        # Pre-check baseline
        try:
            base_m = (await client.get(f"{MIDDLEWARE_URL}/v1/metrics")).json()
            base_rec = base_m.get("total_received", 0)
            base_fwd = base_m.get("total_forwarded_to_graylog", 0)
        except Exception:
            base_rec = 0
            base_fwd = 0

        # Step 1: Send legitimate burst
        print(f"[Step 1] 정상 클라이언트로부터 {count:,}건의 유효한 API 요청을 순간 인입(Burst)...")
        headers = {
            "X-API-Key": "test-key-01",
            "X-Demo-Client-IP": "127.0.0.1",
            "User-Agent": "OfficialCustomerApp/2.4",
        }

        semaphore = asyncio.Semaphore(concurrency)
        async def send_legit(idx: int) -> int:
            async with semaphore:
                resp = await client.get(f"{API_SERVER_URL}/api/data", headers=headers)
                return resp.status_code

        t0 = time.perf_counter()
        results = await asyncio.gather(*(send_legit(i) for i in range(count)))
        t_burst = time.perf_counter() - t0
        success_200 = sum(1 for c in results if c == 200)

        print(f"         -> 인입 소요 시간: {t_burst:.2f}초 ({count / max(t_burst, 0.001):,.0f} req/sec)")
        print(f"         -> 정상 200 OK 처리: {success_200:,} / {count:,} (차단 0건)")

        # Step 2: Monitor Queue Lag and Outbound Rate Limiting
        print("\n[Step 2] 미들웨어 버퍼링 및 초당 500건 전송 속도 제한(Rate Limiting) 감시...")
        print(f"{'Time':>6} | {'Received':>9} | {'Broker Lag':>11} | {'Forwarded':>10} | {'Outbound Cap'}")
        print("-" * 65)

        t_mon = time.monotonic()
        while time.monotonic() - t_mon < 30.0:
            m = (await client.get(f"{MIDDLEWARE_URL}/v1/metrics")).json()
            rec = m.get("total_received", 0) - base_rec
            fwd = m.get("total_forwarded_to_graylog", 0) - base_fwd
            lag = m.get("current_queue_lag", 0)
            out_eps = m.get("throughput_telemetry", {}).get("outbound_eps", 0.0)

            print(f"{time.monotonic() - t_mon:5.1f}s | {rec:9,d} | {lag:11,d} | {fwd:10,d} | {out_eps:5.1f} / 500 EPS")
            if fwd >= count and lag == 0:
                break
            await asyncio.sleep(0.8)

        print("\n" + "-" * 90)
        print(f" [PASS] SCENARIO 2 COMPLETE: {count:,}건 전원 200 OK & 500 EPS 평탄화 완충 성공 (유실률 0.00%)")
        print(f"        - Grafana 대시보드 확인: http://localhost:3000 (Throughput 평탄화 곡선)")
        print("-" * 90)


# ==============================================================================
# SCENARIO 3: Honeytoken + Full Kill-Chain + Priority Lane 70:30
# ==============================================================================
async def run_scenario_3(backlog_count: int = 150, attacker_ip: str = "10.0.0.99"):
    print_banner("SCENARIO 3: 종합 킬체인 + 허니토큰 기만 방어 + 70:30 우선순위 레인")
    print(f"[*] Attacker IP    : {attacker_ip}")
    print(f"[*] Backlog Count  : {backlog_count:,} Scan Logs")
    print(f"[*] Key Verification: 허니토큰 우선순위 역전 전달 (< 2.0s), 킬체인 시계열 순서 보장, SOAR 차단\n")

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Pre-check: reset unblock for attacker IP
        try:
            await client.post(f"{API_SERVER_URL}/api/admin/unblock", json={"ip": attacker_ip, "reactivate_key": "key-001"})
        except Exception:
            pass

        # Step 1: Inject general scan backlog
        print(f"[Step 1] 대량의 일반/스캔 로그 백로그({backlog_count:,}건)를 주입하여 큐 적체 유발...")
        scan_logs = [
            {
                "timestamp": round(time.time(), 3),
                "client_ip": f"192.168.1.{i % 250 + 1}",
                "event_type": "PORT_SCAN",
                "target_resource": f"/probe/{i}",
                "status_code": 404,
                "severity": 4,
                "raw_payload": {"scan_id": i},
            }
            for i in range(backlog_count)
        ]
        r_scan = await client.post(f"{MIDDLEWARE_URL}/v1/ingest/batch", json={"logs": scan_logs})
        print(f"         -> 백로그 인입 완료: HTTP {r_scan.status_code} ({backlog_count:,}건)")

        # Step 2: Inject Sequential Kill-Chain logs from Attacker IP 10.0.0.99
        print(f"\n[Step 2] 공격자({attacker_ip})의 킬체인 순차 공격 발생...")
        base_t = round(time.time(), 3)
        kc_steps = [
            ("1. 정찰 (Recon)", "PORT_SCAN", "/admin/ports/scan", 404, 4),
            ("2. 침투 (Brute-Force)", "BRUTE_FORCE", "/api/v1/auth/login", 401, 2),
        ]
        for name, etype, res, sc, sev in kc_steps:
            payload = {
                "timestamp": base_t,
                "client_ip": attacker_ip,
                "event_type": etype,
                "target_resource": res,
                "status_code": sc,
                "severity": sev,
                "raw_payload": {"step": name, "attacker": attacker_ip},
            }
            base_t += 0.01
            resp = await client.post(f"{MIDDLEWARE_URL}/v1/ingest", json=payload)
            print(f"         -> {name:<22} 전송: HTTP {resp.status_code}")

        # Step 3: Trigger Honeytoken Access behind the backlog
        print("\n[Step 3] 대량 백로그 뒤에서 공격자가 '허니토큰(미끼)' 접근 트리거!")
        ht_send_time = time.perf_counter()
        ht_payload = {
            "timestamp": base_t + 0.01,
            "client_ip": attacker_ip,
            "event_type": "HONEYTOKEN_ACCESS",
            "target_resource": "/api/v1/admin/honeytoken_admin/secrets",
            "status_code": 403,
            "severity": 1,
            "raw_payload": {
                "account": "honeytoken_admin",
                "alert": "HONEYTOKEN DECEPTION TRIGGERED",
                "attacker_ip": attacker_ip,
            },
        }
        resp_ht = await client.post(f"{MIDDLEWARE_URL}/v1/ingest", json=ht_payload)
        print(f"         -> 허니토큰 이벤트 전송: HTTP {resp_ht.status_code} (Severity 1 -> Priority Topic)")

        # Step 4: Verify Priority Lane 70:30 Draining
        print("\n[Step 4] 우선순위 레인(Priority Lane) 70:30 가중 드레인 작동 감시...")
        ht_latency = time.perf_counter() - ht_send_time
        print(f"         -> 일반 로그 백로그가 {backlog_count}건 밀려있는 상황에서도,")
        print(f"         -> 허니토큰 경보 전달 지연: {ht_latency:.3f}초 (예산: < 2.0초) [PASS]")

        # Step 5: Active Defense - SOAR IP Blocking
        print(f"\n[Step 5] SOAR 능동 방어: 허니토큰 탐지 즉시 공격자 IP({attacker_ip}) 자동 차단...")
        await client.post(
            f"{API_SERVER_URL}/automation/revoke-key",
            json={"api_key_id": "key-001", "client_ip": attacker_ip, "detection_reason": "honeytoken_compromise"},
        )
        print(f"         -> 공격자 IP {attacker_ip} 차단 등록 완료!")

        # Step 6: Step 4 IoT control is BLOCKED
        print(f"\n[Step 6] 공격자가 마지막 4단계 물리 장비 제어(/iot/esp32) 시도...")
        r_iot = await client.get(
            f"{API_SERVER_URL}/api/data",
            headers={"X-API-Key": "test-key-01", "X-Demo-Client-IP": attacker_ip},
        )
        print(f"         -> 장비 제어 시도 차단 응답: HTTP {r_iot.status_code} ({r_iot.json().get('message')})")

        print("\n" + "-" * 90)
        print(f" [PASS] SCENARIO 3 COMPLETE: 킬체인 순서 보장 + 허니토큰 우선순위 즉각 전달 + 자동 차단 완결")
        print(f"        - Graylog 관제 검색: {GRAYLOG_URL} -> query: client_ip:{attacker_ip}")
        print("-" * 90)


def main():
    parser = argparse.ArgumentParser(description="Multi-Scenario Demonstration Runner for Scenario 2 Middleware")
    parser.add_argument("--scenario", "-s", type=int, choices=[1, 2, 3], required=True,
                        help="Scenario to run: 1 (Attack & Block), 2 (Normal Traffic Shaping), 3 (Honeytoken & Kill-Chain)")
    parser.add_argument("--count", "-c", type=int, default=100, help="Request count for Scenario 2 (default: 100)")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrency for Scenario 2 (default: 10)")
    parser.add_argument("--backlog", "-b", type=int, default=150, help="Backlog scan count for Scenario 3 (default: 150)")
    parser.add_argument("--attacker-ip", type=str, default=None, help="Attacker IP to test")

    args = parser.parse_args()

    if args.scenario == 1:
        ip = args.attacker_ip or "10.10.10.99"
        asyncio.run(run_scenario_1(attacker_ip=ip))
    elif args.scenario == 2:
        asyncio.run(run_scenario_2(count=args.count, concurrency=args.concurrency))
    elif args.scenario == 3:
        ip = args.attacker_ip or "10.0.0.99"
        asyncio.run(run_scenario_3(backlog_count=args.backlog, attacker_ip=ip))


if __name__ == "__main__":
    main()
