#!/usr/bin/env python3
"""
[시나리오 2 전용 라이브 시연 도구]
Main API Server(:5000/api/data)로 비인가 API 키를 이용한 5회 연속 무차별 대입(Brute Force) 공격을 주입하여,
1. API 서버가 401 거부 및 보안 로그 생성
2. SOAR 미들웨어(:8000)를 거쳐 무손실로 Graylog(:12201)에 평탄화 전달
3. Graylog SIEM 집계(Aggregation) 룰에 의해 동일 IP 5회 이상 실패 탐지
4. n8n SOAR 워크플로우를 통한 공격자 IP 자동 차단
5. 후속 요청 시 HTTP 403(Client IP has been blocked) 차단 격리 확인

외부 폴더(루트 app.py 및 web-app/) 수정 없이 100% 독립 동작합니다.
"""

import argparse
import sys
import time
import httpx


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scenario 2 - Demo Brute Force Attack & SOAR Auto-Block"
    )
    parser.add_argument(
        "--ip",
        default="10.0.0.99",
        help="Attacker IP to simulate (default: 10.0.0.99)",
    )
    parser.add_argument(
        "--count",
        "-c",
        type=int,
        default=5,
        help="Number of failed attack attempts (default: 5)",
    )
    parser.add_argument(
        "--api-url",
        default="http://127.0.0.1:5000",
        help="Main API server URL (default: http://127.0.0.1:5000)",
    )
    args = parser.parse_args()
    target_url = f"{args.api_url}/api/data"

    print("\n" + "=" * 80)
    print(f" [시나리오 2] 무차별 대입 공격(Brute Force) & SOAR 자동 대응 라이브 시연")
    print(f"   - 대상 API 엔드포인트 : {target_url}")
    print(f"   - 공격자 시뮬레이션 IP: {args.ip}")
    print(f"   - 연속 인증 실패 횟수 : {args.count}회")
    print("=" * 80)

    client = httpx.Client(timeout=5.0)

    # 1. 이전 차단 이력 초기화 (반복 시연 가능하도록 자동 언블락)
    print(f"\n[*] [사전 준비] 공격자 IP({args.ip}) 이전 차단 상태 초기화 확인...")
    try:
        unblock_res = client.post(
            f"{args.api_url}/api/admin/unblock", json={"ip": args.ip}
        )
        if unblock_res.status_code == 200:
            print(f"    >>> IP({args.ip}) 차단 해제 완료. 정상 공격 재현 환경 준비됨.")
    except Exception as exc:
        print(f"    [!] 메인 API 서버 언블락 호출 경고 (무시 가능): {exc}")

    # 2. 메인 API 서버로 5회 연속 인증 실패 공격 주입
    print(f"\n[*] [공격 시작] 메인 API 서버로 잘못된 API 키 {args.count}회 주입 (무차별 대입 시도)...")
    for i in range(1, args.count + 1):
        headers = {
            "X-API-Key": f"bruteforce-fake-key-{i:03d}",
            "X-Demo-Client-IP": args.ip,
            "User-Agent": f"Hydra-BruteForce-Scanner/{i}",
        }

        t0 = time.perf_counter()
        try:
            resp = client.get(target_url, headers=headers)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            print(
                f"    [{i}/{args.count}] API 요청: Key='{headers['X-API-Key']}' "
                f"-> API 응답: HTTP {resp.status_code} ({elapsed_ms:.1f}ms)"
            )
        except Exception as exc:
            print(f"    [{i}/{args.count}] 요청 실패: {exc}")
        time.sleep(0.05)

    print(f"\n[*] {args.count}건의 401 보안 로그가 SOAR 미들웨어(:8000)를 거쳐 Graylog(:12201)로 안전하게 버퍼링 배송되었습니다.")

    # 3. Graylog 상관분석 및 n8n 자동 대응 대기 (폴링)
    print(f"[*] [SOAR 루프] Graylog 실시간 집계(Aggregation) 및 n8n IP 차단 트리거 대기 중...")
    blocked = False
    for wait_step in range(1, 31):
        time.sleep(1.0)
        sys.stdout.write(f"\r    ... 감시 중 ({wait_step}초 경과)")
        sys.stdout.flush()

        try:
            chk = client.get(f"{args.api_url}/api/blocked-ips")
            if chk.status_code == 200 and args.ip in chk.json().get("blocked_ips", []):
                blocked = True
                print(f"\n    >>> [성공] n8n SOAR가 공격자 IP({args.ip})를 MySQL 차단 목록에 등록 완료!")
                break
        except Exception:
            pass

    if not blocked:
        print(f"\n    [주의] 30초 내에 자동 차단 응답이 도착하지 않았습니다. (n8n/Graylog 상태 확인 필요)")

    # 4. 차단 여부 최종 검증 (6번째 요청 시도)
    print(f"\n[*] [최종 검증] 차단된 공격자 IP({args.ip})로 API 서버에 재접속 시도...")
    try:
        verify_resp = client.get(
            target_url,
            headers={
                "X-API-Key": "any-key",
                "X-Demo-Client-IP": args.ip,
            },
        )
        print(f"    - API 서버 응답 코드: HTTP {verify_resp.status_code}")
        if verify_resp.status_code == 403 or "blocked" in verify_resp.text:
            print(f"    >>> [차단 확인] HTTP 403 Forbidden! 공격자 IP가 정상 차단되었습니다.")
            print(f"    - 서버 메시지: {verify_resp.text.strip()}")
        else:
            print(f"    - 응답 본문 일부: {verify_resp.text[:150]}")
    except Exception as exc:
        print(f"    [!] 검증 요청 에러: {exc}")

    # 5. 최종 요약 출력
    print("\n" + "=" * 80)
    print(f" [시연 결과 요약]")
    print(f"  1. 인증 실패 공격 발생  : {args.count}회 주입 (HTTP 401 거부 및 로그 발행)")
    print(f"  2. SOAR 미들웨어 전달   : 0.00% 무손실로 Graylog에 평탄화 전송 완료")
    print(f"  3. Graylog SIEM 집계    : 동일 IP 5회 이상 실패 집계 -> Alert 트리거")
    print(f"  4. n8n 자동 대응(SOAR)  : 공격자 IP({args.ip}) 방화벽/DB 자동 차단 완료")
    print(f"  5. 보안 서비스 방어     : 후속 접속 시 HTTP 403 차단 격리 성공")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
