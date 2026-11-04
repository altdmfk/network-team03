"""
시나리오3 킬체인 상관분석 테스트 스크립트.
Graylog GELF HTTP 입력으로 공격 단계 로그를 전송해 CRITICAL/WARNING 분기를 재현한다.

사용법:
    python test_killchain.py critical   # 3단계 전부 전송 -> CRITICAL 격상 재현
    python test_killchain.py warning    # 1~2단계만 전송 -> WARNING(오탐 방지) 재현
    python test_killchain.py recon      # 정찰 단계만 단독 전송
    python test_killchain.py both       # warning -> critical 순서로 둘 다 재현
    python test_killchain.py device     # device_control 1건만 전송 (통합테스트용, 3번째 단계 채우기)

다른 PC에서 실행할 때 (Graylog가 이 PC에 없을 때):
    환경변수 GRAYLOG_GELF_URL을 Graylog가 떠있는 PC의 실제 IP로 지정한다.
    PowerShell:  $env:GRAYLOG_GELF_URL = "http://<내 노트북 IP>:12201/gelf"; python test_killchain.py critical

시나리오1(미들웨어) 공격 IP와 맞춰서 통합테스트할 때:
    환경변수 TARGET_IP를 지정하면 그 IP로 전송한다 (안 주면 랜덤 IP 생성).
    PowerShell:  $env:TARGET_IP = "10.0.0.99"; python test_killchain.py device
"""
import os
import sys
import json
import time
import random
import urllib.request

GRAYLOG_GELF_URL = os.environ.get("GRAYLOG_GELF_URL", "http://localhost:12201/gelf")


def send(event_type, client_ip, extra=None):
    payload = {
        "version": "1.1",
        "host": "test-killchain",
        "short_message": event_type,
        "_event_type": event_type,
        "_client_ip": client_ip,
    }
    if extra:
        payload.update({"_" + k: v for k, v in extra.items()})

    req = urllib.request.Request(
        GRAYLOG_GELF_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(f"  {event_type:<22} -> HTTP {resp.status}  (client_ip={client_ip})")


def random_ip():
    # 매 실행마다 다른 IP를 써야 Graylog 집계 윈도우가 이전 테스트와 안 섞임
    return f"203.0.113.{random.randint(2, 254)}"


def target_ip():
    # TARGET_IP가 지정되면 그 IP를 쓴다 (다른 시나리오의 공격 IP와 맞춰 통합테스트할 때)
    return os.environ.get("TARGET_IP") or random_ip()


def run_critical():
    ip = random_ip()
    print(f"[CRITICAL 재현] 3단계 전부 전송 (client_ip={ip})")
    send("recon_scan", ip, {"status_code": 404, "target_resource": "/api/data"})
    send("api_key_compromised", ip, {"status_code": 403, "target_resource": "/api/v1/auth"})
    send("device_control", ip, {"status_code": 200, "target_resource": "/device/control"})
    print("완료. Graylog가 최대 1분 내 집계 돌려서 n8n Webhook을 CRITICAL로 호출함.")


def run_warning():
    ip = random_ip()
    print(f"[WARNING 재현] 1~2단계만 전송, CRITICAL로 격상되면 안 됨 (client_ip={ip})")
    send("recon_scan", ip, {"status_code": 404, "target_resource": "/api/data"})
    send("api_key_compromised", ip, {"status_code": 403, "target_resource": "/api/v1/auth"})
    print("완료. device_control 없이 2단계만 보냈으니 CRITICAL이 아니라 WARNING만 떠야 정상(오탐 방지 검증).")


def run_recon_only():
    ip = random_ip()
    print(f"[단독 정찰] recon_scan만 1건 전송 (client_ip={ip}) - WARNING도 아직 안 떠야 함(1건은 임계치 미만일 수 있음)")
    send("recon_scan", ip, {"status_code": 404, "target_resource": "/api/data"})


def run_device_only():
    ip = target_ip()
    print(f"[device_control 단독] 1건 전송 (client_ip={ip})")
    send("device_control", ip, {"status_code": 200, "target_resource": "/device/control"})
    print("완료. 같은 IP로 다른 시나리오 이벤트가 이미 2종 이상 들어와 있었다면, 이걸로 3종 채워져서 CRITICAL이 뜰 수 있음.")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "critical"
    print(f"GELF 전송 대상: {GRAYLOG_GELF_URL}")
    if mode == "critical":
        run_critical()
    elif mode == "warning":
        run_warning()
    elif mode == "recon":
        run_recon_only()
    elif mode == "both":
        run_warning()
        print()
        time.sleep(2)
        run_critical()
    elif mode == "device":
        run_device_only()
    else:
        print("사용법: python test_killchain.py [critical|warning|recon|both|device]")
        sys.exit(1)
