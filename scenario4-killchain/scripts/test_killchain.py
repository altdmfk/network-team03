"""
시나리오4 킬체인 상관분석 테스트 스크립트.
Graylog GELF HTTP 입력으로 공격 단계 로그를 전송해 CRITICAL/WARNING 분기를 재현한다.

사용법:
    python test_killchain.py critical   # 3단계 전부 전송 -> CRITICAL 격상 재현
    python test_killchain.py warning    # 1~2단계만 전송 -> WARNING(오탐 방지) 재현
    python test_killchain.py recon      # 정찰 단계만 단독 전송
"""
import sys
import json
import time
import random
import urllib.request

GRAYLOG_GELF_URL = "http://localhost:12201/gelf"


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


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "critical"
    if mode == "critical":
        run_critical()
    elif mode == "warning":
        run_warning()
    elif mode == "recon":
        run_recon_only()
    else:
        print("사용법: python test_killchain.py [critical|warning|recon]")
        sys.exit(1)
