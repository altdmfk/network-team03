"""
발표용 라이브 시연 스크립트 — 정찰 -> 침투 -> 물리타격 3단계를
실제 API 서버·Nmap으로 재현하면서, 동시에 Graylog 상관분석 조건에
필요한 표준 이벤트(event_type)를 전송해 n8n 분기가 확실히 터지도록 한다.

왜 실제 공격 + 표준 이벤트를 같이 보내나:
- 1,2단계는 진짜 API 서버(시나리오3)를 때리는 실제 공격이라 시연 설득력이 있음
- 근데 팀마다 로그 필드명이 아직 완전히 안 맞아서, 실제 로그만으로는
  Graylog 상관분석(event_type 필드 의존)이 라이브 중 안 터질 위험이 있음
- 그래서 실제 요청 "직후"에 표준 규격 이벤트를 Graylog GELF로 직접 보내
  시연이 실패하지 않게 이중 안전장치를 둠(팀 필드 규격이 맞춰지면 이 보조 전송은 빼도 됨)

사용법:
    python demo_killchain_live.py                 # 전체 3단계(CRITICAL까지)
    python demo_killchain_live.py --stage warning  # 1~2단계만(WARNING 재현)

필요한 값 (환경변수 또는 아래 기본값 수정):
    API_SERVER_URL   예: http://127.0.0.1:5000   (김라연 Flask 서버)
    LEAKED_API_KEY    예: test-key-01             (README 공개 테스트 키)
    ATTACKER_IP       비허용 IP로 위장할 값 (README 기본: 10.10.10.10)
    ESP32_URL        예: http://<ESP32_IP>        (하드웨어 도착 후 채우기, 없으면 생략됨)
"""
import argparse
import os
import random
import subprocess
import time
import urllib.request
import json

API_SERVER_URL = os.environ.get("API_SERVER_URL", "http://127.0.0.1:5000")
LEAKED_API_KEY = os.environ.get("LEAKED_API_KEY", "test-key-01")
ATTACKER_IP = os.environ.get("ATTACKER_IP", "10.10.10.10")
ESP32_URL = os.environ.get("ESP32_URL", "")  # 비어있으면 3단계는 건너뜀
GRAYLOG_GELF_URL = os.environ.get("GRAYLOG_GELF_URL", "http://localhost:12201/gelf")


def send_gelf(event_type, client_ip, extra=None):
    payload = {
        "version": "1.1", "host": "demo-live", "short_message": event_type,
        "_event_type": event_type, "_client_ip": client_ip,
    }
    if extra:
        payload.update({"_" + k: v for k, v in extra.items()})
    req = urllib.request.Request(
        GRAYLOG_GELF_URL, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(f"  [Graylog 표준 이벤트] {event_type} -> HTTP {resp.status}")


def http_get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        print(f"  (요청 실패: {e})")
        return None


def stage1_recon(client_ip):
    print("\n[1단계: 정찰] Nmap으로 API 서버 포트 스캔")
    host = API_SERVER_URL.split("//", 1)[1].split(":")[0].split("/")[0]
    try:
        out = subprocess.run(
            ["nmap", "-F", host], capture_output=True, text=True, timeout=30,
        )
        print(out.stdout[-600:] if out.stdout else "(nmap 출력 없음)")
    except FileNotFoundError:
        print("  nmap이 설치 안 되어 있어 생략, 404 다섯 번으로 대체 재현")
        for i in range(5):
            http_get(f"{API_SERVER_URL}/notfound-{i}")
    except Exception as e:
        print(f"  nmap 실행 실패({e}), 표준 이벤트만 전송")
    send_gelf("recon_scan", client_ip, {"status_code": 404, "target_resource": "/api/data"})


def stage2_leaked_key(client_ip):
    print("\n[2단계: 침투] 유출된 API 키를 비허용 IP로 재사용")
    status = http_get(
        f"{API_SERVER_URL}/api/data",
        headers={"X-API-Key": LEAKED_API_KEY, "X-Demo-Client-IP": client_ip},
    )
    print(f"  실제 API 서버 응답: HTTP {status} (403이면 서버가 정상 차단한 것)")
    send_gelf("api_key_compromised", client_ip, {"status_code": status or 403, "target_resource": "/api/data"})


def stage3_device_control(client_ip):
    print("\n[3단계: 물리 타격] IoT 제어 API에 비정상 명령 전송")
    if ESP32_URL:
        status = http_get(f"{ESP32_URL}/device/control")
        print(f"  실제 ESP32 응답: HTTP {status}")
    else:
        print("  ESP32_URL 환경변수 없음 -> 실물 호출 생략, 표준 이벤트만 전송")
    send_gelf("device_control", client_ip, {"status_code": 200, "target_resource": "/device/control"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=["critical", "warning"], default="critical")
    args = parser.parse_args()

    ip = ATTACKER_IP
    print(f"=== 라이브 시연 시작 (client_ip={ip}, 모드={args.stage}) ===")

    stage1_recon(ip)
    time.sleep(1)
    stage2_leaked_key(ip)

    if args.stage == "critical":
        time.sleep(1)
        stage3_device_control(ip)
        print("\n완료. CRITICAL 격상 기대 — pfSense 차단 + ESP32 Lockdown + 메신저 알림 확인")
    else:
        print("\n완료. 3단계 생략 — WARNING(LED 노랑)만 뜨는지 확인 (오탐 방지 검증)")
