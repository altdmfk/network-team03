import network
import socket
import time
import json
from machine import Pin

import config

onboard_led = Pin("LED", Pin.OUT)
external_led = Pin(config.EXTERNAL_LED_PIN, Pin.OUT) if config.EXTERNAL_LED_PIN is not None else None

state = {"locked": False}


def set_leds(locked):
    onboard_led.value(1 if locked else 0)
    if external_led is not None:
        external_led.value(1 if locked else 0)


def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect(config.WIFI_SSID, config.WIFI_PASSWORD)

    attempts = 0
    while not wlan.isconnected() and attempts < 20:
        print("Wi-Fi 연결 중...")
        time.sleep(1)
        attempts += 1

    if not wlan.isconnected():
        raise RuntimeError("Wi-Fi 연결 실패")

    ip = wlan.ifconfig()[0]
    print("Wi-Fi 연결됨:", ip)
    return ip


def json_response(status_code, status_text, body):
    payload = json.dumps(body)
    return (
        "HTTP/1.1 {} {}\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{}"
    ).format(status_code, status_text, len(payload), payload)


def parse_request(request_text):
    try:
        lines = request_text.split("\r\n")
        method, path, _ = lines[0].split(" ")
        body = request_text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in request_text else ""
        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.lower()] = v
        return method, path, headers, body
    except Exception:
        return None, None, {}, ""


def is_authorized(headers):
    return headers.get("x-auth-token") == config.AUTH_TOKEN


def handle_request(method, path, headers, body):
    # 상태 조회 - 인증 불필요
    if method == "GET" and path == "/":
        return json_response(200, "OK", {"device": "pico-w-iot-01", "locked": state["locked"]})

    # IoT 제어 API - 정상 운영 명령(리부트/센서값조작/상태변경 등)이 들어오는 지점
    # Lockdown 상태에서는 전부 거부
    if method == "POST" and path == "/device/control":
        if state["locked"]:
            return json_response(423, "Locked", {"error": "device is locked", "locked": True})
        try:
            cmd = json.loads(body) if body else {}
        except Exception:
            cmd = {}
        print("device/control 수신:", cmd)
        return json_response(200, "OK", {"result": "executed", "command": cmd.get("command", "unknown")})

    # n8n이 킬체인 확정 시 호출하는 엔드포인트
    if method == "POST" and path == "/lockdown":
        if not is_authorized(headers):
            return json_response(401, "Unauthorized", {"error": "invalid token"})
        state["locked"] = True
        set_leds(True)
        print("LOCKDOWN 적용됨")
        return json_response(200, "OK", {"locked": True})

    # 조장(본인) 수동 승인 시에만 호출하는 해제 엔드포인트
    if method == "POST" and path == "/unlock":
        if not is_authorized(headers):
            return json_response(401, "Unauthorized", {"error": "invalid token"})
        state["locked"] = False
        set_leds(False)
        print("Lockdown 해제됨 (수동 승인)")
        return json_response(200, "OK", {"locked": False})

    return json_response(404, "Not Found", {"error": "unknown route"})


def main():
    set_leds(False)
    ip = connect_wifi()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, 80))
    s.listen(5)
    print("서버 시작:", ip, ":80")

    while True:
        conn = None
        try:
            conn, addr = s.accept()
            request = conn.recv(2048).decode("utf-8")
            if not request:
                conn.close()
                continue

            method, path, headers, body = parse_request(request)
            response = handle_request(method, path, headers, body)
            conn.send(response.encode("utf-8"))
        except Exception as e:
            print("요청 처리 오류:", e)
        finally:
            if conn is not None:
                conn.close()


if __name__ == "__main__":
    main()