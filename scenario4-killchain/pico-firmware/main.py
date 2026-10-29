import network
import socket
import time
import json
from machine import Pin

import config

led_blue = Pin(config.LED_BLUE_PIN, Pin.OUT)
led_green = Pin(config.LED_GREEN_PIN, Pin.OUT)
led_yellow = Pin(config.LED_YELLOW_PIN, Pin.OUT)
led_red = Pin(config.LED_RED_PIN, Pin.OUT)
buzzer = Pin(config.BUZZER_PIN, Pin.OUT)

ALL_LEDS = (led_blue, led_green, led_yellow, led_red)

# status: "booting"(파랑) / "normal"(초록) / "warning"(노랑, 1~2단계 탐지) / "locked"(빨강, 킬체인 확정)
state = {"status": "booting"}


def leds_off():
    for led in ALL_LEDS:
        led.value(0)


def show_booting():
    leds_off()
    led_blue.value(1)


def show_normal():
    leds_off()
    led_green.value(1)


def show_warning():
    leds_off()
    led_yellow.value(1)


def show_locked():
    leds_off()
    led_red.value(1)


def apply_status(status):
    state["status"] = status
    if status == "booting":
        show_booting()
        buzzer.value(0)
    elif status == "normal":
        show_normal()
        buzzer.value(0)
    elif status == "warning":
        show_warning()
        buzzer.value(0)
    elif status == "locked":
        show_locked()
        buzzer.value(1)


def blink_once():
    # device/control 정상 처리 시 파랑을 짧게 깜빡여서 명령 수신을 눈으로 확인 (상태 LED는 그대로 유지)
    led_blue.value(1)
    time.sleep(0.15)
    led_blue.value(0)


def apply_lockdown():
    # 깜빡임 3회 + 부저 3번 울림 후 고정 빨강 + 경보음 - Lockdown 적용을 시각/청각으로 구분
    for _ in range(3):
        leds_off()
        buzzer.value(0)
        time.sleep(0.15)
        led_red.value(1)
        buzzer.value(1)
        time.sleep(0.15)
    apply_status("locked")


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
        return json_response(200, "OK", {"device": "esp32-c3-iot-01", "status": state["status"]})

    # IoT 제어 API - 정상 운영 명령(리부트/센서값조작/상태변경 등)이 들어오는 지점
    # Lockdown 상태에서는 전부 거부(423)
    if method == "POST" and path == "/device/control":
        if state["status"] == "locked":
            return json_response(423, "Locked", {"error": "device is locked", "status": "locked"})
        try:
            cmd = json.loads(body) if body else {}
        except Exception:
            cmd = {}
        print("device/control 수신:", cmd)
        blink_once()
        return json_response(200, "OK", {"result": "executed", "command": cmd.get("command", "unknown")})

    # n8n이 킬체인 1~2단계만 탐지했을 때 호출 - LED 노랑(경고)으로 전환
    if method == "POST" and path == "/warning":
        if not is_authorized(headers):
            return json_response(401, "Unauthorized", {"error": "invalid token"})
        if state["status"] != "locked":
            apply_status("warning")
        print("WARNING 적용됨 (1~2단계 탐지)")
        return json_response(200, "OK", {"status": state["status"]})

    # n8n이 킬체인 확정(3단계 모두 충족) 시 호출하는 엔드포인트
    if method == "POST" and path == "/lockdown":
        if not is_authorized(headers):
            return json_response(401, "Unauthorized", {"error": "invalid token"})
        apply_lockdown()
        print("LOCKDOWN 적용됨")
        return json_response(200, "OK", {"status": state["status"]})

    # 조장(본인) 수동 승인 시에만 호출하는 해제 엔드포인트
    if method == "POST" and path == "/unlock":
        if not is_authorized(headers):
            return json_response(401, "Unauthorized", {"error": "invalid token"})
        apply_status("normal")
        print("Lockdown 해제됨 (수동 승인)")
        return json_response(200, "OK", {"status": state["status"]})

    return json_response(404, "Not Found", {"error": "unknown route"})


def main():
    apply_status("booting")
    ip = connect_wifi()
    apply_status("normal")

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
