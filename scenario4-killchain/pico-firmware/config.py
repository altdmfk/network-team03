# Wi-Fi 및 보안 설정 - 실제 값으로 채워서 Pico W에 함께 업로드

WIFI_SSID = "YOUR_WIFI_SSID"
WIFI_PASSWORD = "YOUR_WIFI_PASSWORD"

# n8n -> Pico W 요청 시 헤더(X-Auth-Token)로 넘겨줄 공유 토큰
# lockdown / unlock 호출은 이 토큰이 맞아야 처리됨
AUTH_TOKEN = "CHANGE_ME_SHARED_SECRET"

# 외부 빨간 LED를 쓸 경우 연결한 GPIO 번호 (안 쓰면 None -> 온보드 LED만 사용)
EXTERNAL_LED_PIN = 15