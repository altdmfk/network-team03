# Wi-Fi 및 보안 설정 - 실제 값으로 채워서 ESP32-C3 SuperMini에 함께 업로드

WIFI_SSID = "YOUR_WIFI_SSID"
WIFI_PASSWORD = "YOUR_WIFI_PASSWORD"

# n8n -> ESP32-C3 요청 시 헤더(X-Auth-Token)로 넘겨줄 공유 토큰
# warning / lockdown / unlock 호출은 이 토큰이 맞아야 처리됨
AUTH_TOKEN = "CHANGE_ME_SHARED_SECRET"

# 상태 LED (적색/녹색) 연결한 GPIO 번호
# 정상: 초록만 켬 / 경고(1~2단계 탐지): 적+녹 동시(= 노랑으로 보임) / Lockdown: 적색만
LED_RED_PIN = 2
LED_GREEN_PIN = 3
