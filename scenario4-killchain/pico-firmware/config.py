# Wi-Fi 및 보안 설정 - 실제 값으로 채워서 ESP32-C3 SuperMini에 함께 업로드

WIFI_SSID = "YOUR_WIFI_SSID"
WIFI_PASSWORD = "YOUR_WIFI_PASSWORD"

# n8n -> ESP32-C3 요청 시 헤더(X-Auth-Token)로 넘겨줄 공유 토큰
# warning / lockdown / unlock 호출은 이 토큰이 맞아야 처리됨
AUTH_TOKEN = "CHANGE_ME_SHARED_SECRET"

# 상태 LED 4색 전용 연결 (각자 220Ω 저항과 함께 GND로)
# 파랑: 부팅/Wi-Fi 연결 중 / 초록: 정상 / 노랑: 경고(1~2단계 탐지) / 빨강: Lockdown(CRITICAL)
LED_BLUE_PIN = 2
LED_GREEN_PIN = 3
LED_YELLOW_PIN = 5
LED_RED_PIN = 6

# 액티브 부저(SMG-A, 3.3~5V) 연결한 GPIO 번호
# Lockdown(CRITICAL) 상태일 때만 경보음을 울림. 해제되면 자동으로 꺼짐
BUZZER_PIN = 4
