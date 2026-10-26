# EngineSquare 메인 API 서버

시나리오 3의 유출 API 키 탐지를 시작점으로 사용하는 Flask API 서버입니다.
API 키와 요청 IP를 검증하고, 고정된 JSON 보안 이벤트를 생성해 로컬 로그와
Middleware 수집기로 전달합니다.

## 실행

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

## 기본 테스트

```powershell
.\.venv\Scripts\python.exe -m unittest test_app.py
```

## Postman 확인

- 상태 확인: `GET http://127.0.0.1:5000/health`
- 보호 API: `GET http://127.0.0.1:5000/api/data`
- 정상 요청 헤더: `X-API-Key: test-key-01`
- 비허용 IP 재현 헤더: `X-Demo-Client-IP: 10.10.10.10`
- 이벤트 확인: `GET http://127.0.0.1:5000/api/security-events`
- 인시던트 확인: `GET http://127.0.0.1:5000/api/incidents`
- 차단 IP 확인: `GET http://127.0.0.1:5000/api/blocked-ips`

Graylog/Wazuh 탐지 후 n8n 대응을 시연할 때는 다음 Webhook을 사용합니다.

`POST http://127.0.0.1:5000/automation/revoke-key`

```json
{
  "api_key_id": "test-key-01",
  "client_ip": "10.10.10.10",
  "detection_reason": "not_allowed_ip"
}
```

## Middleware 연결

Middleware 수집기 주소를 설정하면 API 서버가 생성한 각 이벤트를 `POST`로 전달합니다.
설정하지 않으면 `security_events.jsonl`에 저장하고 로컬 테스트를 계속할 수 있습니다.

```powershell
$env:MIDDLEWARE_INGEST_URL = "http://127.0.0.1:8000/v1/ingest"
.\.venv\Scripts\python.exe app.py
```

이벤트의 고정 필드는 `timestamp`, `event_type`, `api_key_id`, `token_id`,
`client_ip`, `target_resource`, `status_code`이며, 상황에 따라 `user_agent`,
`detection_reason`, `incident_id`, `action`, `status`가 추가됩니다.

## 시나리오 3 추가 안내

인증에 사용하는 실제 API 키와 로그에 남기는 `api_key_id`를 분리합니다.
실제 인증값은 서버에서만 사용하고, 로그·Graylog·n8n에는 키 식별자만 전달합니다.
현재 데모에서는 인증값 `test-key-01`과 식별자 `key-001`을 사용합니다.

현재 Docker Middleware 실행 주소는 `http://127.0.0.1:8000/ingest`이며,
실제 Middleware 인증키는 환경변수로 설정합니다. 실제 인증키와 Discord Webhook 주소는 저장소에 포함하지 않습니다.

시나리오 3의 Graylog 탐지 규칙과 n8n 설정 템플릿은
[`scenario3-api-key-compromised/`](./scenario3-api-key-compromised/)에 있습니다.
