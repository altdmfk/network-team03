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

## API 키 식별자 안내

인증에 사용하는 실제 API 키와 로그에 남기는 `api_key_id`를 분리합니다.
실제 인증값은 서버에서만 사용하고, 로그·Graylog·n8n에는 키 식별자만 전달합니다.
현재 데모에서는 인증값 `test-key-01`과 식별자 `key-001`을 사용합니다.

현재 Docker Middleware 실행 주소는 `http://127.0.0.1:8000/ingest`이며,
실제 Middleware 인증키는 환경변수로 설정합니다. 실제 인증키와 Discord Webhook 주소는 저장소에 포함하지 않습니다.

시나리오 3의 Graylog 탐지 규칙과 n8n 설정 템플릿은
[`scenario3-api-key-compromised/`](./scenario3-api-key-compromised/)에 있습니다.

## EngineSquare 공통 웹앱

`web-app/`은 메인 화면, 회원가입·로그인, 게시판, 보안 관제 대시보드와 관리자 페이지를 제공합니다.

- 대시보드: 인시던트 티켓·최근 이벤트 조회, 상태·허용/거부 필터, 5건 단위 페이지 이동, 티켓 종료
- 관리자: API 키 발급·폐기·교체 키 확인, 차단 IP 조회·차단 해제, 회원 등급 관리
- 데이터 저장: Docker MySQL을 API 서버와 공유하며 키·차단 상태 변경은 서버 재시작 없이 다음 요청부터 반영
- 화면 구성: 화면 너비에 맞춰 표와 긴 문구를 조정하는 반응형 레이아웃

MySQL 컨테이너 `mysql-server`를 먼저 실행하고, 프로젝트 루트에서 웹앱을 시작합니다.
API 서버는 별도 창에서 실행합니다.

```powershell
python -m pip install -r requirements.txt -r web-app/requirements.txt
python web-app/app.py
```

웹앱 접속 주소는 `http://127.0.0.1:5001/`입니다.
DB 설정, 권한과 실행 방법은 [web-app README](./web-app/README.md),
시나리오 3의 Graylog·n8n·Wazuh 구성은 [시나리오 3 README](./scenario3-api-key-compromised/README.md)를 참고합니다.
