# 네트워크 팀 프로젝트 3조 (Network Team 03)

본 저장소는 네트워크 팀 프로젝트 3조의 협업 및 통합 코드베이스입니다.

## 프로젝트 모듈 구성

| 모듈 경로 | 담당 기능 및 시나리오 | 상세 문서 |
| :--- | :--- | :--- |
| [`scenario2-middleware/`](./scenario2-middleware/) | 시나리오 2: SOAR 경량 로그 버퍼링 및 트래픽 제어 미들웨어 | [`scenario2-middleware/README.md`](./scenario2-middleware/README.md) |
| `app.py` | 시나리오 3: 유출 API 키 탐지용 Flask API 서버 | [`scenario3-api-key-compromised/`](./scenario3-api-key-compromised/) |

## 시나리오 3 API 서버

API 키와 요청 IP를 검증하고 보안 이벤트를 생성합니다. 비허용 IP 요청은 `403`으로 거부하고, 로그는 Middleware 수집기와 Graylog로 전달합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:MIDDLEWARE_INGEST_URL = "http://127.0.0.1:8000/ingest"
$env:MIDDLEWARE_API_KEY = "<공유된 Middleware 인증키>"
.\.venv\Scripts\python.exe app.py
```

Postman 테스트:

- 정상 요청: `X-API-Key: test-key-01`, `X-Demo-Client-IP: 127.0.0.1` → `200`
- 비허용 IP 요청: 같은 API 키, `X-Demo-Client-IP: 10.10.10.10` → `403`

## 테스트

```powershell
python -m unittest test_app.py
```

시나리오 3의 Graylog 탐지 규칙과 n8n 설정 템플릿은 [`scenario3-api-key-compromised/`](./scenario3-api-key-compromised/)에 있습니다. 실제 인증키와 Discord Webhook 주소는 저장소에 포함하지 않습니다.
