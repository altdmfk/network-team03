# 시나리오 3 - 유출 API 키 탐지

시나리오 3 전용 Graylog 탐지 기준과 n8n 자동 대응 워크플로입니다.

## 처리 흐름

```text
Flask API 서버
  -> Middleware /v1/ingest
  -> Graylog/Wazuh 탐지
  -> 시나리오 3 전용 n8n Webhook
  -> API 키 폐기·재발급, 공격 IP 차단, 인시던트 생성
```

## Graylog

`graylog/scenario3_api_key_compromised_rule.json`의 조건을 시나리오 3 이벤트 정의에 적용합니다.

- 탐지 대상: `api_key_compromised`
- 기준: `status_code=403`인 비허용 IP 사용
- 시연 기준: 1건 발생 즉시 탐지
- n8n 전달 필드: `event_type`, `client_ip`, `timestamp`, `target_resource`, `status_code`, `raw_payload`

Middleware가 `event_type`을 대문자로 정규화할 수 있으므로 Graylog 검색 조건은
`API_KEY_COMPROMISED`와 `api_key_compromised`를 모두 허용합니다.

## n8n

`n8n/scenario3_api_key_response_workflow.json`을 시나리오 3 전용 워크플로로 가져옵니다.

- Webhook: `POST /webhook/scenario3-api-key-compromised`
- API 서버 호출: `POST /automation/revoke-key`
- API 서버 주소는 n8n 환경변수 `API_SERVER_URL`로 지정할 수 있습니다.
- Docker의 n8n에서 호스트 PC의 Flask 서버를 호출할 때는 기본값으로
  `http://host.docker.internal:5000`을 사용합니다.

## 현재 Middleware 테스트 주소

팀 Middleware Docker 설정 기준으로 API 서버는 다음 주소로 로그를 보냅니다.

- Ingest: `POST http://localhost:8000/ingest`
- 인증: `X-API-Key` 헤더에 팀에서 공유한 ingest 키 사용
- Metrics: `GET http://localhost:8000/metrics`
- Mock Graylog 로그: `GET http://localhost:12201/logs`

실제 ingest 키는 코드나 Git에 저장하지 말고 실행 환경의 `MIDDLEWARE_API_KEY`로 지정합니다.

Middleware 주소와 인증키는 별도 설정이며, 이 폴더의 n8n 워크플로에는 저장하지 않습니다.
