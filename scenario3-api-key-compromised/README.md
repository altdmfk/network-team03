# 시나리오 3 - 유출 API 키 탐지

시나리오 3 전용 Graylog 탐지 기준, n8n 자동 대응 워크플로와 Wazuh 규칙·수집 방법입니다.

## 처리 흐름

```text
Flask API 서버
  -> Middleware /ingest
  -> Graylog 탐지
  -> 시나리오 3 전용 n8n Webhook
  -> API 키 폐기·재발급, 공격 IP 차단, 인시던트 생성
```

Wazuh는 API의 원본 JSON 로그를 별도 수집·분석합니다. 아래 Wazuh 수집기를 사용하며,
현재 구성에서 Wazuh 경보가 n8n을 직접 호출하지는 않습니다.

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

## Wazuh 탐지

Wazuh 4.9의 JSON 디코더와 기본 부모 규칙 86600을 사용합니다.
별도 파일 `wazuh/scenario3_rules.xml`에 아래 규칙을 정의하며 다른 시나리오 규칙은 변경하지 않습니다.

조건: event_type=api_key_compromised, detection_reason=not_allowed_ip, status_code=403.
- 100310 (레벨 10): 비허용 IP의 API 키 사용, 403
- 100311 (레벨 3): 정상 API 요청 허용, 200
- 100312 (레벨 3): 자동 대응 완료, 200

### 수집 설정

Wazuh manager의 ossec.conf에 다음 블록을 추가합니다. 기존 설정은 보존합니다.

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/enginesquare-scenario3.jsonl</location>
  </localfile>
</ossec_config>
```

규칙은 /var/ossec/etc/rules/scenario3_rules.xml에 복사합니다.
로그 파일을 생성하고 analysisd/logcollector 설정 검사 후 manager를 재시작합니다.
컨테이너를 삭제·재생성할 경우 설정과 로그 경로의 볼륨 영속성을 별도로 확인해야 합니다.

### 새 요청 수집

프로젝트 루트에서 별도 PowerShell 창으로 실행합니다.

```powershell
python scenario3-api-key-compromised/wazuh/forward_api_logs.py
```

API 서버가 생성한 새 로그만 전달합니다. 이 창이 열려 있어야 수집이 이어집니다.
기존 Graylog/n8n 파이프라인은 유지하며 별도의 자동 대응은 추가하지 않습니다.

### 기존 증적 로그 재처리

INC-API-005의 2026-10-29 11:46:07 KST 원본 로그로 규칙 매칭과 실제 alerts.json 경보 생성을 확인했습니다.
재처리 데이터에는 evidence_mode=historical_replay와 original_event_timestamp를 표시합니다.
Wazuh 경보 생성 시각은 재처리 시각이고 공격 발생 시각은 data.timestamp입니다.
이를 당시 Wazuh가 실시간 탐지한 증거로 표현하면 안 됩니다.
비교용 3건은 `data.evidence_batch:"INC-API-005-comparison"`으로 조회합니다.
원본 한국 시각은 `data.original_time_kst`, 원본 UTC 시각은 `data.original_event_timestamp`입니다.
정상 요청 11:44:21 → 공격 거부 11:46:07 → 대응 완료 11:46:22 (2026-10-29 KST) 순서입니다.
대시보드에서 rule.id:100310 및 data.incident_id:INC-API-005로 검색하고 시간 범위는 재처리 시각을 포함합니다.

공식 참고: https://documentation.wazuh.com/current/user-manual/ruleset/testing.html
