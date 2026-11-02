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

## 재현 순서

아래는 Windows 호스트에 API·웹앱·MySQL을 실행하고, WSL Kali에서 비허용 IP 요청을 보내는 실습 기준입니다.
다른 PC를 사용한다면 `localhost` 대신 해당 서버 PC의 IP를 사용합니다.
Graylog 이벤트 정의와 n8n 워크플로는 아래 상세 설정에 따라 미리 적용·활성화해야 합니다.

### 1. 서비스와 서버 실행

- Docker Desktop을 켜고 MySQL(`mysql-server`), 팀 Middleware 수집기·전송기,
  Graylog와 해당 MongoDB·OpenSearch, n8n을 실행합니다.
- Wazuh도 확인하려면 manager·indexer·dashboard를 실행하고 아래 Wazuh 수집 설정을 먼저 적용합니다.
- 프로젝트 루트의 `.env.example`을 `.env`로 복사해 실제 `MIDDLEWARE_API_KEY`를 입력합니다.
  기존 `.env`가 있다면 덮어쓰지 않습니다. 같은 PC의 Middleware 주소는 `http://localhost:8000/ingest`입니다.
  실제 키는 Git이나 캡처에 포함하지 않습니다.

```powershell
cd D:\KRY\Teamproject\network-team03
python -m pip install -r requirements.txt -r web-app/requirements.txt
.\start-enginesquare.ps1
```

다른 위치에 저장했다면 `cd` 경로를 바꿉니다. 이미 실행 중인 5000·5001 서버는 먼저 종료합니다.
실행 창은 켜둡니다. Enter를 누르면 두 서버가 종료됩니다.
`http://127.0.0.1:5000/health`에서 `{"status":"ok"}`를 확인합니다.
오류가 나면 프로젝트 루트 `.runtime-logs/`의 API·웹앱 로그를 확인합니다.

Wazuh도 실시간 확인하려면 **정상·공격 요청을 보내기 전에** 프로젝트 루트의 별도 PowerShell 창에서
아래 수집기를 실행해 둡니다. 규칙과 수집 설정은 아래 Wazuh 절을 참고합니다.

```powershell
python scenario3-api-key-compromised/wazuh/forward_api_logs.py
```

### 2. Kali IP 확인 및 실습용 키 발급

PowerShell의 별도 창에서 Kali를 엽니다.

```powershell
wsl -d kali-linux -u root
```

Kali에서 Windows 호스트 주소와 실제 출발지 IP를 확인합니다. IP는 실행 환경에 따라 바뀝니다.

```bash
GW=$(ip route show default | awk '{print $3; exit}')
ip route get "$GW"
curl -i --connect-timeout 5 "http://$GW:5000/health"
```

`src` 뒤의 주소가 Kali 출발지 IP입니다. 기존에 차단돼 있다면 관리자에서 해당 IP의 차단을 해제합니다.
관리자 계정으로 `http://127.0.0.1:5001/admin`에 접속해 실습용 API 키를 발급합니다.
허용 IP는 **127.0.0.1만 지정**하고 Kali IP는 넣지 않습니다.
팝업의 `es_...` 원본 키를 보관합니다. `key-...` 식별자는 인증에 사용하는 값이 아닙니다.

### 3. 정상 요청 확인 (200)

Windows Postman에서 다음 요청을 한 번 보냅니다.

```text
GET http://127.0.0.1:5000/api/data
X-API-Key: 발급한 원본 키
```

`X-Demo-Client-IP` 헤더는 제외합니다. HTTP 200과 `message: authorized`를 확인합니다.
공용 대시보드의 최근 이벤트에는 `정상 API 요청 / 허용`이 표시됩니다.

### 4. Kali에서 비허용 IP 사용 재현 (403)

Kali에서 아래 첫 줄을 실행한 뒤, 입력 안내가 나오면 **3단계와 같은 원본 키**를 붙여넣고 Enter를 누릅니다.
숨김 입력이므로 화면에 글자가 표시되지 않습니다.

```bash
read -rsp "실습용 API 키: " API_KEY; echo
```

입력 후 별도로 아래 명령을 실행합니다.

```bash
printf '키 길이: %s\n' "${#API_KEY}"
curl -i --connect-timeout 5 "http://$GW:5000/api/data" -H "X-API-Key: $API_KEY"
unset API_KEY
```

키 전체를 출력하지 말고 길이가 0이 아닌지 확인합니다. 현재 발급 방식은 일반적으로 46자입니다.
실제 Kali IP를 쓰므로 IP 재현 헤더는 넣지 않습니다.
HTTP **403**, `Client IP is not allowed`가 기대 결과입니다.
401이면 키 입력·활성 상태를, `Client IP has been blocked`이면 기존 IP 차단을 확인합니다.
연결 자체가 실패하면 API 바인딩·Windows 방화벽·WSL 네트워크를 확인합니다.

### 5. 탐지·자동 대응 결과 확인

1. Graylog에서 `API_KEY_COMPROMISED` 또는 `api_key_compromised`와 Kali IP로 검색합니다.
   요청 발생 시각이 포함되도록 검색 범위를 지정합니다. Middleware를 거친 로그인지 확인합니다.
2. n8n 시나리오 3 실행 내역에서 키 폐기·재발급 및 IP 차단 결과를 확인합니다.
   탐지 주기와 알림 유예에 따라 전달 시간이 걸릴 수 있습니다.
3. 공용 대시보드에서 `INC-API-...` 티켓, 비허용 IP 이벤트와 대응 조치를 확인합니다.
4. 관리자에서 기존 키 `폐기`, 교체 키 `활성`, Kali IP 차단 기록과 인시던트 연결을 확인합니다.
5. Discord를 연결한 환경에서는 키 **식별자**·IP·인시던트·대응 결과를 확인합니다.
6. Wazuh는 1단계에서 수집기를 켜둔 경우 새 요청을 수집합니다.
   수집기 실행 전에 이미 발생한 요청을 자동으로 다시 수집하지는 않습니다.

Wazuh Events에서 `rule.id:(100310 OR 100311 OR 100312)`로 검색합니다.
정상 요청·공격 거부·자동 대응 완료를 각각 확인합니다.
규칙·수집기 적용 전에 발생한 사건을 재처리한 경우는 아래 설명처럼 과거 로그 재처리 증적으로 구분합니다.

### 6. 폐기 키 거부 및 교체 키 정상 요청 확인

- **Windows Postman의 허용 IP**에서 기존 키로 다시 요청합니다.
  HTTP **401**, `API key is revoked`를 확인합니다.
  Kali는 IP 차단을 먼저 검사하므로 같은 폐기 키여도 403이 나올 수 있습니다.
- 관리자에서 활성 교체 키의 `새 키 확인`으로 원본을 한 번 확인·복사합니다.
  Postman의 `X-API-Key`를 교체 키로 변경한 뒤 같은 주소로 요청해 **200 / authorized**를 확인합니다.
- 반복 호출이 많으면 별도 요청 제한에 걸릴 수 있으므로 필요한 검증 요청만 보냅니다.

### 7. 시연 후 정리

- 다음 시나리오에서 같은 공격 IP를 사용한다면 관리자에서 해당 IP 차단을 해제합니다.
  차단 해제는 폐기 키를 복원하지 않습니다. 시나리오 1과 공유하는 목록임을 유의합니다.
- 열린 티켓은 검토 후 종료합니다. 티켓 종료는 키·차단 상태를 바꾸지 않습니다.
- 불필요한 활성 실습 키는 폐기하고 캡처에 실제 원본 키가 노출되지 않았는지 확인합니다.
- DB나 전체 티켓을 초기화하지 않습니다. 다음 재현은 새 실습용 키로 시작합니다.

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
