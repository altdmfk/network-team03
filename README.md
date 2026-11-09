# EngineSquare 보안 관제 및 SOAR 자동 대응 시스템

EngineSquare는 웹 애플리케이션과 API 서버에서 발생하는 보안 이벤트를 수집하고 분석하여 자동 대응하는 통합 보안 관제 프로젝트입니다.
로그 버퍼링 미들웨어와 SIEM(Graylog·Wazuh) 및 SOAR(n8n)를 연동해 대량 트래픽 완충부터 유출 API 키 차단과 킬체인 상관분석까지 3개 시나리오를 처리합니다.

---

## 1. 시스템 구조 및 디렉터리 안내

```text
[클라이언트 / 공격 트래픽 / IoT 장비]
        │
        ▼
[공용 Flask API 서버 (:5000)] ◄── DB 공유 (MySQL) ──► [공통 웹앱 · 대시보드 (:5001)]
        │                                                       ▲
        ├── JSON 보안 로그 전달                                  │
        ▼                                                       │
[시나리오 1: SOAR 로그 버퍼링 미들웨어 (:8000 / :9100)]          │
        │  - SQLite WAL 파티션 브로커 버퍼링                     │
        │  - 500 EPS 토큰 버킷 스로틀링 · 70:30 우선순위 드레인   │
        ▼                                                       │
[Graylog 6.1 (:9000 / :12201)]  /  [Wazuh 4.9]                  │
        │                                                       │
        ├── 이벤트 정의 매칭 시 웹훅 호출                        │
        ▼                                                       │
[n8n SOAR 자동 대응 워크플로 (:5678)] ──────────────────────────┘
        ├── 시나리오 1: 브루트포스 공격자 IP 차단 및 디스코드 알림
        ├── 시나리오 2: 유출 API 키 폐기·재발급 및 공격자 IP 차단
        └── 시나리오 3: pfSense IP 차단 · ESP32-C3 Lockdown · 인시던트 등록
```

| 경로 | 역할 | 상세 문서 |
| :--- | :--- | :--- |
| [`app.py`](./app.py) | 공용 Flask API 서버 (`:5000`). API 키·IP 검증과 보안 로그 발행 및 자동 대응 웹훅 수신 | 현재 문서 |
| [`web-app/`](./web-app/) | 공통 웹앱 (`:5001`). 게시판과 보안 관제 대시보드 및 관리자 페이지 제공 | [`web-app/README.md`](./web-app/README.md) |
| [`scenario1-middleware/`](./scenario1-middleware/) | 시나리오 1: 로그 버퍼링 및 트래픽 제어 미들웨어 (`:8000`, `:9100`) | [`scenario1-middleware/README.md`](./scenario1-middleware/README.md)<br/>[`SCENARIO1_SETUP_GUIDE.md`](./scenario1-middleware/SCENARIO1_SETUP_GUIDE.md) |
| [`scenario2-api-key-compromised/`](./scenario2-api-key-compromised/) | 시나리오 2: 유출 API 키 탐지 및 자동 폐기·재발급·IP 차단 | [`scenario2-api-key-compromised/README.md`](./scenario2-api-key-compromised/README.md) |
| [`scenario3-killchain/`](./scenario3-killchain/) | 시나리오 3: 킬체인 상관분석 및 IoT 장비 제어 차단 | [`scenario3-killchain.md`](./scenario3-killchain/docs/scenario3-killchain.md)<br/>[`scenario1-integration.md`](./scenario3-killchain/docs/scenario1-integration.md) |
| [`tests/`](./tests/) | 인시던트 ID 발급 규칙 및 킬체인 수신 엔드포인트 단위 테스트 | [`tests/README.md`](./tests/README.md) |

---

## 2. 시나리오별 핵심 내용

### 시나리오 1: 로그 버퍼링 및 트래픽 제어 미들웨어
대량 트래픽이나 공격으로 로그가 급증할 때 하위 Graylog의 과부하를 막고 로그를 유실 없이 전달하는 파이프라인입니다.

- **비동기 수집과 WAL 브로커**: FastAPI 수집기(`:8000`)가 인입 로그를 SQLite WAL 기반 3개 파티션 브로커(`broker_wal.db`)에 디스크 버퍼링합니다. 프로듀서 핫패스에서 동기 DB 조회를 배제하고 인메모리 캐시를 참조해 수집 지연을 줄였습니다.
- **트래픽 평탄화와 선별 재시도**: 컨슈머 워커(`:9100`)가 토큰 버킷 레이트 리미터와 마이크로 배칭을 적용해 초당 500건 이하로 전송 속도를 제어합니다. Graylog 6.1 규격에 맞춰 20개 스레드 병렬 단건 POST로 전송합니다. 부분 실패 시 실패한 인덱스만 선별 재시도하고 HTTP 2xx 응답 확인 후 오프셋을 동기 커밋합니다.
- **우선순위 라우팅과 순서 보장**: `client_ip` 기준 CRC32 해시 파티셔닝으로 동일 공격자 IP의 이벤트 순서를 유지합니다. 긴급 이벤트는 우선순위 토픽으로 분리하고 70:30 가중 드레인을 적용해 일반 로그 백로그가 쌓인 상태에서도 2초 이내에 먼저 전달합니다.
- **SOAR 브루트포스 대응**: Graylog가 1분 내 동일 IP의 401 실패 5회 이상을 집계하면 n8n 웹훅(`/webhook/scenario1-bruteforce`)을 호출합니다. n8n은 공용 API의 `/automation/revoke-key`를 호출해 공격자 IP를 차단하고 디스코드 알림을 발송합니다.
- **실행 및 벤치마크**:
  ```powershell
  cd scenario1-middleware
  Copy-Item .env.example .env
  docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile observability up -d --build

  # 다운스트림 정지 기반 복원력 벤치마크 및 2만 건 스파이크 검증
  python simulators/compare_middleware.py --mode distress --scenario all
  python simulators/spike_test_demo.py --spike-count 20000
  python simulators/demo_bruteforce_attack.py
  ```

### 시나리오 2: 유출 API 키 탐지 및 자동 대응
활성 API 키가 허용 목록에 없는 출발지 IP에서 사용될 때 이를 즉시 탐지하고 키 교체와 IP 차단을 자동 수행하는 시나리오입니다.

- **탐지 흐름**: API 서버가 비허용 IP 요청에 HTTP 403을 반환하고 `api_key_compromised` 이벤트를 미들웨어로 전달합니다. 동일 IP·키 조합의 반복 요청은 5분 동안 1회만 탐지 이벤트로 보내고 이후 요청은 `api_request_blocked`로 전달해 중복 알림을 막습니다.
- **자동 대응**: Graylog가 `status_code=403`인 `api_key_compromised` 이벤트를 감지하면 n8n 웹훅(`/webhook/scenario2-api-key-compromised`)을 호출합니다. n8n은 `POST /automation/revoke-key`를 호출해 기존 키를 폐기하고 교체 키를 발급합니다. 동시에 공격자 IP를 `blocked_ips`에 등록하고 대시보드와 디스코드로 결과를 전송합니다.
- **키 원본 보호**: 인증에 쓰는 원본 API 키(`es_...`)와 로그에 남기는 식별자(`key-...`)를 분리합니다. DB에는 SHA-256 해시만 저장하며 자동 교체로 발급한 신규 키 원본은 Fernet으로 암호화해 관리자가 1회 조회할 때만 복호화한 뒤 파기합니다.
- **Wazuh 병행 분석**: [`forward_api_logs.py`](./scenario2-api-key-compromised/wazuh/forward_api_logs.py) 수집기가 신규 API 로그를 Wazuh 컨테이너(`/var/ossec/logs/enginesquare-scenario2.jsonl`)로 전달합니다. [`scenario2_rules.xml`](./scenario2-api-key-compromised/wazuh/scenario2_rules.xml)에 정의한 규칙(`100310`~`100312`)으로 정상 요청과 비허용 IP 거부 및 자동 대응 완료 이벤트를 분류합니다.

### 시나리오 3: 킬체인 상관분석 및 IoT 장비 제어 차단
단일 이벤트만으로는 차단하지 않고 정찰·침투·물리 장비 제어 시도가 시간순으로 연쇄 발생할 때만 침해 사고로 격상해 네트워크와 하드웨어를 동시에 제어하는 시나리오입니다.

- **3단계 공격 체인**:
  1. **정찰**: 동일 `client_ip`에서 1분 내 404 응답 다수 발생 또는 포트 스캔(`recon_scan`, `PORT_SCAN`) 탐지.
  2. **침투**: 동일 IP에서 유출 API 키 재사용(`api_key_compromised`) 또는 인증 실패 누적(`BRUTE_FORCE`) 발생.
  3. **물리 장비 타격**: IoT 디바이스 제어 엔드포인트(`/device/control`)에 비정상 제어 명령(`device_control`) 전송.
- **상관분석 및 오탐 방지**: Graylog가 미들웨어를 거친 로그를 `client_ip` 기준으로 그룹핑합니다. 10분 윈도우 내에 서로 다른 단계 이벤트 3종 이상(`card(event_type) >= 3`)이 모일 때만 `Killchain CRITICAL` 경보를 발동합니다. 1~2단계만 발생하면 `WARNING`으로 분류해 ESP32-C3 보드의 노란색 경고 LED만 켜고 서비스 차단은 수행하지 않습니다.
- **다중 대응 및 수동 복구**: `CRITICAL` 판정 시 n8n이 pfSense 방화벽 별칭으로 공격자 IP를 차단하고 ESP32-C3 보드로 `/lockdown` 명령을 보내 빨간색 LED 점등과 장비 제어 차단을 수행합니다. 이어서 공용 API의 `POST /automation/killchain-response`를 호출해 `INC-KILLCHAIN-...` 티켓을 등록합니다. Lockdown 해제는 수동 승인 절차로 분리했습니다.
- **시뮬레이션 실행**:
  ```powershell
  # 합성 이벤트 전송 검증 (CRITICAL / WARNING)
  python scenario3-killchain/scripts/test_killchain.py critical
  python scenario3-killchain/scripts/test_killchain.py warning

  # 실제 API 서버 공격 + Graylog 표준 이벤트 연동 시연
  python scenario3-killchain/scripts/demo_killchain_live.py
  ```

---

## 3. 공용 API 서버 및 공통 웹앱 실행

공용 API 서버(`:5000`)와 공통 웹앱(`:5001`)은 동일한 MySQL(`mysql-server`) 데이터베이스를 공유합니다. 키 폐기·재발급과 IP 차단 변경 사항은 서버 재시작 없이 다음 요청부터 즉시 반영합니다.

### 통합 실행 스크립트 사용
MySQL과 미들웨어 등 Docker 컨테이너를 먼저 기동합니다. 프로젝트 루트의 `.env.example`을 `.env`로 복사한 뒤 `MIDDLEWARE_API_KEY` 값을 입력합니다.

```powershell
Copy-Item .env.example .env
python -m pip install -r requirements.txt -r web-app/requirements.txt
.\start-enginesquare.ps1
```

- [`start-enginesquare.ps1`](./start-enginesquare.ps1)은 `.env` 설정을 읽어 공용 API 서버(`:5000`)와 공통 웹앱(`:5001`) 및 Wazuh 로그 수집기를 함께 기동합니다.
- 실행 로그는 `.runtime-logs/` 폴더에 기록합니다. 실행 창에서 Enter를 누르면 세 프로세스를 함께 종료합니다.

### 개별 수동 실행
API 서버와 웹앱을 별도 터미널에서 각각 실행할 수도 있습니다.

```powershell
# 터미널 1: 공용 API 서버 (:5000)
$env:MIDDLEWARE_INGEST_URL = "http://localhost:8000/ingest"
$env:MIDDLEWARE_API_KEY = "<공유받은_수집_키>"
python app.py

# 터미널 2: 공통 웹앱 (:5001)
python web-app/app.py
```

---

## 4. 주요 API 엔드포인트

| 메서드 및 경로 | 설명 |
| :--- | :--- |
| `GET /health` | API 서버 상태 확인 (`{"status": "ok"}`) |
| `GET /api/data` | API 키(`X-API-Key`) 및 허용 IP 검증 대상 보호 리소스. 데모 시 `X-Demo-Client-IP` 헤더로 출발지 IP 재현 가능 |
| `GET /api/security-events` | 최근 생성한 보안 이벤트 목록 조회 |
| `GET /api/incidents` | 인시던트 티켓 목록 조회 |
| `GET /api/blocked-ips` | 현재 차단 중인 IP 목록 조회 |
| `POST /automation/revoke-key` | 시나리오 1·2 SOAR 자동 대응 엔드포인트. 공격자 IP 차단 및 활성 키 폐기·교체 키 발급 수행 |
| `POST /automation/killchain-response` | 시나리오 3 SOAR 결과 수신 엔드포인트. `killchain_critical` 인시던트 티켓(`INC-KILLCHAIN-...`) 및 대시보드 이벤트 기록 |

보안 이벤트 기본 필드는 `timestamp`, `event_type`, `api_key_id`, `client_ip`, `target_resource`, `status_code`입니다. 이벤트 성격에 따라 `user_agent`, `detection_reason`, `incident_id`, `action`, `status` 필드를 추가합니다.

---

## 5. 테스트 실행

```powershell
# 루트 API 서버 및 시나리오 연동 단위 테스트
python -m unittest test_app.py tests.test_incident_prefixes tests.test_killchain_response

# 시나리오 1 미들웨어 단위·통합 테스트 스위트
pytest -v

# 공통 웹앱 및 MySQL 연동 검증 (mysql-server 실행 필요)
python web-app/test_admin_security.py
```
