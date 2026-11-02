# 시나리오 2: SOAR 미들웨어 및 Graylog · n8n 자동 대응 구축 가이드

> **담당 범위**: 시나리오 2 (SOAR 로그 버퍼링 및 트래픽 제어 미들웨어)  
> **주요 기능**: 트래픽 폭주 시 하위 SIEM(Graylog) 보호(500 EPS 평탄화), WAL 기반 무손실 버퍼링, 허니토큰 우선 라우팅, Graylog 무차별 대입 공격 탐지 규칙, n8n 웹훅 기반 공격자 IP 자동 차단.

---

## 목차
1. [전체 파이프라인 구성도](#1-전체-파이프라인-구성도)
2. [1단계: 미들웨어 및 관측성 스택 기동](#2-1단계-미들웨어-및-관측성-스택-기동)
3. [2단계: Graylog 인풋, URL 화이트리스트 및 탐지 규칙 설정](#3-2단계-graylog-인풋-url-화이트리스트-및-탐지-규칙-설정)
   - [2-1. GELF HTTP 인풋 생성](#2-1-gelf-http-인풋-생성)
   - [2-2. URL 화이트리스트 등록](#2-2-url-화이트리스트-등록)
   - [2-3. 전용 스트림 생성](#2-3-전용-스트림-생성)
   - [2-4. 탐지 규칙 1: 무차별 대입 공격 탐지 및 n8n 웹훅 알림](#2-4-탐지-규칙-1-무차별-대입-공격-탐지-및-n8n-웹훅-알림)
   - [2-5. 탐지 규칙 2: 허니토큰 침입 탐지](#2-5-탐지-규칙-2-허니토큰-침입-탐지)
4. [3단계: n8n SOAR 자동 대응 워크플로우 등록](#4-3단계-n8n-soar-자동-대응-워크플로우-등록)
5. [4단계: Prometheus 및 Grafana 알람 규칙](#5-4단계-prometheus-및-grafana-알람-규칙)
6. [5단계: 미들웨어 트래픽 제어 및 핫패스 동작 원리](#6-5단계-미들웨어-트래픽-제어-및-핫패스-동작-원리)
7. [6단계: 시연 실행 및 검증 방법](#7-6단계-시연-실행-및-검증-방법)

---

## 1. 전체 파이프라인 구성도

```text
[공격자 / 클라이언트]
       │
       │ (1) 비인가 API 키 반복 호출 / 대량 스파이크 트래픽 인입
       ▼
┌─────────────────────────────────────────────────────────────┐
│  SOAR 미들웨어 (scenario2-middleware :8000 / :9100)          │
│                                                             │
│  - Partitioned WAL Broker (SQLite WAL 모드, 디스크 버퍼링)   │
│  - produce() 핫패스 인메모리 캐싱 (동기 DB 조회 0회)         │
│  - 2-Lane 우선순위 큐 (허니토큰 70:30 가중 드레인)          │
│  - 토큰 버킷 500 EPS 평탄화 (Graylog Netty 큐 포화 방지)    │
│  - GELF Split POST (동시 25개 요청으로 단건 병렬 전송)       │
└──────────────────────────────┬──────────────────────────────┘
                               │ (2) 초당 500건 이하로 평탄화 전송
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Graylog 6.1 SIEM (:9000 / :12201)                          │
│                                                             │
│  - GELF HTTP Input (:12201)                                 │
│  - [탐지 규칙] Brute Force Detection (1분 내 401 실패 >= 5회)│
│  - 알림: n8n HTTP Webhook 호출                              │
└──────────────────────────────┬──────────────────────────────┘
                               │ (3) Alert 발생 시 웹훅 전송
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  n8n SOAR 엔진 (:5678)                                      │
│                                                             │
│  - 워크플로우: Scenario 2 - Middleware Brute Force Response  │
│  - 공격자 IP (10.0.0.99) 및 탐지 사유 추출                   │
│  - 차단 API 호출: POST /automation/revoke-key               │
└──────────────────────────────┬──────────────────────────────┘
                               │ (4) IP 차단 및 키 폐기 요청
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  웹 애플리케이션 (:5000 / :5001)                            │
│                                                             │
│  - MySQL blocked_ips 테이블에 공격자 IP (10.0.0.99) 등록    │
│  - 후속 요청에 대해 HTTP 403 Forbidden 반환                 │
│  - 관제 대시보드(:5001/dashboard)에 인시던트 티켓 기록       │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 1단계: 미들웨어 및 관측성 스택 기동

`scenario2-middleware` 디렉터리에서 Docker Compose로 수집기, 컨슈머 워커, Prometheus, Grafana를 함께 실행합니다.

```powershell
# 1. 시나리오 2 디렉터리로 이동
cd scenario2-middleware

# 2. 컨테이너 빌드 및 백그라운드 기동
docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile observability up -d --build

# 3. 컨테이너 상태 점검
docker compose ps
```

### 서비스 접속 주소
- **미들웨어 Ingestor**: `http://127.0.0.1:8000/v1/health`
- **컨슈머 워커 메트릭**: `http://127.0.0.1:9100/metrics`
- **Prometheus**: `http://127.0.0.1:9090`
- **Grafana**: `http://127.0.0.1:3000` (계정: `admin` / `admin`)
- **Graylog**: `http://127.0.0.1:9000` (계정: `admin` / `admin`)
- **n8n**: `http://127.0.0.1:5678`

---

## 3. 2단계: Graylog 인풋, URL 화이트리스트 및 탐지 규칙 설정

Graylog 웹 콘솔(`http://127.0.0.1:9000`)에서 아래 항목을 순서대로 설정합니다.

### 2-1. GELF HTTP 인풋 생성
미들웨어가 전송하는 로그를 수신할 포트를 엽니다.
1. 상단 메뉴 **System** > **Inputs**로 이동합니다.
2. 드롭다운에서 **GELF HTTP**를 선택하고 **Launch new input**을 클릭합니다.
   - **Global**: 체크
   - **Title**: `Middleware GELF Ingest`
   - **Port**: `12201`
   - **Bind address**: `0.0.0.0`
3. **Save**를 누르고 상태가 **RUNNING**으로 표시되는지 확인합니다.

---

### 2-2. URL 화이트리스트 등록
Graylog가 내부망의 n8n으로 웹훅 요청을 보낼 수 있도록 허용 목록에 추가합니다.
1. **System** > **Configurations**로 이동합니다.
2. **URL Whitelist** > **Update**를 클릭합니다.
3. **Whitelist Entries**에 아래 주소를 추가하고 저장합니다.
   ```text
   http://host.docker.internal:5678/.*
   http://n8n:5678/.*
   ```

---

### 2-3. 전용 스트림 생성
미들웨어에서 전달된 보안 로그를 별도 스트림으로 분류합니다.
1. 상단 메뉴 **Streams** > **Create Stream**을 클릭합니다.
   - **Title**: `SOAR Security Logs`
   - **Index Set**: `Default index set` 선택 후 저장합니다.
2. `SOAR Security Logs` 우측의 **Manage Rules** > **Add stream rule**을 클릭합니다.
   - **Field**: `source`
   - **Type**: `match exactly`
   - **Value**: `security-middleware`
3. **Start Stream**을 눌러 스트림을 활성화합니다.

---

### 2-4. 탐지 규칙 1: 무차별 대입 공격 탐지 및 n8n 웹훅 알림

1. **알림(Notification) 생성**:
   - **Alerts** > **Notifications** > **Add Notification**을 클릭합니다.
   - **Title**: `S2 n8n Webhook (Brute Force)`
   - **Type**: `HTTP Notification`
   - **URL**: `http://host.docker.internal:5678/webhook/scenario2-bruteforce`
   - **Method**: `POST`
   - **Body Template (JSON)**:
     ```json
     {
       "event_type": "BRUTE_FORCE",
       "client_ip": "${event.fields.client_ip}",
       "timestamp": "${event.timestamp}",
       "title": "${event_definition_title}",
       "reason": "1분 내 인증 5회 이상 실패"
     }
     ```
2. **이벤트 정의(Event Definition) 생성**:
   - **Alerts** > **Event Definitions** > **Create Event Definition**을 클릭합니다.
   - **Title**: `[S2] Brute Force Attack Detection`, **Priority**: `High`
   - **Condition Type**: **Aggregation**
   - **Search Query**:
     ```text
     status_code:401 OR (event_type:APP_REQUEST AND status_code:401)
     ```
   - **Search in the last**: `1 minute`, **Execute every**: `30 seconds`
   - **Streams**: `SOAR Security Logs`
   - **Group by Field(s)**: `client_ip`
   - **Threshold**: `count() >= 5`
   - **Fields**: Field Name `client_ip` / Value `${source.client_ip}` 매핑
   - **Notifications**: `S2 n8n Webhook (Brute Force)` 연결
   - **Grace Period**: `1 minute` (`60 seconds`)
     > [!TIP]
     > 집계 범위가 1분(60초)이고 실행 주기가 30초이므로 Grace Period가 0초이면 동일 공격에 대해 알림이 중복 발송됩니다. Grace Period를 60초로 설정하면 최초 탐지 시 1회만 웹훅을 호출합니다.

---

### 2-5. 탐지 규칙 2: 허니토큰 침입 탐지
1. **Alerts** > **Event Definitions** > **Create Event Definition**을 클릭합니다.
2. **Title**: `[S2] Honeytoken Infiltration Alert`, **Priority**: `Critical`
3. **Condition Type**: **Filter**
4. **Search Query**: `_honeytoken_alert:true OR event_type:HONEYTOKEN_ACCESS`
5. **Threshold**: `count() > 0` (1회 발생 시 즉시 알림)

---

## 4. 3단계: n8n SOAR 자동 대응 워크플로우 등록

- **워크플로우 파일 경로**: [`scenario2-middleware/n8n/scenario2_bruteforce_response_workflow.json`](./n8n/scenario2_bruteforce_response_workflow.json)

### 등록 절차
1. n8n 콘솔(`http://127.0.0.1:5678`)에 접속합니다.
2. 좌측 **Workflows** 메뉴로 이동한 뒤 우측 상단 `...` 메뉴에서 **Import from File**을 선택합니다.
3. [`scenario2_bruteforce_response_workflow.json`](./n8n/scenario2_bruteforce_response_workflow.json) 파일을 가져옵니다.
4. 노드 구성을 확인합니다.
   - **Webhook**: `POST /webhook/scenario2-bruteforce` 수신
   - **Normalize**: 이벤트 페이로드에서 `client_ip` 추출
   - **Block Attacker IP**: `http://host.docker.internal:5000/automation/revoke-key`를 호출하여 MySQL `blocked_ips` 테이블에 공격자 IP 등록
   - **Format Alert**: 알림 메시지 포맷 생성
5. 우측 상단 토글을 **Active** 상태로 전환합니다.

---

## 5. 4단계: Prometheus 및 Grafana 알람 규칙

[`docs/observability/prometheus_alerts.yml`](./docs/observability/prometheus_alerts.yml)에 정의된 파이프라인 상태 감시 규칙입니다.

| 알람 명칭 | 임계치 및 조건 | 심각도 | 설명 |
| :--- | :--- | :--- | :--- |
| **`HighQueueLag`** | `sum(queue_lag) > 1000` (2분 지속) | Warning | 유입량 대비 컨슈머 처리 지연으로 WAL 큐 적체 증가 |
| **`DLQDepthNonZero`** | `dlq_depth > 0` (5분 지속) | Warning | 전송 실패 또는 스키마 오류로 DLQ에 격리된 로그 존재 |
| **`GraylogHigh5xxRate`** | Graylog 5xx 에러율 > 5% (1분 지속) | Critical | 하위 SIEM 장애 발생으로 컨슈머가 지수 백오프 및 파티션 일시 정지 수행 중 |
| **`InvariantViolationsDetected`** | `invariant_violations > 0` (즉시) | Critical | 수신·전송·격리 원장 수량 불일치 감지 |
| **`ConsumerNotProgressing`** | 큐 적체가 있으나 3분간 전송량 0 | Critical | 컨슈머 워커 중단 또는 하위 네트워크 단절 상태 |

---

## 6. 5단계: 미들웨어 트래픽 제어 및 핫패스 동작 원리

1. **논블로킹 프로듀서 핫패스 (`lightweight_broker.py`, `ingestor.py`)**
   - 수집 요청을 처리하는 `produce()` 경로에서 동기 SQLite 조회를 제거했습니다.
   - 미소비 큐 적체량(`unconsumed_lag`)은 백그라운드 태스크가 `asyncio.to_thread`로 1초마다 갱신하며, 토픽별 파티션 수는 최초 1회 조회 후 인메모리에 캐싱합니다.
2. **우선순위 라우팅 (`ingestor.py`)**
   - `HONEYTOKEN_ACCESS` 이벤트 또는 `severity <= 2` 로그는 `security-logs.priority` 토픽으로 분기합니다.
3. **70:30 가중 드레인 (`consumer_worker.py`)**
   - 일반 로그 백로그가 쌓여 있어도 배치 슬롯의 70%를 우선순위 레인에 할당해 허니토큰 경보를 2.0초 이내에 먼저 전달합니다. 나머지 30%는 표준 레인에 할당해 일반 로그 기아 현상을 막습니다.
4. **토큰 버킷 속도 제한 (`TokenBucketRateLimiter`)**
   - `MAX_LOGS_PER_SEC = 500.0`, `BATCH_SIZE = 100` 설정으로 초당 최대 500건까지만 Graylog로 내보냅니다.
5. **단건 병렬 분할 전송 (`GELF_SPLIT_POST=true`, `delivery_client.py`)**
   - 상용 Graylog 6.1의 단건 JSON 파싱 규격에 맞춰 100건 배치를 `asyncio.Semaphore(25)` 제한 아래 병렬 POST로 전송합니다.

---

## 7. 6단계: 시연 실행 및 검증 방법

### 시연 1: 미들웨어 유무(A/B) 비교 벤치마크
```powershell
python simulators/compare_middleware.py --logs 20000 --concurrency 300
```
- **TEST A (미들웨어 없음)**: Graylog Netty 큐 포화 및 타임아웃으로 20,000건 중 11,282건 유실(56.4%), 34.55초 소요
- **TEST B (미들웨어 경유)**: 18.36초 만에 20,000건 전량 수락(유실 0.00%) 후 백그라운드에서 500 EPS로 평탄화 전송

### 시연 2: 2만 건 스파이크 완충 및 5단계 무손실 감사 리포트
```powershell
python simulators/spike_test_demo.py --spike-count 20000
```
- 4.5초 동안 20,004건 인입 후 초당 500건 속도로 드레인
- `Sent (20,004) == Received (20,004) == Forwarded (20,004) == Graylog Stored (20,004)` 수량 일치 확인

### 시연 3: 무차별 대입 공격 탐지 및 n8n 자동 IP 차단

메인 API 서버(`:5000/api/data`)로 잘못된 API 키를 5회 연속 전송하여 HTTP 401 발생부터 Graylog 집계 탐지, n8n 웹훅 호출, 공격자 IP 차단(HTTP 403)까지 전체 흐름을 검증합니다.

**방법 A: 시연 스크립트 실행**
```powershell
python simulators/demo_bruteforce_attack.py
```
- 이전 차단 이력 해제 $\rightarrow$ 5회 연속 401 요청 주입 $\rightarrow$ Graylog 탐지 및 n8n 차단 대기 $\rightarrow$ 재접속 시 HTTP 403 차단 응답 확인까지 순서대로 실행됩니다.

**방법 B: PowerShell 명령으로 직접 호출**
```powershell
# 1. 동일 IP(10.0.0.99)로 5회 연속 잘못된 API 키 전송 (HTTP 401 발생)
1..5 | ForEach-Object {
    try {
        Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:5000/api/data" `
            -Headers @{"X-API-Key"="invalid-fake-key-$_"; "X-Demo-Client-IP"="10.0.0.99"}
    } catch {}
}
```

#### 시연 결과 확인 위치
1. **Graylog Alerts (`http://127.0.0.1:9000/alerts`)**:
   - `[S2] Brute Force Attack Detection` 이벤트 발생 확인 (동일 IP 5회 이상 401 실패 집계)
2. **n8n Executions (`http://127.0.0.1:5678`)**:
   - `Scenario 2 - Middleware Brute Force Response` 워크플로우 실행 성공(`SUCCESS`) 및 `/automation/revoke-key` 호출 확인
3. **웹 애플리케이션 차단 및 대시보드 확인**:
   ```powershell
   # 차단된 공격자 IP(10.0.0.99)로 재접속 시도 -> HTTP 403 Forbidden 반환 확인
   Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:5000/api/data" `
       -Headers @{"X-API-Key"="test-key-01"; "X-Demo-Client-IP"="10.0.0.99"}
   # 응답: {"error":"request_rejected","message":"Client IP has been blocked"} (HTTP 403)
   ```
   - 관제 대시보드(`http://127.0.0.1:5001/dashboard`)에서 차단된 IP(`10.0.0.99`)와 인시던트 티켓을 확인합니다.
