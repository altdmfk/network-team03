# [시나리오 2 전용] SOAR 미들웨어 & Graylog / n8n 자동대응 상세 구축 가이드

> **담당 시나리오**: 시나리오 2 (SOAR 로그 버퍼링 및 트래픽 제어 미들웨어)  
> **핵심 역할**: 트래픽 폭주 시 하위 SIEM(Graylog) 과부하 방지(500 EPS 평탄화), 무손실(0.00%) 버퍼링, 허니토큰 우선 배송, SIEM 무차별 대입 공격 탐지 룰, n8n 자동 IP 차단 워크플로우 구축.

---

## 📌 목차
1. [전체 파이프라인 구성도](#1-전체-파이프라인-구성도)
2. [1단계: 미들웨어 & 관측성 스택 기동](#2-1단계-미들웨어--관측성-스택-기동)
3. [2단계: Graylog 인풋, URL 화이트리스트 및 탐지 규칙(Rule) 설정](#3-2단계-graylog-인풋-url-화이트리스트-및-탐지-규칙rule-설정)
   - [2-1. GELF HTTP 입력(Input) 생성](#2-1-gelf-http-입력input-생성)
   - [2-2. URL 화이트리스트 등록 (n8n 웹훅 차단 해제)](#2-2-url-화이트리스트-등록-n8n-웹훅-차단-해제)
   - [2-3. 전용 스트림(Stream) 생성](#2-3-전용-스트림stream-생성)
   - [2-4. 탐지 룰 1: 무차별 대입 공격 (Brute Force Detection) & n8n 알림](#2-4-탐지-룰-1-무차별-대입-공격-brute-force-detection--n8n-알림)
   - [2-5. 탐지 룰 2: 허니토큰 긴급 침입 탐지](#2-5-탐지-룰-2-허니토큰-긴급-침입-탐지)
4. [3단계: n8n SOAR 자동 대응 워크플로우 등록](#4-3단계-n8n-soar-자동-대응-워크플로우-등록)
5. [4단계: Prometheus & Grafana 관측성 알람 규칙](#5-4단계-prometheus--grafana-관측성-알람-규칙)
6. [5단계: 미들웨어 핵심 트래픽 제어 규칙 (내부 메커니즘)](#6-5단계-미들웨어-핵심-트래픽-제어-규칙-내부-메커니즘)
7. [6단계: 발표 시연 실행 및 단계별 검증 방법](#7-6단계-발표-시연-실행-및-단계별-검증-방법)

---

## 1. 전체 파이프라인 구성도

```
[공격자 / 클라이언트]
       │
       │ (1) 초당 수백 건의 로그인 실패 / 대량 트래픽 인입
       ▼
┌─────────────────────────────────────────────────────────────┐
│  SOAR 미들웨어 (scenario2-middleware :8000 / :9100)          │
│                                                             │
│  - Partitioned WAL Broker (SQLite WAL 모드, 무손실 버퍼링)  │
│  - 2-Lane 우선순위 큐 (허니토큰 70:30 가중 드레인)          │
│  - 토큰 버킷 500 EPS 평탄화 (Netty 스레드 포화 방지)        │
│  - GELF Split Delivery (동시 20개 워커로 100% 개별 인덱싱)  │
└──────────────────────────────┬──────────────────────────────┘
                               │ (2) 500 EPS 일정 속도로 안전 배송
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Graylog 6.1 SIEM (:9000 / :12201)                          │
│                                                             │
│  - GELF HTTP Input (:12201)                                 │
│  - [탐지 룰] Brute Force Detection (1분 내 401 실패 >= 5회) │
│  - 알림: n8n HTTP Webhook 전송                              │
└──────────────────────────────┬──────────────────────────────┘
                               │ (3) 실시간 HTTP Alert Webhook 호출
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  n8n SOAR 엔진 (:5678)                                      │
│                                                             │
│  - 워크플로우: Scenario 2 - Middleware Brute Force Response  │
│  - 파싱: 공격자 IP (10.0.0.99) 및 탐지 사유 추출             │
│  - 자동 대응 호출: POST /automation/revoke-key               │
└──────────────────────────────┬──────────────────────────────┘
                               │ (4) IP 차단 API 호출
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  웹 애플리케이션 (:5000 / :5001)                            │
│                                                             │
│  - MySQL blocked_ips 테이블에 공격자 IP (10.0.0.99) 등록    │
│  - 후속 요청에 대해 HTTP 403 Forbidden 즉시 반환            │
│  - 웹 관제 대시보드(:5001/dashboard)에 인시던트 티켓 표시   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 1단계: 미들웨어 & 관측성 스택 기동

`scenario2-middleware` 디렉터리에서 Docker Compose로 미들웨어 수집기, 컨슈머 워커, 프로메테우스, 그라파나를 동시 기동합니다.

```powershell
# 1. 시나리오 2 디렉터리로 이동
cd scenario2-middleware

# 2. 컨테이너 빌드 및 백그라운드 기동 (관측성 프로파일 포함)
docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile observability up -d --build

# 3. 컨테이너 상태 점검 (모두 healthy / Up 확인)
docker compose ps
```

### 정상 실행 확인 포트
- **미들웨어 Ingestor**: `http://localhost:8000/v1/health`
- **컨슈머 워커 메트릭**: `http://localhost:9100/metrics`
- **Prometheus**: `http://localhost:9090`
- **Grafana**: `http://localhost:3000` (계정: `admin` / `admin`)
- **Graylog**: `http://localhost:9000` (계정: `admin` / `admin`)
- **n8n**: `http://localhost:5678`

---

## 3. 2단계: Graylog 인풋, URL 화이트리스트 및 탐지 규칙(Rule) 설정

Graylog 웹 콘솔(`http://localhost:9000`)에 접속하여 아래 5가지 설정을 진행합니다.

### 2-1. GELF HTTP 입력(Input) 생성
미들웨어가 평탄화된 로그를 전송받을 수신 포트를 엽니다.
1. 상단 메뉴 **System** > **Inputs** 로 이동합니다.
2. 드롭다운에서 **GELF HTTP**를 선택하고 **Launch new input**을 클릭합니다:
   - **Global**: `[v]` 체크 (모든 노드 적용)
   - **Title**: `Middleware GELF Ingest`
   - **Port**: `12201`
   - **Bind address**: `0.0.0.0`
3. **Save**를 누르고 상태가 녹색 **RUNNING**인지 확인합니다.

---

### 2-2. URL 화이트리스트 등록 (n8n 웹훅 차단 해제)
Graylog가 로컬 내부망의 n8n으로 웹훅을 쏠 수 있도록 허용합니다:
1. **System** > **Configurations** 이동
2. 우측 하단의 **URL Whitelist** > **Update** 클릭
3. **Whitelist Entries**에 다음 주소를 추가 후 저장:
   ```text
   http://host.docker.internal:5678/.*
   http://n8n:5678/.*
   ```

---

### 2-3. 전용 스트림(Stream) 생성
미들웨어에서 유입되는 로그만 분리 관제합니다:
1. 상단 메뉴 **Streams** > **Create Stream**:
   - **Title**: `SOAR Security Logs`
   - **Index Set**: `Default index set` 선택 후 Save.
2. `SOAR Security Logs` 우측의 **Manage Rules** 클릭 > **Add stream rule**:
   - **Field**: `source`
   - **Type**: `match exactly`
   - **Value**: `security-middleware`
3. **Start Stream**을 눌러 스트림을 활성화합니다.

---

### 2-4. 탐지 룰 1: 무차별 대입 공격 (Brute Force Detection) & n8n 알림

1. **알림(Notifications) 생성**:
   - **Alerts** > **Notifications** > **Add Notification** 클릭
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
       "reason": "1분 내 로그인 5회 이상 실패"
     }
     ```
2. **이벤트 정의(Event Definition) 생성**:
   - **Alerts** > **Event Definitions** > **Create Event Definition**
   - **Title**: `[S2] Brute Force Attack Detection`, **Priority**: `High`
   - **Condition Type**: **Aggregation**
   - **Search Query**:
     ```text
     status_code:401 OR (event_type:APP_REQUEST AND status_code:401)
     ```
   - **Search in the last**: `1 minute`, **Execute every**: `30 seconds`
   - **Streams**: `SOAR Security Logs`
   - **Group by Field(s)**: `client_ip`
   - **Threshold**: When `count() >= 5`
   - **Fields**: Field Name `client_ip` / Value `${source.client_ip}` 매핑
   - **Notifications**: 앞서 생성한 `S2 n8n Webhook (Brute Force)` 연결
   - **Grace Period (중복 알림 억제)**: `1 minute` (또는 `60 seconds`)
     > [!TIP]
     > **Grace Period를 60초로 주는 이유**: 집계 범위가 1분(60초)이므로, Grace Period가 0초이면 1분 동안 10~30초마다 동일 IP에 대해 n8n 알람이 중복 발송됩니다. 60초로 설정하면 탐지 즉시 1회만 알람이 가고 중복 발송이 방지됩니다.

---

### 2-5. 탐지 룰 2: 허니토큰 긴급 침입 탐지
1. **Alerts** > **Event Definitions** > **Create Event Definition**
2. **Title**: `[S2] Honeytoken Infiltration Alert`, **Priority**: `Critical`
3. **Condition Type**: **Filter**
4. **Search Query**: `_honeytoken_alert:true OR event_type:HONEYTOKEN_ACCESS`
5. **Threshold**: 1회 발생 즉시 탐지 (`count() > 0`)

---

## 4. 3단계: n8n SOAR 자동 대응 워크플로우 등록

다른 시나리오의 구조를 바탕으로 시나리오 2 전용으로 준비된 n8n 워크플로우 파일입니다.

- **워크플로우 파일 위치**: [`scenario2-middleware/n8n/scenario2_bruteforce_response_workflow.json`](file:///scenario2-middleware/n8n/scenario2_bruteforce_response_workflow.json)

### 등록 방법 (1분 소요):
1. 브라우저로 n8n 콘솔(`http://localhost:5678`)에 접속합니다.
2. 좌측 메뉴 **Workflows** 이동 > 우측 상단 `...` 메뉴 클릭 > **Import from File** 선택.
3. [`scenario2-middleware/n8n/scenario2_bruteforce_response_workflow.json`](file:///scenario2-middleware/n8n/scenario2_bruteforce_response_workflow.json) 파일을 선택합니다.
4. 임포트된 워크플로우 확인:
   - **Webhook**: `POST /webhook/scenario2-bruteforce` (Graylog 수신)
   - **Normalize**: `client_ip` 파싱
   - **Block Attacker IP**: `http://host.docker.internal:5000/automation/revoke-key` 호출 (Flask API 서버를 통해 MySQL `blocked_ips` 테이블에 등록)
   - **Format Alert**: Discord/슬랙용 알림 문구 생성
5. 우측 상단의 토글 스위치를 **Active (Published)** 상태로 켭니다.

---

## 5. 4단계: Prometheus & Grafana 관측성 알람 규칙

미들웨어 파이프라인의 건강 상태를 감시하는 5대 인프라 알람입니다:

| 알람 명칭 (`Alert Name`) | 임계치 및 조건 | 심각도 | 설명 |
|---|---|---|---|
| **`HighQueueLag`** | `sum(queue_lag) > 1000` (2분 지속) | Warning | 인제스터 인입 대비 컨슈머 처리 지연으로 WAL 대기열 적체 |
| **`DLQDepthNonZero`** | `dlq_depth > 0` (5분 지속) | Warning | 형식 오류 또는 전송 실패로 Dead-Letter Queue에 격리된 로그 존재 |
| **`GraylogHigh5xxRate`** | Graylog 5xx 에러율 > 5% (1분 지속) | Critical | 하위 SIEM 과부하/다운. 컨슈머가 지수 백오프 및 큐 일시정지 적용 중 |
| **`InvariantViolationsDetected`** | `invariant_violations > 0` (즉시) | Critical | 수신/전송/유실 회계 원장 불일치 (무손실 보장 위반 감지) |
| **`ConsumerNotProgressing`** | 인입은 있으나 3분간 전송량 0 | Critical | 컨슈머 워커 스레드 교착 또는 네트워크 단절 상태 |

---

## 6. 5단계: 미들웨어 핵심 트래픽 제어 규칙 (내부 메커니즘)

1. **우선순위 라우팅 규칙 (`ingestor.py`)**:
   - `HONEYTOKEN_ACCESS` 또는 `severity <= 2` $\rightarrow$ `security-logs.priority` 우선 배정
2. **70:30 가중 드레인 규칙 (`consumer_worker.py`)**:
   - 대량 트래픽 적체 시에도 허니토큰 경보를 지연 예산(2.0초 미만) 내 최우선 드레인 (일반 로그 30% 기아 방지 지분 보장)
3. **토큰 버킷 평탄화 규칙 (`TokenBucketRateLimiter`)**:
   - `MAX_LOGS_PER_SEC = 500.0`, `BATCH_SIZE = 100` (초당 5개 배치로 Netty 스레드 보호)
4. **개별 전송 분할 규칙 (`GELF_SPLIT_POST=true`, `delivery_client.py`)**:
   - 100건 배치를 20개 병렬 스레드로 개별 전송하여 Graylog OpenSearch에 100% 개별 인덱싱

---

## 7. 6단계: 발표 시연 실행 및 단계별 검증 방법

### 🧪 [시연 1] 미들웨어 유무(A/B) 성능 비교
```powershell
python scenario2-middleware/simulators/compare_middleware.py --count 1000
```
- Direct 전송(Netty 타임아웃 및 유실) vs SOAR 미들웨어(1,700 req/s, 0.00% 무손실 평탄화) 대조

### 🧪 [시연 2] 20,000건 대규모 스파이크 & 5단계 무손실 감사 리포트
```powershell
python scenario2-middleware/simulators/spike_test_demo.py --spike-count 20000
```
- 4.5초 만에 2만 건 수집 후 500 EPS로 안정 드레인 (Grafana 수평선 시연)
- `Sent (20,004) == Received (20,004) == Forwarded (20,004) == Graylog Stored (20,004)` 무손실 증명

### 🧪 [시연 3] 실제 웹 서버 로그인 10회 실패 시도 $\rightarrow$ Graylog 브루트포스 탐지 $\rightarrow$ n8n 자동 IP 차단 (SOAR 완결)

더 이상 가짜 모의 로그를 주입하지 않고, **실제 메인 API 서버(`:5000/api/login`)로 틀린 비밀번호를 10회 연속 전송하여 실시간 차단까지의 전 과정을 시연**합니다.

**방법 A. 원클릭 파이썬 자동화 스크립트 실행 (가장 추천 ⭐)**:
```powershell
python simulators/demo_bruteforce_attack.py
```
> 사전 차단 해제 -> 5회 연속 401 공격 주입 -> Graylog 탐지 -> n8n 자동 차단 -> 403 차단 검증까지 2초 만에 자동 완결됩니다.

**방법 B. 파워쉘 1줄 루프로 직접 요청 주입**:
```powershell
# 동일 IP(10.0.0.99)로 5회 연속 잘못된 API 키 주입 (401 유발)
1..5 | ForEach-Object {
    try {
        Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:5000/api/data" `
            -Headers @{"X-API-Key"="invalid-fake-key-$_"; "X-Demo-Client-IP"="10.0.0.99"}
    } catch {}
}
```

#### 시연 결과 확인 (발표 화면 3곳):
1. **Graylog Alerts (`http://localhost:9000/alerts`)**:
   - `[S2] Brute Force Attack Detection` 알림이 빨간색 Alert로 전환 (동일 IP 10회 실패 포착)
2. **n8n Executions (`http://localhost:5678`)**:
   - `Scenario 2 - Middleware Brute Force Response` 워크플로우가 `SUCCESS`로 자동 실행
   - `http://host.docker.internal:5000/automation/revoke-key`를 호출하여 IP 차단 완료
3. **웹앱 차단 확인 (공격자 재접속 시도 시 즉시 차단)**:
   ```powershell
   # 차단된 공격자가 다시 로그인 시도 -> HTTP 403 Forbidden 응답 확인!
   Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:5000/api/data" `
       -Headers @{"X-API-Key"="any-key"; "X-Demo-Client-IP"="10.0.0.99"}
   # 출력: {"error":"request_rejected","message":"Client IP has been blocked"} (HTTP 403)
   ```
   - 관제 대시보드(`http://127.0.0.1:5001/dashboard`)에 `10.0.0.99` 차단 IP 및 인시던트 티켓 등록 확인!
   - 관제 대시보드(`http://127.0.0.1:5001/dashboard`)에 차단 IP `10.0.0.99` 및 신규 인시던트 티켓 표시.
   - 공격자가 동일 IP로 재접속 시도 시 `HTTP 403 Client IP has been blocked`로 차단됨을 확인:
     ```powershell
     Invoke-RestMethod -Method Get -Uri http://127.0.0.1:5000/api/data -Headers @{"X-API-Key"="test-key-01"; "X-Demo-Client-IP"="10.0.0.99"}
     # -> 403 Forbidden: Client IP has been blocked 응답 확인
     ```
