# 시나리오 1: SOAR 미들웨어 및 Graylog · n8n 자동 대응 구축 가이드

트래픽 급증 시 하위 Graylog 과부하를 막기 위해 500 EPS 트래픽 평탄화와 WAL 기반 디스크 버퍼링을 수행합니다. 허니토큰 우선 라우팅, Graylog 공격 탐지 규칙, n8n 웹훅 기반 공격자 IP 자동 차단 파이프라인을 구축하고 검증하는 운영 가이드입니다.

---

## 목차
1. [전체 파이프라인 구성도](#1-전체-파이프라인-구성도)
2. [1단계: 미들웨어 및 관측 스택 기동](#2-1단계-미들웨어-및-관측-스택-기동)
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
│  SOAR 미들웨어 (scenario1-middleware :8000 / :9100)          │
│                                                             │
│  - Partitioned WAL Broker (SQLite WAL 모드 디스크 버퍼링)    │
│  - produce() 핫패스 인메모리 캐싱 (동기 DB 쿼리 0회)         │
│  - 2-Lane 우선순위 큐 (허니토큰 70:30 가중 드레인)          │
│  - 토큰 버킷 500 EPS 트래픽 평탄화 (Graylog 수신 큐 포화 방지)│
│  - GELF Split POST (동시 20개 스레드 단건 전송, 실패 선별 재시도) │
└──────────────────────────────┬──────────────────────────────┘
                               │ (2) 초당 500건 이하 정속 전송
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Graylog 6.1 SIEM (:9000 / :12201)                          │
│                                                             │
│  - GELF HTTP Input (:12201)                                 │
│  - [탐지 규칙] Brute Force Detection (1분 내 401 실패 >= 5회)│
│  - 알림: n8n HTTP Webhook 호출                              │
└──────────────────────────────┬──────────────────────────────┘
                               │ (3) 경보 발생 시 웹훅 호출
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  n8n SOAR 엔진 (:5678)                                      │
│                                                             │
│  - 워크플로우: Scenario 1 - Middleware Brute Force Response  │
│  - 공격자 IP (10.0.0.99) 및 탐지 사유 파싱                   │
│  - 차단 API 호출: POST /automation/revoke-key               │
│  - 디스코드 봇 실시간 알림 전송 (임베드 및 버튼 링크 포함)    │
│  - Graylog 응답 반환                                        │
└──────────────┬──────────────────────────────┬───────────────┘
               │ (4) IP 차단 및 API 키 폐기 요청 │ (5) 봇 알림 전송 (버튼 포함)
               ▼                              ▼
┌──────────────────────────────┐ ┌─────────────────────────────┐
│  웹 애플리케이션 (:5000 /:5001)│ │ Discord 채널 (#메신저-알림)  │
│                              │ │                             │
│  - MySQL blocked_ips 등록    │ │ - 침해사고 긴급 임베드 알림 │
│  - HTTP 403 차단 격리        │ │ - [📊 실시간 대시보드 열기] │
│  - 관제 대시보드 티켓 등록   │ │   Link 버튼 연동            │
└──────────────────────────────┘ └─────────────────────────────┘
```

---

## 2. 1단계: 미들웨어 및 관측 스택 기동

`scenario1-middleware` 디렉터리에서 Docker Compose로 수집기, 컨슈머 워커, Prometheus, Grafana를 기동합니다.

```powershell
# 1. 시나리오 1 디렉터리로 이동
cd scenario1-middleware

# 2. 컨테이너 빌드 및 백그라운드 기동
docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile observability up -d --build

# 3. 컨테이너 상태 점검
docker compose ps
```

### 서비스 접속 주소
- 미들웨어 수집기: `http://127.0.0.1:8000/v1/health`
- 컨슈머 워커 메트릭: `http://127.0.0.1:9100/metrics`
- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3000` (기본 계정: admin / admin)
- Graylog: `http://127.0.0.1:9000` (기본 계정: admin / admin)
- n8n: `http://127.0.0.1:5678`

---

## 3. 2단계: Graylog 인풋, URL 화이트리스트 및 탐지 규칙 설정

Graylog 웹 콘솔(`http://127.0.0.1:9000`)에서 아래 항목을 순서대로 구성합니다.

### 2-1. GELF HTTP 인풋 생성
미들웨어가 전송하는 로그를 수신할 포트를 활성화합니다.
1. 상단 메뉴 System > Inputs로 이동합니다.
2. 드롭다운에서 GELF HTTP를 선택하고 Launch new input을 클릭합니다.
   - Global: 체크
   - Title: `Middleware GELF Ingest`
   - Port: `12201`
   - Bind address: `0.0.0.0`
3. Save를 클릭하고 상태가 RUNNING으로 표시되는지 확인합니다.

---

### 2-2. URL 화이트리스트 등록
Graylog가 내부망의 n8n 웹훅 엔드포인트로 HTTP 요청을 보낼 수 있도록 허용 목록에 추가합니다.
1. System > Configurations로 이동합니다.
2. URL Whitelist > Update를 클릭합니다.
3. Whitelist Entries에 아래 두 주소를 추가하고 저장합니다.
   ```text
   http://host.docker.internal:5678/.*
   http://n8n:5678/.*
   ```

---

### 2-3. 전용 스트림 생성
미들웨어가 전달한 보안 로그를 별도 스트림으로 분류해 관리합니다.
1. 상단 메뉴 Streams > Create Stream을 클릭합니다.
   - Title: `SOAR Security Logs`
   - Index Set: Default index set 선택 후 저장합니다.
2. `SOAR Security Logs` 우측의 Manage Rules > Add stream rule을 클릭합니다.
   - Field: `source`
   - Type: match exactly
   - Value: `security-middleware`
3. Start Stream을 눌러 스트림을 활성화합니다.

---

### 2-4. 탐지 규칙 1: 무차별 대입 공격 탐지 및 n8n 웹훅 알림

1. 알림 생성:
   - Alerts > Notifications > Add Notification을 클릭합니다.
   - Title: `S1 n8n Webhook (Brute Force)`
   - Type: HTTP Notification
   - URL: `http://host.docker.internal:5678/webhook/scenario1-bruteforce`
   - Method: POST
   - Body Template:
     ```json
     {
       "event_type": "BRUTE_FORCE",
       "client_ip": "${event.fields.client_ip}",
       "timestamp": "${event.timestamp}",
       "title": "${event_definition_title}",
       "reason": "1분 내 인증 5회 이상 실패"
     }
     ```
2. 이벤트 정의 생성:
   - Alerts > Event Definitions > Create Event Definition을 클릭합니다.
   - Title: `[S1] Brute Force Attack Detection`, Priority: High
   - Condition Type: Aggregation
   - Search Query:
     ```text
     status_code:401 OR (event_type:APP_REQUEST AND status_code:401)
     ```
   - Search in the last: 1 minute, Execute every: 30 seconds
   - Streams: `SOAR Security Logs`
   - Group by Field(s): `client_ip`
   - Threshold: `count() >= 5`
   - Fields: Field Name `client_ip` / Value `${source.client_ip}` 매핑
   - Notifications: `S1 n8n Webhook (Brute Force)` 연결
   - Grace Period: 1 minute (60 seconds)
     집계 범위가 1분이고 실행 주기가 30초이므로 Grace Period를 60초로 설정합니다. 동일 공격 건에 대한 중복 알림을 방지합니다.

---

### 2-5. 탐지 규칙 2: 허니토큰 침입 탐지
1. Alerts > Event Definitions > Create Event Definition을 클릭합니다.
2. Title: `[S1] Honeytoken Infiltration Alert`, Priority: Critical
3. Condition Type: Filter
4. Search Query: `_honeytoken_alert:true OR event_type:HONEYTOKEN_ACCESS`
5. Threshold: `count() > 0` (1회 발생 즉시 탐지)

---

## 4. 3단계: n8n SOAR 자동 대응 워크플로우 등록

워크플로우 파일: [`scenario1-middleware/n8n/scenario1_bruteforce_response_workflow.json`](./n8n/scenario1_bruteforce_response_workflow.json)

### 등록 및 활성화 절차
1. n8n 콘솔(`http://127.0.0.1:5678`)에 접속합니다.
2. 좌측 Workflows 메뉴로 이동한 뒤 우측 상단 메뉴에서 Import from File을 선택합니다.
3. [`scenario1_bruteforce_response_workflow.json`](./n8n/scenario1_bruteforce_response_workflow.json) 파일을 업로드합니다.
4. 워크플로우 노드 구성을 확인합니다.
   - **Scenario 1 Webhook**: `POST /webhook/scenario1-bruteforce` 수신
   - **Normalize Brute Force Event**: 이벤트 페이로드에서 `client_ip`, `detection_reason` 등 정규화
   - **Block Attacker IP**: `{{ $env.AUTOMATION_WEBHOOK_BASE_URL || 'http://host.docker.internal:5000' }}/automation/revoke-key`를 호출하여 MySQL `blocked_ips` 테이블에 공격자 IP 등록 및 티켓 생성
   - **Format Alert Message**: 텍스트 알림 포맷 구성
   - **Send Discord Notification**: Discord Bot REST API(`https://discord.com/api/v10/channels/1567368969524879513/messages`)로 리치 임베드 및 `[📊 실시간 대시보드 열기]` 링크 버튼(`style: 5`) 전송
   - **Respond to Graylog**: Graylog에 성공 결과 반환
5. Discord Bot 인증 방식 설정:
   - 보안을 위해 Git 저장소 및 워크플로우 파일에는 실제 봇 토큰을 평문으로 남기지 않습니다.
   - **n8n Credential로 등록할 경우 (권장)**: HTTP Request 노드(`Send Discord Notification`) → Authentication: `Generic Credential Type` → `Header Auth` 선택 후 Name: `Authorization`, Value: `Bot {전달받은_봇_토큰}`을 등록합니다.
   - **환경 변수로 전달할 경우**: n8n 컨테이너 실행 환경 변수에 `DISCORD_BOT_TOKEN={전달받은_봇_토큰}`을 지정하면 자동으로 `Authorization: Bot {토큰}` 헤더가 주입됩니다.
6. 우측 상단 토글을 Active 상태로 전환하여 자동 실행을 활성화합니다.

---

## 5. 4단계: Prometheus 및 Grafana 알람 규칙

[`docs/observability/prometheus_alerts.yml`](./docs/observability/prometheus_alerts.yml)에 정의된 미들웨어 파이프라인 감시 규칙입니다.

| 알람 명칭 | 임계치 및 조건 | 심각도 | 설명 |
| :--- | :--- | :--- | :--- |
| `HighQueueLag` | `sum(queue_lag) > 1000` (2분 지속) | Warning | 유입량 대비 컨슈머 처리 지연으로 WAL 큐 적체 증가 |
| `DLQDepthNonZero` | `dlq_depth > 0` (5분 지속) | Warning | 전송 실패 또는 스키마 오류로 DLQ에 격리된 로그 존재 |
| `GraylogHigh5xxRate` | Graylog 5xx 에러율 > 5% (1분 지속) | Critical | 하위 SIEM 장애 발생으로 컨슈머가 지수 백오프 및 파티션 일시 정지 수행 중 |
| `InvariantViolationsDetected` | `invariant_violations > 0` (즉시) | Critical | 수신·전송·격리 원장 수량 불일치 감지 |
| `ConsumerNotProgressing` | 큐 적체가 있으나 3분간 전송량 0 | Critical | 컨슈머 워커 중단 또는 하위 네트워크 단절 상태 |

---

## 6. 5단계: 미들웨어 트래픽 제어 및 핫패스 동작 원리

### 6-1. 논블로킹 프로듀서 핫패스
수집 요청을 처리하는 `produce()` 경로에서 동기 SQLite 쿼리를 배제했습니다. 백그라운드 태스크가 `asyncio.to_thread`로 미소비 큐 적체량(`unconsumed_lag`)을 1초마다 갱신합니다. 토픽별 파티션 수는 최초 1회 조회 후 인메모리에 캐싱합니다. 쓰기 락 경합을 줄여 대량 트래픽 스파이크를 지연 없이 수용합니다.

### 6-2. 우선순위 라우팅 및 70:30 가중 드레인
`HONEYTOKEN_ACCESS` 이벤트나 심각도 2 이하의 긴급 로그는 `security-logs.priority` 토픽으로 분기합니다. 컨슈머는 70:30 가중 드레인 알고리즘을 사용합니다. 일반 로그 백로그가 누적되어도 배치 슬롯의 70%를 우선순위 레인에 할당합니다. 허니토큰 경보를 지연 예산(2.0초 미만, 실측 0.045초) 내에 전달합니다. 남은 30% 슬롯은 표준 레인에 할당하여 일반 트래픽의 기아 현상을 방지합니다.

### 6-3. 토큰 버킷 레이트 리미터 및 트래픽 평탄화
초당 500건 방출 상한(`MAX_LOGS_PER_SEC=500.0`)과 100건 마이크로 배칭(`BATCH_SIZE=100`, `BATCH_LINGER_MS=100`)을 적용합니다. Graylog 최대 처리 한계선인 650 EPS를 넘지 않도록 마진을 둡니다. 버스트 트래픽을 일정한 속도로 평탄화해 전송합니다.

### 6-4. GELF 단건 병렬 분할 전송과 선별 재시도
상용 Graylog 6.1의 GELF HTTP 인풋 규격에 맞춰 100건 배치를 20개 스레드 풀에서 병렬 단건 POST로 전송합니다. 부분 전송 실패가 발생하면 전체를 재전송하지 않습니다. `pending_indices`로 실패한 메시지만 선별 재시도하여 중복 전송 부하를 줄입니다.

---

## 7. 6단계: 시연 실행 및 검증 방법

### 시연 1: 다운스트림 장애 주입 및 OpenSearch 실측 검증

Direct Graylog 전송과 미들웨어 버퍼링 전송을 대칭 조건(단건 HTTP POST, 동시 연결 세마포어, 3.0초 SLA 타임아웃)에서 비교 실행합니다. 전송 도중 상용 Graylog 컨테이너를 정지(`docker pause`)시켜 데이터 유실률과 응답 지연을 측정합니다. OpenSearch Scroll API(`size=10000`)와 Python `set()`을 통해 실측 데이터를 검증합니다.

```powershell
# 시나리오 A(500건 / 3초 장애) 및 시나리오 B(20,000건 / 15초 장애) 종합 비교 벤치마크 실행
python simulators/compare_middleware.py --mode distress --scenario all
```

#### 종합 실측 결과 비교 (Scenario A & B)

```text
============================================================================================================================
 [RESILIENCE UNDER SIEM DISTRESS: COMPREHENSIVE DUAL-SCENARIO REPORT]
----------------------------------------------------------------------------------------------------------------------------
Metric                         | [Scenario A] 500 logs / 3s Pause           | [Scenario B] 20k logs / 15s Pause         
                               | Direct Graylog       | SOAR Middleware     | Direct Graylog       | SOAR Middleware    
----------------------------------------------------------------------------------------------------------------------------
Target Endpoint                | POST /gelf           | POST /v1/ingest     | POST /gelf           | POST /v1/ingest    
Client Concurrency             | 20 workers           | 20 workers          | 50 workers           | 50 workers         
Client Timeout                 | 3.0s                 | 3.0s                | 3.0s                 | 3.0s               
Client Retry Policy            | 1 Retry (0.5s)       | 0 (WAL Decoupled)   | 1 Retry (0.5s)       | 0 (WAL Decoupled)  
Downstream Distress            | Pause (3.0s)         | Pause (3.0s)        | Pause (15.0s)        | Pause (15.0s)      
----------------------------------------------------------------------------------------------------------------------------
Client Ingest Duration         | 3.89s                | 2.51s (WAL)         | 117.66s              | 117.67s (WAL)      
Client Ingest Throughput       | 128 req/s            | 199 logs/s          | 170 req/s            | 170 logs/s         
Service Latency (Pure RTT Avg) | 234.75 ms            | 9.89 ms             | 60.42 ms             | 12.01 ms           
  - Service P95 / P99          | 3003.6 / 3032.1 ms   | 19.4 / 27.5 ms      | 340.8 / 1049.2 ms    | 27.2 / 60.9 ms     
Total Latency (Queue+Wait Avg) | 2162.90 ms           | 9.86 ms             | 461.33 ms            | 12.24 ms           
  - Total P95 / P99            | 3000.0 / 3022.6 ms   | 30.5 / 39.8 ms      | 3000.0 / 3014.2 ms   | 36.8 / 68.2 ms     
Client Logs Accepted           | 295                  | 500                 | 17,757               | 20,000             
Client Logs Failed (Loss)      | 205                  | 0                   | 2,243                | 0                  
----------------------------------------------------------------------------------------------------------------------------
End-to-End Delivered (DB)      | 312 logs (312 uniq)  | 500 logs (500 uniq) | 18,356 logs (18,356 uniq) | 20,052 logs (20,000 uniq)
End-to-End Log Loss Rate       | 37.6% (188 lost)     | 0.0% (0 lost)       | 8.2% (1,644 lost)    | 0.0% (0 lost)      
End-to-End Duplicate Rate      | 0.0% (Clean)         | 0.0% (Clean)        | 0.0% (Clean)         | +0.3% (+52 dups)   
Architectural Verdict          | UNPROTECTED (188 lost) | 0 LOST, 0 DUPS (Observed) | UNPROTECTED (1,644 lost) | ZERO-LOSS (At-Least-Once, +52 dups)
============================================================================================================================
 * Note 1: 인제스터 단일 워커 최적 동시성(concurrency=50) 기준이며, 대규모 확장은 Kafka 전환 로드맵을 참조합니다.
 * Note 2: At-Least-Once 파이프라인으로 10초 초과 장기 다운타임 시 정상 재전송에 따른 중복이 발생할 수 있습니다.
 * Note 3: OpenSearch 적재 건수는 DB 실제 카디널리티 쿼리로 실측 검증했습니다(실패 시 UNVERIFIED 처리 후 sys.exit(2)).
```

#### 실측 핵심 분석
1. **Direct Graylog 전송의 한계**:
   - 다운스트림이 정지하면 50개 커넥션 풀 슬롯이 고갈됩니다. 새로 유입되는 요청은 슬롯을 얻지 못하고 3.0초 SLA 타임아웃으로 탈락합니다.
   - 시나리오 A(500건, 3초 정지)에서 **188건(37.6%) 유실**을 확인했습니다.
   - 시나리오 B(20,000건, 15초 정지)에서 **1,644건(8.2%) 유실**을 확인했습니다.
2. **SOAR 미들웨어의 완충 및 복원력**:
   - 미들웨어는 하위 SIEM 상태와 무관하게 로컬 WAL에 즉시 기록하고 202 응답을 반환합니다.
   - 평균 응답 지연 시간은 **12.01ms (P99 60.9ms)**, 체감 지연 시간은 **12.24ms**를 기록했습니다.
   - 20,000건을 유실 없이 100.0% 수용했습니다. OpenSearch에 고유 문서 20,000건을 정상 보존했습니다.
   - 10초를 초과하는 다운타임(15초) 환경에서는 타임아웃에 따른 재전송으로 52건(+0.3%) 중복이 발생했으나 At-Least-Once 전송 특성에 맞게 동작함을 확인했습니다.

---

### 시연 2: 2만 건 스파이크 완충 및 5단계 원장 대사 리포트

```powershell
python simulators/spike_test_demo.py --spike-count 20000
```

4.5초 동안 초당 4,448건 속도로 20,004건을 수집합니다. 최대 18,501건을 WAL 디스크에 버퍼링한 뒤 초당 500건 속도로 37.4초 동안 드레인합니다. 실행 완료 후 `Sent (20,004) == Received (20,004) == Forwarded (20,004) == Graylog Stored (20,004)` 등 5단계 전 구간에서 원장 수량이 일치하고 유실이 0건(0.00%)임을 확인합니다.

---

### 시연 3: 무차별 대입 공격 탐지 및 n8n 자동 IP 차단

메인 API 서버(`:5000/api/data`)로 잘못된 API 키를 5회 연속 전송합니다. HTTP 401 발생부터 Graylog 집계 탐지, n8n 웹훅 호출, 공격자 IP 차단(HTTP 403)까지 이어지는 방어 파이프라인을 검증합니다.

```powershell
# 시연 전용 자동화 스크립트 실행
python simulators/demo_bruteforce_attack.py
```

이전 차단 이력 초기화, 5회 연속 401 오류 유도, Graylog 집계 및 n8n 웹훅 비동기 대기, 차단 후 재접속 시 HTTP 403 차단 응답 확인까지 순차적으로 자동 실행합니다.

PowerShell 명령으로 직접 수동 검증할 수도 있습니다.
```powershell
# 동일 IP(10.0.0.99)로 5회 연속 잘못된 API 키 요청 전송
1..5 | ForEach-Object {
    try {
        Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:5000/api/data" `
            -Headers @{"X-API-Key"="invalid-fake-key-$_"; "X-Demo-Client-IP"="10.0.0.99"}
    } catch {}
}
```

#### 시연 결과 확인 위치
1. Graylog Alerts (`http://127.0.0.1:9000/alerts`): `[S1] Brute Force Attack Detection` 이벤트 발생 확인 (동일 IP 5회 이상 실패 집계)
2. n8n Executions (`http://127.0.0.1:5678`): `Scenario 1 - Middleware Brute Force Response` 워크플로우 실행 성공 및 `/automation/revoke-key` 호출 확인
3. 웹 애플리케이션 차단 및 관제 대시보드:
   ```powershell
   # 차단된 공격자 IP(10.0.0.99)로 재접속 시도 -> HTTP 403 Forbidden 반환 확인
   Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:5000/api/data" `
       -Headers @{"X-API-Key"="test-key-01"; "X-Demo-Client-IP"="10.0.0.99"}
   # 응답: {"error":"request_rejected","message":"Client IP has been blocked"} (HTTP 403)
   ```
   관제 대시보드(`http://127.0.0.1:5001/dashboard`)에서 차단된 IP(`10.0.0.99`)와 인시던트 티켓을 최종 확인합니다.
