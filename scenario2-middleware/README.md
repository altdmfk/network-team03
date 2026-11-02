# SOAR 로그 버퍼링 및 트래픽 제어 미들웨어

대량 트래픽이나 공격 로그가 급증할 때 하위 SIEM(Graylog)의 과부하를 방지하고 로그를 유실 없이 전달하는 경량 로그 파이프라인 미들웨어입니다.

---

## 빠른 시작: Graylog 연동 및 실행

### 1. Graylog 인풋 및 탐지 규칙 설정

#### 1.1 GELF HTTP 인풋 생성
1. Graylog 웹 콘솔(`http://127.0.0.1:9000`)에 접속합니다.
2. 상단 메뉴 **System** > **Inputs**로 이동합니다.
3. 드롭다운에서 **GELF HTTP**를 선택하고 **Launch new input**을 클릭합니다.
   - **Global**: 체크
   - **Title**: `Middleware GELF Ingest`
   - **Port**: `12201`
   - **Bind address**: `0.0.0.0`
4. **Save**를 누르고 인풋 상태가 **RUNNING**인지 확인합니다.

#### 1.2 SIEM 공격 탐지 규칙 등록
미들웨어가 500 EPS로 평탄화하여 전달한 로그를 기반으로 Graylog에서 공격 탐지 규칙을 생성합니다.
1. **무차별 대입 공격 탐지**:
   - **Alerts** > **Event Definitions** > **Create Event Definition**
   - **Title**: `[S2] Brute Force Attack Detection` (Priority: `High`)
   - **Condition Type**: **Aggregation**
   - **Search Query**: `status_code:401 OR (event_type:APP_REQUEST AND status_code:401)`
   - **Time Range**: `1 minute`, **Execute every**: `30 seconds`
   - **Group by Field**: `client_ip`
   - **Threshold**: `count() >= 5` (1분 내 동일 IP에서 5회 이상 실패 시 경보)
   - **Grace Period**: `1 minute` (동일 IP 중복 알람 억제)
   - **Notifications**: `S2 n8n Webhook (Brute Force)` 연결
2. **허니토큰 침입 탐지**:
   - **Title**: `[S2] Honeytoken Infiltration Alert` (Priority: `Critical`)
   - **Condition Type**: **Filter**
   - **Search Query**: `_honeytoken_alert:true OR event_type:HONEYTOKEN_ACCESS`
   - **Threshold**: `count() > 0` (1회 발생 시 즉시 탐지)

### 2. 도커 컴포즈 실행
기본 설정은 호스트의 Graylog(`http://host.docker.internal:12201/gelf`)로 로그를 전달합니다.

```powershell
# scenario2-middleware 디렉터리로 이동
cd scenario2-middleware

# 미들웨어 및 관측성 스택(Prometheus, Grafana) 동시 실행
docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile observability up -d --build

# 컨테이너 상태 확인
docker compose ps
```

> **단독 Mock Graylog 실행**:
> 상용 Graylog 없이 로컬 검증 서버로 단독 테스트할 때는 아래 명령을 실행합니다.
> ```powershell
> docker compose -f docker-compose.yml -f docker-compose.mock.yml up -d --build
> ```

---

### 3. 모니터링 화면 접속
- **Grafana 대시보드**: `http://127.0.0.1:3000` (`SOAR Middleware Observability` 대시보드와 Prometheus 데이터소스 자동 등록)
- **Prometheus**: `http://127.0.0.1:9090`
- **미들웨어 Ingestor**: `http://127.0.0.1:8000/v1/health`
- **Consumer Worker 메트릭**: `http://127.0.0.1:9100/metrics`

---

### 4. 벤치마크 및 검증 스크립트 실행

```powershell
# 1. 미들웨어 유무(A/B) 성능 비교 테스트
python simulators/compare_middleware.py --logs 5000 --concurrency 300

# 2. 2만 건 스파이크 완충 및 5단계 무손실 감사 리포트 검증
python simulators/spike_test_demo.py --spike-count 20000

# 3. 연속 부하 테스트 (20,000건 x 2회)
python simulators/load_test_20k.py

# 4. 전체 단위 및 통합 테스트 스위트 실행 (162개 테스트)
pytest -v
```

---

## 1. 핵심 설계 목표

1. **트래픽 평탄화와 하위 인프라 보호**
   - 수천 건의 로그가 순간 유입될 때 비동기 HTTP 수집기(`ingestor.py`, 포트 8000)가 요청을 즉시 수락합니다.
   - 수신한 로그는 디스크 기반 WAL 브로커(`broker_wal.db`, 3개 파티션)에 버퍼링합니다.
   - 컨슈머 워커(`consumer_worker.py`)는 토큰 버킷 레이트 리미터(`MAX_LOGS_PER_SEC=500.0`)와 마이크로 배칭(`BATCH_SIZE=100`, `BATCH_LINGER_MS=100`)을 적용합니다. Graylog가 처리할 수 있는 초당 500건 이하로 유입량을 제어하여 전송합니다.

2. **무손실 로그 파이프라인 (최소 1회 전송 및 멱등성)**
   - 최소 1회 전송 보장과 멱등성 키(`_event_id`)를 조합하여 데이터 정합성을 유지합니다.
   - 프로듀서는 인메모리 큐와 백그라운드 배치 커밋 스레드를 통해 WAL 디스크에 기록합니다. 큐 용량이나 미소비 래그 한도를 초과하면 즉시 HTTP 503 백프레셔를 반환하여 상위 서비스 장애 전파를 막습니다.
   - 컨슈머는 Graylog의 HTTP 2xx 응답이나 DLQ 격리를 확인한 뒤에만 파티션별 최대 오프셋(`max_offset + 1`)을 동기 커밋합니다.
   - GELF 페이로드에 `{partition}:{offset}` 형태의 고유 키를 부여합니다. 네트워크 재전송이 발생해도 하위 수신단에서 중복 로그를 식별할 수 있습니다.
   - Graylog 장애(HTTP 5xx, 연결 거부)가 발생하면 지수 백오프로 대기합니다. 대기 중에는 파티션을 일시 정지(`pause`)하여 메시지 디큐 없이 세션 하트비트를 유지합니다.

3. **프로듀서 핫패스 논블로킹 아키텍처**
   - 수집 요청을 처리하는 `produce()` 핫패스에서 동기 SQLite 조회를 배제하여 이벤트 루프 블로킹을 제거했습니다.
   - 미소비 큐 적체량(`unconsumed_lag`)은 FastAPI `lifespan`에 등록된 백그라운드 태스크가 `asyncio.to_thread`를 통해 1초 주기로 갱신하며, 프로듀서는 인메모리 캐시값만 참조합니다.
   - 토픽별 파티션 수는 런타임에 변하지 않으므로 최초 1회 조회 후 인메모리에 캐싱합니다. 이를 통해 백그라운드 쓰기 스레드의 트랜잭션 락(`BEGIN IMMEDIATE`)과 수집 스레드 간 경합을 원천 차단했습니다.

4. **공격자 IP 기준 순서 보장과 우선순위 레인**
   - `client_ip`를 파티션 키로 지정(`crc32(client_ip) % 3`)합니다. 동일 공격자(`10.0.0.99`)의 연속 공격 이벤트(`PORT_SCAN` $\rightarrow$ `BRUTE_FORCE` $\rightarrow$ `IOT_CONTROL`)는 같은 파티션에 유입 시각 순서대로 적재되고 소비됩니다.
   - 기만 공격 탐지(`HONEYTOKEN_ACCESS`)와 고위험 이벤트(`severity <= 2`)는 우선순위 토픽(`security-logs.priority`)으로 분기합니다.
   - 컨슈머는 70:30 가중 드레인 알고리즘을 사용합니다. 일반 로그 백로그가 쌓여도 허니토큰 경보를 지연 예산(2.0초 미만) 안에 먼저 전달합니다. 동시에 표준 레인 지분을 30% 보장하여 일반 트래픽의 기아 현상을 방지합니다.

---

## 2. Kafka 대신 자체 경량 WAL 브로커를 구현한 이유

대규모 분산 환경에서는 Apache Kafka가 표준이지만, 단일 노드 보안 인프라와 온프레미스 환경을 고려하여 자체 경량 WAL 브로커(`src/middleware/lightweight_broker.py`, `broker_wal.db`)를 구현했습니다.

1. **JVM 및 인프라 오버헤드 제거**
   - Kafka 브로커는 JVM 기반으로 컨테이너당 수백 MB~1GB 이상의 메모리를 점유합니다. 브로커 기동과 메타데이터 동기화에도 시간이 소요됩니다.
   - 자체 브로커는 파이썬 표준 라이브러리와 SQLite WAL 모드(`PRAGMA journal_mode=WAL`)로 동작합니다. 수십 MB 메모리만 사용하며 컨테이너 기동 즉시 트래픽을 처리합니다.

2. **네이티브 라이브러리 컴파일 의존성 제거**
   - `confluent-kafka`는 C 기반 `librdkafka` 바이너리 의존성을 가집니다.
   - 표준 SQLite 엔진을 사용하여 별도 네이티브 빌드 없이 모든 환경에서 동일하게 동작합니다.

3. **Kafka 호환 인터페이스 유지**
   - 외부 브로커는 제거했지만 핵심 메시징 메커니즘은 동일하게 구현했습니다.
   - IP 기반 CRC32 파티셔닝, 파티션별 단조 증가 오프셋, 컨슈머 그룹 오프셋 커밋, 워터마크 기반 래그 계산, Pause/Resume 기반 디큐 제어를 지원합니다.
   - 추후 멀티 노드 확장이 필요할 때 비즈니스 로직 수정 없이 Kafka 클라이언트로 교체할 수 있도록 인터페이스를 맞췄습니다.

---

## 3. 시스템 아키텍처

```mermaid
flowchart LR
    subgraph Producers["이벤트 발생원"]
        A["웹 애플리케이션 API 서버<br/>(:5000)"]
        B["공격 시뮬레이터 / 벤치마크 도구<br/>(spike_test_demo.py / compare_middleware.py)"]
    end

    subgraph Middleware["SOAR 로그 버퍼링 미들웨어"]
        D["FastAPI 비동기 인제스터<br/>(:8000)<br/>인증 · 레이트 리미터 · 민감정보 마스킹"]
        
        subgraph LightweightBroker["경량 파티셔닝 WAL 브로커 (SQLite WAL Mode)"]
            E1[("security-logs<br/>(표준 레인, 3 파티션)")]
            E2[("security-logs.priority<br/>(허니토큰/긴급, 3 파티션)")]
            E3[("security-logs.dlq<br/>(Dead-Letter Queue)")]
        end

        F["스로틀링 컨슈머 워커<br/>(:9100)<br/>500 EPS 상한 · 70:30 가중 드레인 · 오프셋 커밋"]
        G[("SQLite WAL 메트릭 원장<br/>(metrics.db)")]
    end

    subgraph SIEM["보안 관제 인프라"]
        I["Graylog 6.1 GELF HTTP<br/>(:12201)<br/>OpenSearch 2.5 인덱싱"]
    end

    subgraph Observability["관측성 스택"]
        J["Prometheus<br/>(:9090)"]
        K["Grafana 대시보드<br/>(:3000)"]
    end

    A -->|POST /v1/ingest| D
    B -->|대량 부하 인입| D
    D -->|표준 이벤트| E1
    D -->|허니토큰 / Severity <= 2| E2
    E1 -->|가중 드레인 30%| F
    E2 -->|가중 드레인 70%| F
    F -->|GELF HTTP POST| I
    F -->|전송 실패 시 격리| E3
    D <-->|수집 카운터 & 래그 기록| G
    F <-->|전송 카운터 & 처리 속도 기록| G
    D -->|GET /metrics/prometheus| J
    F -->|GET :9100/metrics| J
    J --> K
```

---

## 4. 디렉터리 및 주요 컴포넌트 구조

| 경로 | 설명 |
| :--- | :--- |
| [`Dockerfile`](./Dockerfile) | Python 3.11-slim 기반 멀티스테이지 빌드 및 비루트 계정(`appuser:10001`) 실행 환경 |
| [`docker-compose.yml`](./docker-compose.yml) | Ingestor, Consumer Worker, Prometheus, Grafana 프로비저닝 구성 |
| [`src/config.py`](./src/config.py) | Pydantic v2 기반 파이프라인 환경변수 검증 모델 (`PipelineSettings`) |
| [`src/ingestor.py`](./src/ingestor.py) | FastAPI 비동기 수집기, 백그라운드 래그 캐시 갱신 루프, 레이트 리미터, 헬스체크 |
| [`src/consumer_worker.py`](./src/consumer_worker.py) | 컨슈머 오케스트레이터, 마이크로 배칭, 70:30 가중 드레인, 백오프 및 오프셋 커밋 |
| [`src/metrics_store.py`](./src/metrics_store.py) | SQLite WAL 기반 메트릭 스토어 (`SharedMetricsStore`), 슬라이딩 윈도우 EPS 계산 |
| [`src/middleware/`](./src/middleware/) | 경량 WAL 브로커, 토큰 버킷, GELF 변환기, 전송 클라이언트, DLQ 퍼블리셔 |
| [`simulators/compare_middleware.py`](./simulators/compare_middleware.py) | 미들웨어 유무(Direct Graylog vs SOAR Middleware) A/B 벤치마크 도구 |
| [`simulators/spike_test_demo.py`](./simulators/spike_test_demo.py) | 2만 건 스파이크 인입, 드레인 모니터링 및 5단계 무손실 감사 리포트 검증 도구 |
| [`simulators/load_test_20k.py`](./simulators/load_test_20k.py) | 2만 건 연속 부하 주입 및 `produce()` 핫패스 무중단 검증 스크립트 |
| [`simulators/run_scenarios.py`](./simulators/run_scenarios.py) | 웹앱 공격 차단(1), 정상 트래픽 평탄화(2), 킬체인 및 허니토큰(3) 시나리오 실행기 |
| [`docs/observability/`](./docs/observability/) | Grafana 대시보드 JSON, 자동 프로비저닝 설정 및 Prometheus 알람 규칙 |

---

## 5. 검증 시나리오 및 벤치마크 결과

| 시나리오 | 실행 명령어 | 실측 결과 |
| :--- | :--- | :--- |
| **미들웨어 유무(A/B) 비교** | `python simulators/compare_middleware.py --logs 20000 --concurrency 300` | • **미들웨어 없을 때**: Netty 큐 포화 및 타임아웃으로 20,000건 중 **11,282건 유실(56.4%)**, 34.55초 소요<br>• **미들웨어 있을 때**: 20,000건 전량 수락(**유실 0.00%**), 18.36초 만에 인입 완료 후 500 EPS로 평탄화 전송 |
| **2만 건 스파이크 무손실 검증** | `python simulators/spike_test_demo.py --spike-count 20000` | • 4.5초 만에 20,004건 인입 (버스트 **4,448 logs/s**)<br>• 최대 **18,501건** WAL 디스크 버퍼링 후 초당 500건 상한으로 37.4초 동안 드레인<br>• `Sent 20,004 == Stored 20,004` (**유실 0건**) |
| **연속 고부하 안정성 검증** | `python simulators/load_test_20k.py` | • 20,000건 연속 2회(총 40,000건) 배치 인입 시 `ReadError` **0건**<br>• 회차당 8.7~9.5초 완료 (평균 **2,100~2,280 logs/s**) |
| **웹앱 공격 탐지 및 자동 차단** | `python simulators/run_scenarios.py -s 1` | • 비허용 IP 접근 시 HTTP 403 응답 및 인시던트 티켓 발급<br>• SOAR 웹훅 연동으로 공격자 IP 자동 차단 및 침해 로그 보존 |
| **킬체인 순서 보장 및 허니토큰** | `python simulators/run_scenarios.py -s 3` | • 백로그 적체 상황에서 허니토큰 경보를 **2.0초 이내**에 우선 전송<br>• 공격자 IP 기반 CRC32 파티셔닝으로 공격 단계 시계열 순서 유지 |
| **SIEM 장애 시 백오프 복구** | `python simulators/spike_test_demo.py --simulate-outage` | • Graylog 503 응답 시 컨슈머 파티션 일시 정지 및 지수 백오프 대기<br>• 복구 즉시 전송을 재개하여 유실 없이 전량 적재 |
| **단위 및 통합 테스트 스위트** | `pytest -v` | • 파티셔닝, 오프셋 커밋, 인메모리 캐시 갱신, DLQ 격리, 마스킹 등 **162개 테스트 통과** |

---

## 6. API 엔드포인트 명세

### 6.1 HTTP Ingestor (`http://127.0.0.1:8000`)

| 메서드 & 경로 | 상태 코드 | 설명 |
| :--- | :--- | :--- |
| `GET /v1/health` | `200 OK` / `503` | 인제스터 상태, 브로커 토픽 및 SQLite WAL 쓰기 락 상태 검사 |
| `POST /v1/ingest` | `202 Accepted` | 단일 보안 이벤트 검증 및 `client_ip` 파티션 키 기반 브로커 비동기 적재 |
| `POST /v1/ingest/batch` | `202 Accepted` | 다건 보안 이벤트 배열 일괄 수집 |
| `GET /v1/metrics` | `200 OK` | 실시간 파이프라인 지표 JSON 반환 (처리량, 큐 적체량, 5단계 원장 수치) |
| `GET /v1/metrics/prometheus` | `200 OK` | Prometheus 텍스트 포맷 메트릭 노출 |
| `GET /v1/admin/dlq` | `200 OK` | [Admin] DLQ 및 포이즌 토픽 적체 메시지 수 조회 |
| `POST /v1/admin/dlq/replay` | `200 OK` | [Admin] DLQ 메시지를 메인 토픽으로 지정 건수만큼 재전송 |
| `POST /v1/metrics/reset` | `200 OK` | [Admin] 메트릭 원장 카운터 및 처리량 버킷 초기화 |

---

## 7. 메트릭 원장 분리와 5단계 무손실 감사 리포트

유실(`permanently_dropped_logs`)과 일시 격리(`dlq_quarantined_logs`)를 분리하여 아래 회계 불변식을 검증합니다.

$$\text{Total Sent} = \text{Total Received} = \text{Total Forwarded} + \text{permanently\_dropped} + \text{dlq\_quarantined} = \text{Graylog Stored}$$

### 2만 건 스파이크 감사 리포트 출력 예시
```text
[5-STAGE END-TO-END ZERO-LOSS & BACKPRESSURE AUDIT REPORT]
  1. [Stage 1] Attack Load Generator Sent       : 20,004 logs (Burst Rate: 4,448 logs/sec)
  2. [Stage 2] HTTP Ingestor Accepted           : 20,004 logs (Peak Inbound: 4,448 logs/sec, permanently_dropped: 0)
  3. [Stage 3] Lightweight WAL Broker Buffered  : 20,004 logs (Peak Queue Lag Buffered: 18,501 logs)
  4. [Stage 4] Consumer Worker Throttled Commit : 20,004 logs (Peak Outbound: 500 / Limit: 500 logs/sec, dlq_quarantined: 0)
  5. [Stage 5] Graylog GELF Server Stored       : 20,004 logs (Duplicates Deduped: 0, DLQ Replayed: 0)
  • Priority Lane (Honeytoken) Latency    : 0.045s (Budget: < 2.0s) [PASS]

================================================================================================================
 [PASS] SCENARIO 2 VERIFIED: 100% SPIKE BUFFERED & 0.0000% LOG LOSS
        Sent (20,004) == Received (20,004) == Forwarded (20,004) + permanently_dropped (0) == Graylog Stored (20,004)
================================================================================================================
```

---

## 8. 보안 기능

1. **API 인증 및 권한 분리**
   - `X-API-Key` 헤더를 상수 시간(`hmac.compare_digest`)으로 비교하여 타이밍 공격을 방지합니다.
   - 요청 본문 HMAC-SHA256 서명(`X-Timestamp`, `X-Signature`) 검증과 300초 재생 공격 방지 윈도우를 지원합니다.
   - 수집 키(`INGEST_API_KEYS`)와 관리자 키(`ADMIN_API_KEY`)를 분리하여 관리자 API 접근을 통제합니다.

2. **API 키 단위 수집 속도 제한**
   - IP 스푸핑 시 메모리 테이블이 급증하는 문제를 막기 위해 API 키 식별자 단위로 토큰 버킷을 운용합니다.
   - 한도 초과 시 `HTTP 429 Too Many Requests`와 `Retry-After` 헤더를 반환합니다.

3. **민감정보 자동 마스킹**
   - 브로커 적재 전에 `raw_payload` 내부 민감 필드를 `"[REDACTED]"`로 치환합니다.
   - 대상 키워드: `password`, `passwd`, `token`, `api_key`, `secret`, `authorization`, `cookie`, `session` (대소문자 무관, 중첩 JSON 포함).

---

## 9. 관측성 및 모니터링

1. **Prometheus 메트릭 노출**
   - 수집 및 전송 카운터: `logs_received_total`, `logs_forwarded_total` (HTTP 2xx 확인 시 증가), `logs_permanently_dropped_total`, `dlq_published_total`
   - 게이지: `queue_lag{topic, partition}`, `dlq_depth`, `configured_max_logs_per_sec`, `invariant_violations`
   - 히스토그램: `graylog_delivery_latency_seconds`, `batch_size`, `end_to_end_latency_seconds`

2. **Grafana 대시보드 자동 프로비저닝**
   - 컨테이너 기동 시 Prometheus 데이터소스와 대시보드가 자동 등록됩니다.
   - 인입/방출 EPS, 파티션별 큐 적체량, 토큰 버킷 처리 속도, DLQ 깊이를 실시간으로 확인할 수 있습니다.

---

## 10. 한계점 및 운영 고려사항

1. **단일 호스트 SQLite WAL 스토리지 특성**
   - 현재 브로커는 단일 호스트 또는 공유 볼륨(`/app/state`) 위에서 동작합니다.
   - 단일 노드에서는 수천 EPS 스파이크를 완충할 수 있으나, 다중 노드로 수평 확장할 때는 NFS 파일 락 경합을 피하기 위해 외부 Kafka나 Redpanda 클러스터로 전환해야 합니다.

2. **트래픽 평탄화에 따른 일반 로그 지연**
   - 초당 수천 건의 스파이크를 초당 500건으로 제한하므로 대량 유입 시 일반 로그의 꼬리 지연 시간(p99)이 수 초간 증가합니다.
   - 이는 하위 Graylog와 OpenSearch의 과부하를 막기 위한 설계상 트레이드오프입니다. 긴급 경보는 70:30 우선순위 레인을 통해 2.0초 이내에 먼저 전달합니다.

3. **클라이언트 Fail-Open 원칙**
   - 미들웨어 장애가 메인 비즈니스 서버나 IoT 제어 보드로 전파되지 않도록 [`simulators/client_integration_snippet.py`](./simulators/client_integration_snippet.py)의 `SafeSecurityLogClient`는 비동기 큐와 서킷 브레이커로 동작합니다. 미들웨어 연속 실패 시 서킷을 열고 로컬 파일(`client_fallback_logs.jsonl`)에 우회 기록합니다.
