# 아키텍처 설계 및 문제 해결 기록

로그 스파이크 제어와 무손실 파이프라인을 구축하며 해결한 기술 과제와 설계 결정, 실측 결과를 정리한 엔지니어링 개발 기록이다.

---

## 1. 백오프 대기 중 메시지 유실 방지와 오프셋 수동 커밋

하위 SIEM(Graylog)에 HTTP 503 오류나 네트워크 타임아웃이 발생하면 컨슈머는 세션을 유지하기 위해 지수 백오프 루프 내에서 `consumer.poll(0)`을 호출했다. 그러나 일반 `poll(0)`은 브로커에서 새 메시지를 디큐하여 반환하므로, 반환된 메시지를 처리하지 않고 버릴 경우 장애 복구 후 오프셋 커밋 시 해당 메시지까지 함께 커밋되어 영구 유실이 발생하는 문제가 있었다. 또한 인자 없는 `commit(asynchronous=False)`을 호출하면 컨슈머가 읽었던 모든 메시지의 오프셋이 일괄 커밋되는 결함이 존재했다.

이를 해결하기 위해 백오프 대기 루프에서 일반 `poll(0)` 호출을 제거했다. 파티션을 일시 정지(`pause`)한 상태에서만 폴링하여 메시지 디큐 없이 세션 하트비트만 유지하도록 변경했다. 또한 Graylog 전달이 확인된 배치 내 파티션별 최대 오프셋(`max_offset + 1`)만 지정하여 동기 커밋하는 [`ExplicitOffsetCommitter`](./src/middleware/offset_committer.py)를 구현했다.

단위 테스트를 통해 백오프 대기 중 디큐 횟수 0회와 파티션별 오프셋 정밀 커밋을 검증했다. 하위 시스템 장애가 지속되더라도 메시지 유실이 발생하지 않음을 확인했다.

---

## 2. 로그 개수 비례 토큰 버킷 스로틀링과 마이크로 배칭

초기 레이트 리미터는 배치 내 로그 개수와 무관하게 배치당 토큰 1개를 차감했다. 그 결과 10건짜리 부분 배치와 100건짜리 완전 배치가 동일한 대기 시간을 소모하여 큐 소진이 불필요하게 지연되었다. 또한 트래픽 유입 간격이 불규칙할 때 배치가 채워지지 않은 상태로 소규모 HTTP 요청이 빈번하게 발생하여 전송 효율이 저하되었다.

전송할 실제 로그 개수(`acquire(len(messages))`)만큼 토큰을 차감하는 [`TokenBucketRateLimiter`](./src/middleware/rate_limiter.py)를 구현했다. 초당 500건 제한 기준 100건 배치는 0.20초, 25건 배치는 0.05초만큼 비례하여 대기하도록 개선했다. 이와 함께 [`BrokerBatchPoller`](./src/middleware/batch_poller.py)에 마이크로 배칭 루프를 적용하여 `BATCH_SIZE(100건)`에 도달하거나 첫 메시지 수신 후 `BATCH_LINGER_MS(100ms)`가 지날 때까지 메시지를 수집하여 반환하도록 구성했다.

대량 유입 시 100건 단위 완전 배치로 묶어 초당 500건 이하로 전송 속도를 안정적으로 유지하고, 유입량이 줄어들면 불필요한 대기 없이 즉시 잔여 큐를 비우도록 했다.

---

## 3. 데드레터 큐(DLQ) 브로커 토픽 격리 및 자동 재처리

로컬 파일 기반 DLQ는 다중 컨테이너 환경에서 동시 쓰기 시 파일 락 경합이 발생했다. 또한 파싱할 수 없는 비정형 포이즌 메시지가 파티션 선두에 남으면 전체 배치가 반복 실패하여 후속 정상 로그까지 적체되는 파티션 블로킹 현상이 나타났다. 격리된 로그를 수동 개입 없이 복구할 절차가 없던 점도 운영상 한계였다.

DLQ 저장소를 브로커 전용 토픽(`security-logs.dlq`)으로 분리하는 [`BrokerDeadLetterPublisher`](./src/middleware/dlq_publisher.py)를 구현하고, 원본 토픽, 파티션, 오프셋, 실패 원인을 메시지 헤더에 함께 기록하도록 했다. 비정형 손상 메시지는 `is_poison()` 판별 로직을 통해 `security-logs.poison` 토픽으로 즉시 격리하고 오프셋을 커밋하여 파티션 블로킹을 해소했다. 아울러 유휴 주기마다 DLQ 메시지를 메인 토픽으로 재발행하는 재처리 루프를 구성했다.

비정형 메시지로 인한 큐 정체를 방지하고, 일시적 네트워크 장애로 격리된 정상 로그를 자동 복구하는 파이프라인을 완성했다.

---

## 4. 파티션·오프셋 조합 이벤트 ID(`_event_id`) 기반 멱등성 보장

최소 1회(At-Least-Once) 전송 파이프라인에서는 Graylog가 배치를 수신하여 디스크에 적재했더라도 HTTP 응답 타임아웃이 발생하면 컨슈머가 동일 배치를 재전송한다. 수신단에서 중복 식별 메커니즘이 없으면 저장된 로그 수가 전송한 로그 수보다 많아져 데이터 정합성이 깨진다.

GELF 페이로드에 브로커 파티션 번호와 오프셋을 조합한 불변 고유 식별자 `_event_id: f"{partition}:{offset}"`를 주입했다. 검증용 수신 서버([`mock_graylog_server.py`](./simulators/mock_graylog_server.py))에 인메모리 이벤트 ID 집합을 구축하여, 중복 수신 시 HTTP 202를 반환하되 중복 카운터만 증가시키고 고유 저장 카운터에는 합산하지 않도록 처리했다.

네트워크 재전송이 빈번하게 발생하는 환경에서도 `전송 로그 수 == 고유 저장 로그 수` 정합성을 유지함을 검증했다.

---

## 5. 슬라이딩 윈도우 EPS 및 최대 큐 적체량 집계

수집기와 컨슈머 워커가 분리된 프로세스로 동작하여 순간 유입 속도, 방출 속도, 최대 큐 적체량을 단일 API에서 통합 조회하기 어려웠다. 또한 단순 누적 카운터만으로는 실시간 버스트 양상을 추적할 수 없었다.

SQLite WAL 기반 공유 메트릭 스토어([`SharedMetricsStore`](./src/metrics_store.py))를 구현하여 1초 단위 버킷에 인바운드와 아웃바운드 처리량을 기록하고 30초가 지난 버킷은 자동 프루닝하도록 설계했다. 최근 1~3초 슬라이딩 윈도우 평균 EPS와 최대 큐 적체량(`peak_queue_lag`)을 단일 트랜잭션으로 원자적 갱신 및 조회하도록 구성했다.

트래픽 급증 시 유입 속도 변화, 500 EPS 방출 제한 준수 여부, 큐 적체 해소 전 과정을 단일 엔드포인트(`/v1/metrics`)에서 실시간으로 관측할 수 있게 되었다.

---

## 6. 책임 분리 리팩토링과 Pydantic v2 설정 검증

초기 컨슈머 워커는 단일 클래스에서 폴링, 속도 제어, GELF 변환, HTTP 전송, 오프셋 커밋, DLQ 처리를 모두 수행하여 모듈 간 결합도가 높고 단위 테스트 작성이 까다로웠다. 또한 환경변수를 단순 문자열로 파싱하여 음수 속도 제한이나 잘못된 설정값이 유입되어도 런타임 장애 시점에야 결함이 발견되었다.

워커의 역할을 [`BrokerBatchPoller`](./src/middleware/batch_poller.py), [`TokenBucketRateLimiter`](./src/middleware/rate_limiter.py), [`GelfTransformer`](./src/middleware/gelf_transformer.py), [`GraylogDeliveryClient`](./src/middleware/delivery_client.py), [`ExplicitOffsetCommitter`](./src/middleware/offset_committer.py) 등 단일 책임 컴포넌트로 분리했다. 이와 함께 Pydantic v2 기반 [`PipelineSettings`](./src/config.py)를 도입하여 프로세스 기동 시점에 타입과 값 범위를 검증하도록 개선했다.

컴포넌트별 독립적인 단위 테스트 작성이 수월해졌으며, 잘못된 환경변수 주입을 프로세스 기동 즉시 감지하여 런타임 오동작을 예방했다.

---

## 7. 메트릭 원장 분리와 5단계 회계 불변식 검증

프로듀서 버퍼 포화로 인한 영구 유실과 컨슈머 재시도 초과로 인한 DLQ 격리를 단일 카운터(`dropped_logs`)로 통합 관리했다. 이로 인해 DLQ 재전송 성공 시 카운터를 차감할 때 영구 유실 수치와 혼재되어 원장 정합성이 왜곡되는 결함이 있었다.

메트릭 원장을 영구 유실(`permanently_dropped_logs`)과 일시 격리(`dlq_quarantined_logs`)의 독립 카운터로 분리했다. 차감 연산 결과가 음수가 되면 즉시 트랜잭션을 롤백하고 `invariant_violations` 카운터를 증가시키는 방어 로직을 적용했다. 전체 수량 대사는 `Total Sent == Total Received == Total Forwarded + permanently_dropped + dlq_quarantined == Graylog Stored` 불변식을 적용했다.

영구 유실과 일시 격리를 명확히 구분하여 파이프라인 전 구간의 로그 수량을 오차 없이 대사할 수 있게 되었다.

---

## 8. 파티션 일시 정지 기반 백오프와 리밸런스 제어

하위 Graylog 장애가 장기화되어 백오프 대기 시간이 길어지면 브로커가 컨슈머를 세션 타임아웃으로 판정하여 컨슈머 그룹에서 퇴출하고 리밸런스를 반복하는 악순환이 발생할 위험이 있었다. 또한 리밸런스 시점에 전송 확인을 받지 못한 배치의 오프셋이 커밋되면 데이터 유실이 발생할 수 있었다.

백오프 진입 시 할당된 파티션을 `consumer.pause()`로 정지하고, 정지 상태에서 `poll(0)`을 호출하여 메시지 디큐 없이 세션 하트비트만 유지하도록 설계했다. 전송이 정상화되면 `resume()`으로 수집을 재개한다. 또한 `cooperative-sticky` 리밸런스 프로토콜에 맞춰 `on_revoke` 콜백에서는 미완료 배치를 커밋하지 않고 인플라이트 버퍼를 안전하게 비우며, `on_lost` 콜백에서는 소유권 상실에 따라 오프셋 커밋 없이 상태를 폐기하도록 구현했다.

하위 시스템 장애와 컨슈머 그룹 리밸런스 과정에서도 오프셋 오커밋과 메시지 유실을 방지했다.

---

## 9. 우선순위 레인 분리 및 70:30 가중 드레인

대규모 스캔 트래픽으로 수천 건의 로그가 적체된 상황에서 단일 FIFO 큐만 사용할 경우, 즉각 대응이 필요한 허니토큰 경보(`HONEYTOKEN_ACCESS`)가 일반 로그 뒤에 밀려 수십 초 이상 지연되는 문제가 발생했다. 반대로 우선순위 큐를 단순 엄격 우선순위로 처리하면 고위험 이벤트가 지속될 때 일반 로그가 전혀 처리되지 못하는 기아 현상이 발생했다.

허니토큰 및 심각도 2 이하의 고위험 이벤트를 우선순위 전용 토픽(`security-logs.priority`)으로 분기 라우팅했다. 컨슈머에는 70:30 가중 드레인 알고리즘을 도입하여 배치 슬롯의 70%를 우선순위 레인에 우선 배정하고 표준 레인에 최소 30%를 보장하도록 구성했다. 특정 레인이 비어 있을 때는 반대편 레인이 잔여 슬롯을 모두 활용하도록 했다.

공격자 IP 단위의 CRC32 파티셔닝으로 발생 순서를 보장하면서, 대규모 백로그가 적체된 환경에서도 허니토큰 경보를 지연 예산(2.0초 미만) 내인 0.045초에 즉시 전달했다.

---

## 10. 다중 인증, API 키 단위 속도 제한 및 민감정보 마스킹

비인가 트래픽 유입에 대응하기 위한 수집단 보호가 필요했으나, 클라이언트 IP 기반으로 속도 제한 버킷을 생성하면 IP 스푸핑 공격 시 메모리 점유량이 무한정 증가하는 취약점이 있었다. 또한 로그 페이로드에 포함된 평문 패스워드나 API 키가 SIEM으로 직접 적재되는 보안 누출 위험이 존재했다.

`X-API-Key` 상수 시간 비교와 HMAC-SHA256 서명(`X-Timestamp`, `X-Signature`) 검증 체계를 수립하고 수집 전용 키와 관리자 전용 키의 접근 권한을 분리했다. 클라이언트 IP 대신 API 키 식별자 단위로 인메모리 토큰 버킷을 운용하여 메모리 고갈 공격을 방어하고 한도 초과 시 HTTP 429와 `Retry-After` 헤더를 반환하도록 처리했다. 브로커 적재 직전에는 `password`, `token`, `secret`, `api_key` 등 민감 키의 값을 `"[REDACTED]"`로 일괄 마스킹하도록 파이프라인을 구축했다.

수집 엔드포인트의 위변조 방지, 비인가 접근 차단, 민감정보 비식별화 처리를 강화했다.

---

## 11. 스토리지 쓰기 헬스체크 및 클라이언트 Fail-Open 서킷 브레이커

단순 프로세스 생존 여부만 반환하는 헬스체크는 디스크 풀이나 SQLite WAL 쓰기 락 경합 상태에서도 HTTP 200을 반환하여 인프라 장애 감지가 지연되는 문제가 있었다. 또한 미들웨어 장애 발생 시 비즈니스 API 서버가 동기 HTTP 요청을 대기하면 워커 스레드가 고갈되어 메인 서비스 장애로 전파될 위험이 있었다.

`/v1/health` 호출 시 0.1초 타임아웃으로 SQLite WAL 쓰기 트랜잭션(`BEGIN IMMEDIATE; ROLLBACK;`)을 직접 프로브하여 스토리지 쓰기 가능 여부를 검증하고, 실패 시 RFC 7807 규격의 HTTP 503을 반환하도록 설계했다. 클라이언트([`SafeSecurityLogClient`](./simulators/client_integration_snippet.py))에는 비동기 유계 큐와 서킷 브레이커를 적용하여 비즈니스 로직 스레드는 큐 삽입 즉시 반환되도록 하고, 연속 실패 시 서킷을 열어 로컬 파일(`client_fallback_logs.jsonl`)로 우회 저장하는 Fail-Open 구조를 확립했다.

스토리지 장애를 즉시 식별할 수 있는 정밀 헬스체크를 구축하고, 관제 인프라의 장애가 상위 비즈니스 서버의 가용성을 훼손하지 않도록 격리했다.

---

## 12. Prometheus 메트릭 노출 및 Grafana 자동 프로비저닝

컨테이너 재기동이나 신규 배포 시마다 Grafana 웹 콘솔에서 Prometheus 데이터소스와 대시보드 JSON을 수동으로 등록해야 하는 운영 비효율이 있었다.

`grafana_datasource.yml`과 `grafana_dashboard_provider.yml` 프로비저닝 설정을 작성하고 `docker-compose.yml`의 볼륨 마운트로 바인딩하여 기동 시 자동 로드되도록 구성했다.

컨테이너 실행 즉시 별도의 수동 작업 없이 인바운드/아웃바운드 EPS, 파티션별 큐 적체량, 토큰 버킷 속도 제어 현황을 대시보드에서 실시간으로 모니터링할 수 있는 운영 환경을 구축했다.

---

## 13. Graylog 6.1 GELF HTTP 단건 전송 모드(`GELF_SPLIT_POST`) 및 커넥션 풀 튜닝

검증용 Mock 서버는 개행 구분 NDJSON 페이로드를 일괄 처리하지만, 상용 Graylog 6.1의 GELF HTTP 인풋은 HTTP 요청당 단일 JSON 객체만 파싱하도록 구현되어 있어 NDJSON 전송 시 첫 줄만 색인되고 나머지 로그가 누락되는 문제가 발견되었다. 반면 배치 내 로그를 순차 단건 요청으로 전송하면 네트워크 왕복 지연이 누적되어 목표 처리량(500 EPS)을 달성할 수 없었다.

[`GraylogDeliveryClient`](./src/middleware/delivery_client.py)에 `GELF_SPLIT_POST` 모드를 도입하고 `ThreadPoolExecutor(max_workers=20)` 스레드 풀을 통해 배치 내 100건 로그를 병렬 단건 POST로 전송하도록 구현했다. 부분 전송 실패 시 100건 전체를 재전송하여 대규모 중복을 유발하지 않도록 `pending_indices`를 추적하여 실패한 인덱스만 선별 재시도하도록 개선했다. 아울러 `httpx.Limits(max_connections=50, max_keepalive_connections=25)`로 Keep-Alive 커넥션을 유지하여 TCP 핸드셰이크 오버헤드를 최소화하고, 배치 내 모든 요청이 2xx 응답을 수신해야만 성공으로 판정하여 배치 원자성을 유지했다.

상용 Graylog 6.1 환경에서도 로그 누락 없이 초당 500건의 목표 처리 속도를 안정적으로 달성했다.

---

## 14. 프로듀서 `produce()` 핫패스 동기 SQLite 조회 제거 및 인메모리 캐싱

2만 건 연속 부하 테스트 중 인제스터 응답 지연과 클라이언트 `ReadError`가 간헐적으로 발생했다. 프로파일링 결과 FastAPI 이벤트 루프 스레드가 호출하는 [`LightweightProducer.produce()`](./src/middleware/lightweight_broker.py) 핫패스 내에서 미소비 래그 검사를 위한 `get_total_unconsumed_lag()`와 토픽 파티션 수 확인을 위한 `_get_num_partitions()` 등 2건의 동기 SQLite 쿼리가 매 로그마다 실행되고 있었다. 백그라운드 쓰기 스레드가 디스크 커밋을 위해 `BEGIN IMMEDIATE` 트랜잭션 락을 점유하는 동안 이벤트 루프 스레드가 락 대기(`busy_timeout=5.0s`)에 진입하면서 이벤트 루프 전체가 블로킹되는 병목이었다.

`produce()` 경로의 동기 DB 조회를 제거하고 인메모리 캐시(`get_cached_lag()`)만 참조하도록 구조를 전환했다. 미소비 래그 갱신은 FastAPI 수명주기(`lifespan`)에 등록된 백그라운드 루프(`_broker_lag_refresh_loop`)가 `asyncio.to_thread`를 통해 1초 주기로 워커 스레드에서 비동기 갱신하도록 분리했다. 토픽별 파티션 수 역시 런타임 불변 속성이므로 `_partition_count_cache`에 최초 1회만 조회 후 캐싱하여 이후 쿼리를 0회로 줄였다.

핫패스의 동기 DB 쿼리를 제거함으로써 20,000건 연속 2회(총 40,000건) 부하 테스트([`simulators/load_test_20k.py`](./simulators/load_test_20k.py))에서 `ReadError` 0건을 달성하고 회차당 8.7~9.5초(2,100~2,280 logs/s)의 수집 성능을 확인했다.

---

## 15. A/B 벤치마크 연속 실행 시 로컬 프록시 `TIME_WAIT` 소켓 고갈 원인 격리

14번 핫패스 최적화 후 미들웨어 단독 부하 테스트는 통과했으나, [`compare_middleware.py`](./simulators/compare_middleware.py)로 TEST A(Graylog 직접 전송) 직후 TEST B(미들웨어 전송)를 연속 실행하면 TEST B의 첫 요청에서 여전히 `httpx.ReadError`가 발생하는 현상이 나타났다.

인제스터 컨테이너 액세스 로그에는 요청 수신 기록이 없었고 호스트 `netstat` 분석 결과 `:8000` 포트는 `LISTENING` 상태로 요청이 컨테이너에 도달하지 못하고 끊어졌다. 반면 직전 TEST A가 호출한 `:12201` 포트에는 `max_keepalive_connections=0` 설정으로 인해 8,200개 이상의 `TIME_WAIT` 및 `FIN_WAIT_2` 소켓이 잔류하고 있었다. Windows Docker Desktop 환경에서 `localhost`는 IPv6(`[::1]`)로 우선 해석되어 `wslrelay.exe` 프록시를 경유하는데, TEST A의 수천 개 단발 소켓이 프록시 테이블을 고갈시켜 직후 연결된 TEST B의 소켓까지 프록시 계층에서 리셋된 것이 근본 원인이었다.

시뮬레이터의 기본 목적지 주소를 `localhost`에서 IPv4 루프백(`127.0.0.1`, `com.docker.backend.exe` 직결)으로 변경하여 `wslrelay.exe` 경유를 배제했다. 다수 클라이언트의 동시 연결 폭주를 모사하여 Graylog Netty 큐 포화를 유도해야 하는 TEST A의 벤치마크 취지를 유지하기 위해 `max_keepalive_connections=0`은 보존하되, TEST A와 TEST B 사이에 3초 쿨다운을 배치하여 소켓이 정상 회수되도록 조정했다.

5,000건 및 20,000건 연속 벤치마크에서 TEST A의 Netty 큐 포화 유실(20,000건 중 11,282건 유실, 56.4%)을 재현함과 동시에, TEST B는 단 한 건의 `ReadError` 없이 20,000건 전량을 무손실(0.00%)로 완주하여 미들웨어의 버퍼링 효과를 확인했다.

---

## 16. 웹 애플리케이션 및 n8n SOAR IP 자동 차단 연동

메인 API 서버([`app.py`](../web-app/app.py)), 미들웨어(:8000), Graylog(:12201), n8n SOAR 엔진(:5678)을 연계하여 침해 탐지부터 능동 방어까지 연결되는 실시간 보안 자동화 루프를 완성했다.

동일 IP에서 비인가 API 키 반복 호출(HTTP 401) 또는 비허용 IP 접근이 발생하면 미들웨어가 해당 보안 로그를 무손실 버퍼링하여 Graylog로 전달한다. Graylog의 집계 규칙이 1분 내 5회 이상 실패를 탐지하면 n8n 웹훅을 호출하고, n8n 워크플로우가 웹 애플리케이션의 차단 엔드포인트(`POST /automation/revoke-key`)를 트리거하여 MySQL `blocked_ips` 테이블에 공격자 IP를 즉시 등록한다.

후속 유입되는 모든 공격 요청은 웹 애플리케이션 인바운드 단에서 HTTP 403 Forbidden으로 차단되며, 관제 대시보드에 인시던트 티켓이 발급되는 전체 방어 파이프라인을 시뮬레이터([`demo_bruteforce_attack.py`](./simulators/demo_bruteforce_attack.py))로 검증했다.

---

## 17. 미들웨어 유무(A/B) 비교 및 2만 건 스파이크 실측 요약

미들웨어 유무에 따른 성능 차이를 실측한 A/B 벤치마크(20,000건, 동시성 300) 결과, 미들웨어 없이 Graylog로 직접 전송한 대조군은 Graylog Netty 수신 큐 포화 및 타임아웃으로 인해 20,000건 중 11,282건이 유실(유실률 56.4%)되었으며 총 34.55초가 소요되었다. 반면 미들웨어를 경유한 실험군은 인제스터가 18.36초 만에 20,000건을 전량 수락하여 클라이언트 블로킹을 조기 해제하고 백그라운드에서 초당 500건으로 안정적으로 평탄화하여 유실 0건(유실률 0.00%)으로 전송을 완료했다.

2만 건 스파이크 5단계 무손실 감사 리포트([`spike_test_demo.py`](./simulators/spike_test_demo.py)) 실측 결과, 4.5초 동안 초당 4,448건의 속도로 20,004건이 인입되었으며 최대 18,501건이 WAL 디스크에 버퍼링되었다. 컨슈머는 초당 500건 방출 상한을 준수하며 37.4초 만에 백로그를 전량 소진했다.

`Sent (20,004) == Received (20,004) == Forwarded (20,004) == Graylog Stored (20,004)` 등 5단계 전 구간 원장 수량이 정확히 일치하여 단 1건의 유실도 없는 엔드투엔드 무손실 파이프라인 동작을 확인했다.

---

## 18. 향후 과제

프로덕션 배포 파이프라인의 완성도를 높이기 위해 PR 생성 시 `pytest`, `ruff`, `mypy`를 자동 수행하는 CI 워크플로우를 구축할 계획이다.

단일 노드 스토리지 한계를 넘어 다중 서버로 수평 확장이 필요한 대규모 환경을 대비하여 외부 Kafka 및 Redpanda 클러스터 연동 어댑터의 실측 검증을 추진한다.

분산 추적 고도화를 위해 W3C `traceparent` 헤더를 OTLP Collector 및 Jaeger와 연동하여 구간별 세부 지연 시간을 시각화하는 모니터링 체계를 확충할 예정이다.

---

## 19. 고가용성·보안 아키텍처 및 벤치마크 통합 리팩토링 (2026)

파이프라인의 런타임 안정성, 인메모리 보안, 운영 매개변수 외재화 및 벤치마크 신뢰도를 개편했다.

스토리지 쓰기 헬스체크의 동기 블로킹 문제를 해소하기 위해 `/v1/health`의 SQLite WAL 프로브를 `await asyncio.to_thread(_probe_sqlite_storage, ...)`로 작업 스레드에 위임하고 0.3초 타임아웃 가드를 배치했다. 이를 통해 DB 락 경합 시에도 FastAPI 이벤트 루프가 멈추지 않도록 조치했다. 또한 인메모리 보안을 위해 레이트 리미터 버킷 키에 원문 API 키 대신 SHA-256 해시값을 저장하여 메모리 덤프나 로그를 통한 자격증명 노출 위험을 방지했다.

상용 Graylog 병렬 분할 전송 모드에서 발생하던 불필요한 중복 전송 문제를 해결하기 위해 `pending_indices` 기반 선별 재시도 메커니즘을 도입했다. Pydantic 스키마 검증기에서 전역 설정값을 변이하던 안티패턴을 제거하고 상태 비저장 검증 컨텍스트를 적용했다. 계층형 재시도 컨슈머(`RetryTopicConsumer`)와 DLQ 재발행(`replay()`)을 컨슈머 워커 백그라운드 태스크 및 관리자 API로 통합했다.

운영 편의성을 위해 SQLite PRAGMA 설정, 분할 스레드 수, SOAR 차단 웹훅 URL을 환경변수로 외재화했다. `compare_middleware.py`의 인위적 제약을 제거하고 대칭적 커넥션 풀(Keep-Alive=100, Timeout=3.0s, Concurrency=50 공통 안전 임계치)을 도입했다. 모든 시뮬레이터와 클라이언트에 HMAC-SHA256 표준 서명 검증을 기본 적용하고, 모의 Graylog 서버에 수신 통계 및 지연 주입 API를 추가하여 검증 기반을 정비했다.

---

## 20. 다운스트림 장애 복원력 벤치마크 고도화 및 아키텍처 한계 실측 검증 (2026)

미들웨어 유무에 따른 복원력을 검증하기 위해 1 Event = 1 HTTP POST 단건 전송 대칭 조건에서 실제 Graylog 다운스트림 정지(`docker pause`)를 주입하는 벤치마크를 수행하며, 과거 기록의 한계를 규명하고 시스템의 물리적 경계선을 실측으로 확립했다.

### 과거 벤치마크 왜곡 요인 규명 및 19번 결론 재검토
과거 17번의 2만 건 테스트는 Direct만 단건 동시성 300이었고, 미들웨어는 `POST /v1/ingest/batch`로 100건씩 묶어 `for` 루프로 순차 동기 전송(동시성=1, 총 200회 요청)한 수치였다. 19번에서 1 Event = 1 POST 단건 전송으로 전환한 뒤 동일한 `concurrency=300`을 인가했을 때, 실제로는 Uvicorn 단일 워커(`--workers 1`)의 리스닝 소켓 백로그 큐가 포화되며 대규모 `ConnectError`(4,190건)와 클라이언트 타임아웃이 발생함을 확인했다. 이에 따라 기존 19번의 "concurrency=300 안정 수용" 결론을 실측을 통해 교정했다.

### 정밀 Sweep 테스트 및 공통 안전 임계치(concurrency=50) 확립
직전 테스트의 `CLOSE_WAIT` 잔여 소켓 간섭을 차단하기 위해 10초 쿨다운을 적용한 동시성 Sweep(30~300)을 오름차순 및 셔플로 실측했다. 동시성 30(Avg 112ms)부터 300(Avg 1,730ms, P95 5,642ms)까지 RTT가 단조 증가함을 확인했다. `concurrency=50`에서는 단일 워커 기준 20,000건 전량 100% 수용(202 Accepted, Avg 210ms, P95 677ms)을 달성하여 3.0초 타임아웃 SLA를 충족했다. Direct(Graylog) 역시 `concurrency=50`에서 소켓 거부 없이 동작하므로, 50을 양측 모두가 다운스트림 장애(15초)와 정면 충돌할 수 있는 대칭적 공통 안전 임계치로 최종 확정했다.

### 프로세스 내부 스레드 경합(14번) vs 프로세스 간 파일 락 경합(신규 발견) 구분
`concurrency=300`의 소켓 거부를 해결하기 위해 Uvicorn을 `--workers 4` 멀티 프로세스로 전환하자 무장애 20,000건 전송 시 `ConnectError` 4,190건이 0건으로 해소(100.0% 수용)됨을 실측했다. 그러나 15초 다운타임 주입 시 4개 워커 프로세스가 동일한 `broker_wal.db` 파일에 동시 `BEGIN IMMEDIATE` 쓰기를 시도하면서 극심한 OS 파일 레벨 `SQLITE_BUSY` 락 경합이 발생했다.

이는 14번에서 해결한 "단일 프로세스 내부의 FastAPI 이벤트 루프 스레드 vs 백그라운드 쓰기 스레드 간 동기 쿼리 경합"과는 전혀 다른, 다중 프로세스 간 SQLite 단일 파일 쓰기 락의 물리적 한계라는 신규 아키텍처 경계선을 실측 확인한 것이다. 따라서 단일 임베디드 SQLite 파일 브로커는 단일 프로세스(`--workers 1`, concurrency=50 이하)에 최적화된 설계이며, 다중 워커나 다중 서버 수평 확장은 18번 로드맵에 명시된 외부 Kafka나 Redpanda 브로커로 전환해야 함을 정립했다.

### 측정 왜곡 제거: 레이턴시 분리 및 OpenSearch 카디널리티 정밀 검증
- 오픈루프 도착률 스케줄링 및 커넥션 슬롯 SLA 타임아웃 도입:
  과거 $t=0$ 동시 2만 개 코루틴 생성으로 인해 Direct의 19,900건이 클라이언트 세마포어 메모리(`async with semaphore:`)에 버퍼링되던 측정 왜곡과, 미들웨어의 Total Latency가 85초로 치솟던 큐잉 왜곡을 해결하기 위해, 미들웨어 지속 가능 처리량의 약 74% 수준인 목표 도착률(시나리오 A: 200 req/s, 시나리오 B: 170 req/s)로 순차 발송하는 오픈루프 스케줄러를 적용했다.
  각 요청은 예정 시점($t_{scheduled}$)부터 세마포어 슬롯 획득 및 HTTP 완료까지 엄격한 3.0초 SLA 타임아웃(`time_to_acquire = total_deadline - time.perf_counter() - min_post_timeout`)을 적용받는다. 다운스트림 장애(15초 `docker pause`) 동안 Direct는 50개 커넥션 슬롯이 완전히 잠겨 신규 유입 요청이 슬롯을 얻지 못하고 큐에서 즉시 폐기되어 실제 대규모 DB 유실로 이어진다. 반면 미들웨어는 WAL 즉시 반환(Service RTT ~12ms)으로 슬롯이 즉시 회수되어 큐 지연이 0ms에 수렴(Total Latency 12.24ms)하며 100% 무손실 수용을 달성했다.
- Scroll API 및 Python `set()` 전수 카디널리티 실측:
  OpenSearch `cardinality` 집계가 HyperLogLog++ 확률적 근사 오차($\pm 0.005\%$)로 인해 20,000건 집계 시 20,001건을 반환하던 한계와, 이를 가리던 `min(n, raw_unique)` 편법 캡 코드를 전면 제거했다. 대신 OpenSearch 고속 Scroll API(`size=10000`)로 전체 문서를 1초 이내에 순회하며 Python `set()`으로 전수 집계하여 단 1건의 오차도 없는 `exact_unique` 실측치를 도출했다. (조회 실패 시 `UNVERIFIED` + `sys.exit(2)` 정책 유지)
- 최종 실측 결과:
  - 시나리오 A (500건, conc=20, 3초 장애, 200 req/s):
    - Direct Graylog: Client Ingest 3.89s (128 req/s), Total Latency Avg 2,162.90ms (P99 3,022.6ms), Client Failed 205건(41.0%), OpenSearch 실측 312건 적재(312 고유), 최종 유실률 37.6% (188건 영구 유실) 관측 (`UNPROTECTED (188 lost)`).
    - SOAR Middleware: Client Ingest 2.51s (199 logs/s), Service Latency Avg 9.89ms, Total Latency Avg 9.86ms (P99 39.8ms), Client Accepted 500건 전량(100.0%), OpenSearch 실측 500건 적재(500 고유), 최종 유실률 0.0% (0건 유실, 0건 중복) 관측 (`0 LOST, 0 DUPS (Observed)`).
  - 시나리오 B (20,000건, conc=50, 15초 장애, 170 req/s):
    - Direct Graylog: Client Ingest 117.66s (170 req/s), Total Latency Avg 461.33ms (P99 3,014.2ms), Client Failed 2,243건(11.2%), OpenSearch 실측 18,356건 적재(18,356 고유), 최종 유실률 8.2% (1,644건 영구 유실) 관측 (`UNPROTECTED (1,644 lost)`).
    - SOAR Middleware: Client Ingest 117.67s (170 logs/s, Direct와 대칭 전송 시간 달성), Service Latency Avg 12.01ms, Total Latency Avg 12.24ms (P99 68.2ms, 과거 85초에서 12ms로 안정화), Client Accepted 20,000건 전량 수용(100.0%), OpenSearch 실측 20,052건 적재(20,000 고유 전량 보존), 최종 유실률 0.0% (0건 유실) 및 15초 장기 다운타임 하 At-Least-Once 정상 재전송 중복 +0.3% (+52 dups) 관측 (`ZERO-LOSS (At-Least-Once, +52 dups)`).
- 무중복 보장 과장 배제 및 At-Least-Once 한계 명시:
  미들웨어 컨슈머 워커 역시 10초 타임아웃 기반 At-Least-Once 파이프라인이므로, 시나리오 B처럼 10초를 초과하는 15초 장기 장애 시에는 워커의 정상 타임아웃 재전송으로 인해 중복(+52건)이 발생함을 실측으로 확인했다. 따라서 "무조건 무중복(Exactly-Once) 보장" 대신 "본 테스트 조건하 무손실 수용 및 At-Least-Once 복원력 입증(Zero-Loss with At-Least-Once Recovery)"으로 정직하고 투명한 기술 결론을 도출했다.
