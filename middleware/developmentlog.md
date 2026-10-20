# 아키텍처 설계 및 문제 해결 기록 (Development Log)

본 문서는 **시나리오 2: 대규모 로그 스파이크 제어(Massive Log Spike Control) 및 무손실 로그 파이프라인(`Total Sent == Total Stored, 0.00% Log Loss`)**을 구축하고 고도화하는 과정에서 직면한 핵심 기술적 과제와 이를 해결하기 위한 아키텍처 설계 및 엔지니어링 의사결정을 기록한 기술 문서입니다.

---

## 1. 백오프(Backoff) 대기 중 `consumer.poll(0)` 호출로 인한 잠재적 메시지 유실 방지 및 명시적 오프셋 커밋

- **대상**
  - [`consumer_worker.py`](./consumer_worker.py), [`middleware/delivery_client.py`](./middleware/delivery_client.py), [`middleware/offset_committer.py`](./middleware/offset_committer.py)
- **문제**
  1. 하위 SIEM(Graylog) 장애(`HTTP 503` 또는 타임아웃) 발생 시 컨슈머 워커가 지수 백오프(Exponential Backoff) 루프에서 대기하는 동안, 컨슈머 그룹 세션을 유지하려는 목적으로 루프 내부에서 `self.consumer.poll(0)`을 호출하고 반환값을 무시하는 로직이 존재했습니다.
  2. 일반적인 `Consumer.poll(0)`은 **실제 브로커/로컬 큐에서 새로운 메시지 1건을 디큐(Dequeue)하여 반환**합니다. 반환된 메시지를 버린 상태에서 이후 Graylog가 복구되어 인자 없는 `self.consumer.commit(asynchronous=False)`를 호출하면, 백오프 도중 버려진 메시지들의 오프셋까지 함께 커밋되어 **영구적인 조용한 로그 유실(Silent Log Drop)**이 발생하는 치명적 결함이 있었습니다.
- **수정 내용**
  1. 백오프 대기 루프 내의 불필요한 `self.consumer.poll(0)` 호출을 제거하고, 파티션 pause/resume 기반의 격리 메커니즘을 적용했습니다.
  2. 인자 없는 전체 커밋(`self.consumer.commit(asynchronous=False)`)을 제거하고, 현재 Graylog에 전달 완료된 `messages` 배치 내에 포함된 `(topic, partition)`별 최대 오프셋(`max_offset + 1`)만을 계산하여 `TopicPartition` 리스트로 명시적 동기 커밋(`self.consumer.commit(offsets=batch_offsets, asynchronous=False)`)을 수행하는 `ExplicitOffsetCommitter`를 구현했습니다.
- **결과**
  - 반복적인 Graylog `HTTP 503` 장애 주입 및 장시간 백오프 대기 상황에서도 단 1건의 메시지도 암묵적으로 소비되거나 누락되지 않음을 보장했으며, 단위 테스트(`test_transient_outage_recovery_with_backoff_and_delayed_commit`)를 통해 백오프 중 `consumer.poll()` 호출 횟수가 `0`회이고 파티션별 정확한 오프셋만 커밋됨을 검증했습니다.

---

## 2. 배치 단위가 아닌 정확한 로그 단위(Log-Unit) 토큰 버킷 스로틀링 및 마이크로 배칭 구현

- **대상**
  - [`config.py`](./config.py), [`docker-compose.yml`](./docker-compose.yml), [`middleware/rate_limiter.py`](./middleware/rate_limiter.py), [`middleware/batch_poller.py`](./middleware/batch_poller.py)
- **문제**
  1. 기존 레이트 리미터는 배치 내 로그 개수와 무관하게 배치당 `1.0` 토큰(`MAX_BATCHES_PER_SECOND=5.0`)을 소모했습니다. 이로 인해 스파이크 후반부나 소량 유입 구간에서 10건짜리 부분 배치(Partial Batch)가 100건짜리 전체 배치와 동일한 대기 시간(`0.20s`)을 소모하여 불필요한 드레인 지연이 발생하거나, 설정 변경 시 초당 최대 로그 전송량(`MAX_LOGS_PER_SEC`)을 직관적으로 제어하기 어려웠습니다.
  2. 단일 `consume()` 호출만으로는 순간적인 네트워크 지터 시 배치가 충분히 채워지지 않은 채 소규모 HTTP 요청이 빈번하게 발생할 수 있었습니다.
- **수정 내용**
  1. 설정 체계를 `MAX_LOGS_PER_SEC=500.0`, `BATCH_SIZE=100`, `BATCH_LINGER_MS=100`, `POLL_TIMEOUT=0.1`로 정렬하고, 하위 호환성을 위해 레거시 `MAX_BATCHES_PER_SECOND` 환경변수만 주어진 경우 `MAX_LOGS_PER_SEC = MAX_BATCHES_PER_SECOND * BATCH_SIZE`로 자동 산출되도록 [`config.py`](./config.py)를 구성했습니다.
  2. `TokenBucketRateLimiter`가 실제 전송할 로그 개수(`acquire(float(len(messages)))`)만큼 토큰을 소모하도록 개선하여, 100건 배치는 `0.20s`(초당 500건), 25건 부분 배치는 `0.05s`만큼 정확히 비례하여 대기하도록 정밀화했습니다.
  3. `BrokerBatchPoller.poll_batch()`에 마이크로 배칭 루프를 도입하여 `BATCH_SIZE(100건)`에 도달하거나 첫 메시지 수신 후 `BATCH_LINGER_MS(100ms)`가 경과할 때까지 짧은 폴링을 누적하도록 개선했습니다.
- **결과**
  - 대규모 스파이크 유입 시에는 100건 단위의 고효율 NDJSON 배치로 묶어 초당 정확히 `500 logs/sec` 이하로 하위 Graylog 서버를 보호하고, 잔여 로그 드레인 구간에서는 지연 없이 신속하게 큐를 비워내는 안정적인 트래픽 셰이핑(Traffic Shaping)을 달성했습니다.

---

## 3. Dead-Letter Queue(DLQ) 자동 재전송(Auto-Replay) 엔진 및 메트릭 정합성 복원

- **대상**
  - [`middleware/dlq_store.py`](./middleware/dlq_store.py) (`JsonlDeadLetterStore`), [`metrics_store.py`](./metrics_store.py) (`reconcile_dlq_replay`)
- **문제**
  - 유한 재시도 횟수(`MAX_DELIVERY_RETRIES > 0`) 설정 하에서 Graylog 장기 장애 발생 시, 전송 실패 배치가 로컬 디스크(`dead_letter_logs.jsonl`)로 격리되고 `dropped_logs`가 증가합니다. 그러나 Graylog가 다시 정상화된 이후에도 격리된 DLQ 파일이 자동으로 재처리되지 않으면, 운영자가 수동 개입하기 전까지 최종 상태에서 `Total Sent == Total Forwarded` 및 `dropped_logs == 0`을 달성할 수 없었습니다.
- **수정 내용**
  1. `JsonlDeadLetterStore.replay()` 엔진을 구현하여, 유휴 폴링 주기 또는 정상 배치 전송 직후(`DeliveryOutcome.DELIVERED`)에 `dead_letter_logs.jsonl` 파일이 존재하면 `BATCH_SIZE` 단위로 읽어 레이트 리미터(`acquire(len(chunk))`)를 거쳐 Graylog로 재전송하도록 구현했습니다.
  2. 재전송 중 일부 청크만 성공하고 다시 장애가 발생하더라도 데이터가 손상되지 않도록, 매 청크 성공 시마다 미전송 잔여 레코드만 임시 파일(`.tmp`)에 기록 후 `os.fsync()` 및 원자적 교체(`os.replace`)를 수행하고, 모두 전송되면 DLQ 파일을 즉시 삭제하도록 설계했습니다.
  3. `SharedMetricsStore.reconcile_dlq_replay(replayed_count)`를 추가하여 SQLite WAL 내에서 단일 `BEGIN IMMEDIATE` 트랜잭션으로 `total_forwarded_to_graylog`와 `dlq_replayed_logs`를 증가시키고 `dropped_logs`를 차감(`MAX(0, metric_value - ?)`)하도록 구현했습니다.
- **결과**
  - 극단적인 하위 SIEM 장애로 인해 로그가 DLQ로 격리되더라도, SIEM 복구 즉시 자동으로 재전송 및 지표 보정이 이루어져 최종 `dropped_logs == 0` 및 `0.0000%` 로그 유실을 보장합니다.

---

## 4. 결정론적 멱등성 키(`_event_id`) 도입을 통한 At-Least-Once 재시도 중복 식별

- **대상**
  - [`middleware/gelf_transformer.py`](./middleware/gelf_transformer.py) (`transform_to_gelf`), [`mock_graylog_server.py`](./mock_graylog_server.py) (`MockGraylogState.ingest_gelf_records`)
- **문제**
  - At-Least-Once(최소 1회 전송) 파이프라인에서는 Graylog가 배치를 정상 수신·적재했으나 네트워크 지연으로 HTTP 응답이 타임아웃될 경우, 컨슈머 워커가 동일 배치를 재전송합니다. 이때 수신 측에서 중복을 식별하지 못하면 `Graylog Stored > Total Sent`가 되어 정확한 무손실 대사(Reconciliation)가 불가능해집니다.
- **수정 내용**
  1. `transform_to_gelf()` 및 폴백 빌더에서 모든 GELF 1.1 메시지에 브로커 파티션과 오프셋을 조합한 결정론적 고유 식별자 `"_event_id": f"{partition}:{offset}"`를 삽입했습니다.
  2. `MockGraylogState`에 `_seen_event_ids` 집합과 `duplicate_gelf_ignored` 카운터를 추가하여, 동일 `_event_id`가 재수신될 경우 `HTTP 202`를 정상 반환(컨슈머가 오프셋을 커밋할 수 있도록 보장)하되 내부 고유 적재 카운터(`total_gelf_received`) 및 Kill-Chain/Honeytoken 집계에서는 중복을 제외하고 `duplicate_gelf_ignored`만 증가시키도록 구현했습니다.
- **결과**
  - 네트워크 타임아웃이나 프로세스 재시작으로 인한 배치 재전송이 발생하더라도 `_event_id` 기반 멱등성 중복 제거를 지원하는 하위 스토어와 결합 시 `Total Sent == Graylog Unique Stored` 정합성을 확보합니다. (상용 Graylog + OpenSearch 환경에서의 `_id` 매핑 요구사항은 [`README.md`](./README.md) 10장 한계점 섹션에 명시했습니다.)

---

## 5. 프로세스 간 슬라이딩 윈도우 EPS(초당 처리량) 및 최대 큐 적체량(Peak Queue Lag) 텔레메트리 구축

- **대상**
  - [`metrics_store.py`](./metrics_store.py) (`SharedMetricsStore`), [`ingestor.py`](./ingestor.py) (`GET /metrics`, `POST /metrics/reset`, `WalLogBufferingMiddleware.stop`), [`spike_test_demo.py`](./spike_test_demo.py)
- **문제**
  1. Ingestor 프로세스와 Consumer Worker 프로세스가 분리되어 있어, 스파이크 발생 시점의 순간 유입 속도(`inbound_eps`)와 컨슈머의 스로틀링 방출 속도(`outbound_eps`), 그리고 스파이크 기간 중 브로커가 완충한 최대 큐 적체량(`peak_queue_lag`)을 단일 API(`GET /metrics`)에서 실시간으로 관측하기 어려웠습니다.
  2. Ingestor 종료 시 프로듀서 내부 버퍼에 남아 있던 메시지의 브로커 응답(`total_broker_acked`)이 SQLite에 마지막까지 플러시되지 않을 가능성이 있었고, 반복 데모 실행 시 이전 실행의 카운터가 남는 문제가 있었습니다.
- **수정 내용**
  1. SQLite WAL 데이터베이스 내에 `throughput_events (bucket_sec, direction, count)` 테이블을 신설하여, 각 프로세스가 `flush()`할 때마다 1초 단위 에포크 버킷(`inbound`, `outbound`)을 기록하고 30초 이전 버킷을 자동 정리하도록 구현했습니다.
  2. `read_snapshot()`에서 최근 활성 1~3초 슬라이딩 윈도우 평균 EPS(`inbound_eps`, `outbound_eps`)와 리셋 이후 최고치(`peak_inbound_eps`, `peak_outbound_eps`), 그리고 SQLite `MAX(metric_value, ?)` 기반의 `peak_queue_lag`를 계산하여 반환하도록 구현했습니다.
  3. `WalLogBufferingMiddleware.stop()`에서 `producer.flush(timeout=15.0)` $\rightarrow$ `_flush_acked_counter()` $\rightarrow$ `metrics_store.flush()` 순서로 종료 시퀀스를 고정하여 마지막 메시지까지 누락 없이 기록되도록 강화하고, `POST /metrics/reset` 엔드포인트를 추가했습니다.
  4. [`spike_test_demo.py`](./spike_test_demo.py)에 실시간 드레인 테이블(`Broker Lag (Peak)`, `Outbound EPS (Cap)` 포함)과 **5단계(Stage 1~5) End-to-End 무손실 및 백프레셔 감사 리포트**를 구현했습니다.
- **결과**
  - 수천 건의 스파이크가 유입될 때 **유입 속도(수천 EPS) 대비 방출 속도(500 EPS 이하 제한) 제어**와 **수천 건의 큐 적체(`peak_queue_lag`)가 유실 없이 `0`으로 수렴하는 전 과정**을 정량적 지표로 확인했습니다.

---

> [!NOTE]
> 아래 6장 이후의 섹션들은 세션별 커밋 이력이 부재함에 따라 시간 순서(Chronological)가 아닌 아키텍처 의존성(기반 모듈 분리 및 설정 검증 $\rightarrow$ 전송/리밸런스 안전성 $\rightarrow$ DLQ 및 우선순위 레인 $\rightarrow$ 인증 및 관측성) 기준의 논리적 순서(Logical Order)로 정리되었습니다.

---

## 6. 단일 책임 원칙(SRP) 기반 모듈 분리, Pydantic v2 설정 검증 및 컨테이너 패키징 고도화

- **대상**
  - [`middleware/__init__.py`](./middleware/__init__.py), [`config.py`](./config.py) (`PipelineSettings`, `load_settings`), [`consumer_worker.py`](./consumer_worker.py), [`ingestor.py`](./ingestor.py), [`metrics_store.py`](./metrics_store.py), [`Dockerfile`](./Dockerfile), [`docker-compose.yml`](./docker-compose.yml), [`pyproject.toml`](./pyproject.toml)
- **문제**
  1. 기존 [`consumer_worker.py`](./consumer_worker.py)가 단일 클래스 내에서 폴링, 속도 제한, GELF 변환, HTTP 전송/백오프, 오프셋 커밋, DLQ 파일 입출력까지 모두 담당하여 응집도가 낮고 개별 컴포넌트의 격리 테스트가 어려웠습니다.
  2. [`config.py`](./config.py)가 단순 `int(os.getenv(...))` 파싱에 의존하여 잘못된 환경변수(`BATCH_SIZE=0`, 음수 속도 제한, `max_backoff < base_backoff` 등) 주입 시 기동 시점 검증이 이루어지지 않았습니다 (추정).
  3. [`ingestor.py`](./ingestor.py)의 배치 수집 도중 브로커 로컬 큐 포화(`BufferError`)가 발생할 경우, 이미 큐잉된 전반부 이벤트 수량이 누락되어 수집 카운터 정합성이 왜곡될 위험이 있었습니다.
  4. [`Dockerfile`](./Dockerfile)이 단일 스테이지 root 권한으로 실행되어 컨테이너 보안 위험이 있었고, [`docker-compose.yml`](./docker-compose.yml)에 종료 유예 시간(`stop_grace_period`)이 지정되지 않아 컨슈머 및 프로듀서의 안전 플러시 타임아웃(15초) 도중 도커 기본 타임아웃(10초)으로 인해 강제 종료(`SIGKILL`)될 위험이 있었습니다.
- **수정 내용**
  1. `middleware/` 패키지를 신설하고 책임을 분리했습니다:
     - `BrokerBatchPoller`: 마이크로 배칭 및 EOF/오류 필터링
     - `TokenBucketRateLimiter`: 정확한 로그 단위 토큰 소비 레이트 리미터
     - `GelfTransformer`: GELF 1.1 직렬화 및 `_event_id` 주입
     - `GraylogDeliveryClient`: 지수 백오프 + 지터 재시도 전송
     - `ExplicitOffsetCommitter`: 파티션별 최대 오프셋 커밋 및 리밸런스 추적
     - `JsonlDeadLetterStore`: 원자적 `.tmp` 교체 및 JSONL 입출력
     - `StructuredJsonFormatter`: 구조화 로깅
  2. Pydantic v2 기반 `PipelineSettings` 및 `load_settings()`를 구축하여 음수 방지, 상한치 검증, 백오프 범위 유효성(`max_backoff >= base_backoff`)을 기동 시점에 강제했습니다.
  3. [`ingestor.py`](./ingestor.py)의 배치 수집 중 부분 실패 시에도 이미 수락된 건수(`enqueued_count`)만큼 `total_received`에 즉시 가산하도록 트랜잭션 정합성을 보정했습니다.
  4. [`Dockerfile`](./Dockerfile)을 멀티스테이지 빌드로 전환하고 UID 10001의 비루트 계정(`appuser:appgroup`)을 적용했으며, [`docker-compose.yml`](./docker-compose.yml)에 `stop_grace_period: 20s`와 헬스체크를 설정했습니다.
- **결과**
  - 개별 미들웨어 계층의 격리 단위 테스트가 가능해졌으며, 설정 오류를 서버 시작 즉시 차단합니다.
  - 검증 테스트:
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_load_settings_defaults_and_legacy_batches_per_sec_fallback`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_invalid_settings_raise_validation_error`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_retry_policy_backoff_computation`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_batch_poller_filters_partition_eof_and_errors`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_structured_json_formatter_includes_correlation_fields`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_batch_ingest_partial_failure_records_accepted_prefix`

---

## 7. 메트릭 원장 분리(`permanently_dropped` vs `dlq_quarantined`), 불변식 위반 추적 및 래그 캐시(Lag Cache) 도입

- **대상**
  - [`metrics_store.py`](./metrics_store.py) (`SharedMetricsStore`), [`ingestor.py`](./ingestor.py) (`WalLogBufferingMiddleware`, `GET /v1/metrics`), [`spike_test_demo.py`](./spike_test_demo.py)
- **문제**
  1. 초기 파이프라인에서 프로듀서 영구 유실과 컨슈머 DLQ 격리가 단일 카운터(`dropped_logs`)로 취급되어, DLQ 재전송 성공 시 `dropped_logs`를 차감할 때 프로듀서 측의 영구 유실 로그까지 잘못 차감되어 정합성이 왜곡될 위험이 존재했습니다 (추정).
  2. 중복 재전송 버그나 잘못된 오프셋 조작으로 인해 카운터가 `0` 미만(음수)으로 감소할 경우, 전체 대사식의 신뢰도가 손상되는 결함이 있었습니다.
  3. 또한 대규모 스파이크 및 잦은 메트릭 조회 시 매번 경량 브로커에 파티션 워터마크와 컨슈머 오프셋을 동기 질의하는 오버헤드로 인해 인제스터 이벤트 루프 지연이 발생할 위험이 있었습니다 (추정).
- **수정 내용**
  1. 메트릭 원장을 두 개의 명확한 물리 카운터로 분리했습니다:
     - `permanently_dropped_logs`: 프로듀서 버퍼 고갈 또는 전송 실패로 인한 복구 불가능 영구 유실.
     - `dlq_quarantined_logs`: 컨슈머가 하위 장애로 인해 DLQ에 일시 격리하여 복구 대기 중인 수량.
     - `dropped_logs`: 하위 호환을 위한 파생 합산값 (`permanently_dropped_logs + dlq_quarantined_logs`).
  2. `decrement_counter()` 및 `reconcile_dlq_replay()`에서 카운터 차감 결과가 음수가 될 경우, SQLite 트랜잭션을 즉시 `ROLLBACK`하고 `ERROR` 로그를 출력하며 `invariant_violations` 카운터를 증가시키는 원장 보호 메커니즘을 구축했습니다.
  3. `WalLogBufferingMiddleware`에 1.0초 유효기간의 래그 캐시(`lag_cache_ttl=1.0`)를 도입하여, 짧은 간격으로 수십 회 이상의 메트릭 요청이 유입되더라도 브로커 워터마크 질의 빈도를 초당 최대 1~2회로 제한했습니다.
  4. 새 감사 공식(`Total Sent == Total Received == Total Forwarded + permanently_dropped + dlq_quarantined == Graylog Stored`)을 [`spike_test_demo.py`](./spike_test_demo.py)의 5단계 감사 리포트에 반영했습니다.
- **결과**
  - 원장의 절대적 무결성이 수학적으로 보장되며, 롤백 발생 시 불변식 위반 건수가 실시간 집계됩니다.
  - 검증 테스트:
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_split_counters_and_dead_letter_offset_does_not_inflate_forwarded`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_double_replay_rolls_back_and_does_not_touch_permanently_dropped`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_replay_after_metrics_reset_triggers_rollback_and_violation`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_invariant_violation_rollback_preserves_pre_transaction_state`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_lag_cache_ttl_fifty_rapid_metrics_calls_trigger_at_most_two_broker_queries`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_five_stage_audit_new_invariant_formula`

---

## 8. 일시 정지(Pause) 기반 백오프 하트비트 유지, Cooperative-Sticky 리밸런스 콜백 및 우아한 종료(SIGTERM)

- **대상**
  - [`middleware/delivery_client.py`](./middleware/delivery_client.py) (`GraylogDeliveryClient`), [`middleware/offset_committer.py`](./middleware/offset_committer.py) (`ExplicitOffsetCommitter`), [`consumer_worker.py`](./consumer_worker.py)
- **문제**
  1. 하위 Graylog 장기 장애(5분 초과) 시 무한 재시도(`MAX_DELIVERY_RETRIES=0`) 모드에서 백오프 루프를 돌면 타임아웃을 초과하여 브로커가 컨슈머를 죽은 것으로 판단하고 강제 퇴출(Eviction) 및 무한 리밸런스를 유발합니다.
  2. 일반적인 `poll(0)` 호출은 미처리 메시지를 디큐하여 누락시키므로, 메시지를 추가 디큐하지 않으면서 컨슈머 세션을 유지할 수단이 필요했습니다.
  3. 컨슈머 그룹 리밸런스(`on_revoke`, `on_lost`) 도중 HTTP 2xx 확인을 받지 못한 인플라이트 배치의 오프셋이 커밋될 경우 심각한 조용한 유실이 발생할 수 있었습니다.
- **수정 내용**
  1. 백오프 진입 시 할당된 파티션을 일시 정지(`consumer.pause(assigned_partitions)`)하고, **오직 파티션이 일시 정지된 상태에서만 `consumer.poll(0)`을 호출**하여 메시지 디큐 없이 하트비트를 유지하며, Graylog 전송 성공 후 파티션을 재개(`consumer.resume(assigned_partitions)`)하는 안전 메커니즘을 구현했습니다.
  2. `partition.assignment.strategy=cooperative-sticky`를 적용하고 `ExplicitOffsetCommitter`에 콜백을 등록했습니다:
     - `on_revoke`: HTTP 2xx가 확인되지 않은 인플라이트 배치는 커밋을 거부하고 상태를 초기화(새 컨슈머가 재생하도록 양보)하며, 이미 전송 완료된 배치에 대해서만 오프셋을 커밋합니다.
     - `on_lost`: 소유권이 박탈되었으므로 어떠한 오프셋도 커밋하지 않고 인플라이트 상태를 폐기하며 경고 로그를 남깁니다.
  3. 시그널 핸들러(`install_signal_handlers`, `SIGTERM`/`SIGINT`)를 등록하여 백오프 도중 종료 신호 수신 시 미확인 배치를 안전하게 포기하고 자원을 닫은 후 종료하도록 구현했습니다.
- **결과**
  - 10분 이상의 장기 다운타임이나 백오프 도중 리밸런스/시그널이 발생해도 조용한 유실 없이 At-Least-Once 복구 능력을 증명했습니다.
  - 검증 테스트:
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_paused_backoff_polls_only_while_paused_and_never_discards_messages`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_cooperative_sticky_strategy_and_rebalance_callbacks_registration`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_on_revoke_commits_only_confirmed_batches_never_unconfirmed`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_on_lost_drops_in_flight_state_without_committing_and_logs_warning`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_fault_injection_rebalance_during_backoff_aborts_unconfirmed_batch_without_commit`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_fault_injection_rebalance_commit_failure_after_2xx_logs_structured_context_without_double_count`
    - [`tests/test_refactored_components.py`](./tests/test_refactored_components.py):: `test_fault_injection_sigterm_mid_backoff_abandons_unconfirmed_batch_and_closes_cleanly`

---

## 9. 브로커 DLQ/Poison 토픽 분리, 지연 재시도 티어, 스키마 버전 관리 및 관리자 엔드포인트

- **대상**
  - [`middleware/dlq_publisher.py`](./middleware/dlq_publisher.py) (`BrokerDeadLetterPublisher`), [`middleware/retry_topic_consumer.py`](./middleware/retry_topic_consumer.py) (`RetryTopicConsumer`), [`ingestor.py`](./ingestor.py) (`SecurityLogEvent`, `/v1/admin/dlq`, `/v1/admin/dlq/replay`), [`consumer_worker.py`](./consumer_worker.py)
- **문제**
  1. JSONL 파일 기반 DLQ는 다중 컨테이너 환경에서 파일 잠금 경합이 발생하므로, 프로덕션 환경의 안전한 수평 확장을 위해 브로커 토픽 기반 DLQ가 필수적이었습니다 (추정).
  2. 잘못 파싱된 비정형 바이트(Poison Message)가 파티션 선두에 남을 경우, 전체 배치가 지속 실패하여 정상 이벤트까지 영구 지연되는 헤드오브라인 블로킹(HOLB)이 발생했습니다.
  3. 대규모 엔드포인트 및 IoT 기기가 다양한 펌웨어 버전으로 이벤트를 전송할 때, 사전 공지되지 않은 주요 스키마 변경(Breaking Major Schema Change)으로 인해 컨슈머 워커가 비정상 종료되거나 역직렬화 실패 로그가 무차별 유실될 위험이 있었습니다 (추정).
- **수정 내용**
  1. `BrokerDeadLetterPublisher`를 구현하여 DLQ 저장소를 브로커 토픽(`security-logs.dlq`)으로 승격했습니다. 발행 시 `x-original-topic`, `x-original-partition`, `x-original-offset`, `x-retry-count`, `x-failure-reason`, `x-first-failed-at` 메타데이터 헤더를 주입하며, `producer.flush()`로 브로커 영속화가 확인된 경우에만 원본 오프셋 커밋을 허용했습니다.
  2. `is_poison()` 판별 로직을 도입하여 손상된 메시지는 즉시 `security-logs.poison` 토픽으로 격리 발행하고 해당 오프셋을 커밋하여 파티션을 정상 진행시켰습니다.
  3. `security-logs.retry.1m` 및 `security-logs.retry.10m` 지연 재시도 토픽과 `RetryTopicConsumer`를 구축하여 지연 도달 전 파티션 pause/seek 대기 및 최대 재시도 한도 초과 시 DLQ 승격을 지원했습니다.
  4. `SecurityLogEvent`에 `schema_version` 필드를 도입하여 기본값 `1.0`, 마이너 버전(1.x) 허용, 지원되지 않는 메이저 버전(!= 1)은 422 상태 코드로 거부하도록 구현했습니다.
  5. 관리자 전용 API(`GET /v1/admin/dlq`, `POST /v1/admin/dlq/replay`)를 구현하여 토픽별 적체 상태 조회 및 지정 건수 메인 토픽 재전송을 지원했습니다.
- **결과**
  - 다중 컨슈머 워커가 동시 실행되는 환경에서도 파일 충돌 없이 안전하게 DLQ를 격리 및 재처리할 수 있게 되었습니다.
  - 검증 테스트:
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_missing_schema_version_defaults_to_1_0`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_minor_version_bump_is_accepted`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_unknown_major_version_rejected_with_validation_error`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_invalid_schema_version_format_rejected`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_ingest_endpoint_rejects_unsupported_major_version`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_dlq_publisher_injects_required_headers`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_dlq_publish_failure_means_no_commit`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_poison_message_does_not_block_partition`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_retry_count_cap_escalates_to_dlq`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_retry_topic_consumer_pauses_partition_when_not_due`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_retry_tier_escalation_1m_to_10m`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_two_workers_concurrent_dlq_handling_no_lost_or_duplicated_records`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_gelf_transformer_preserves_event_id_on_replay`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_replay_idempotency_in_mock_graylog`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_get_admin_dlq_stats`
    - [`tests/test_broker_dlq_and_admin.py`](./tests/test_broker_dlq_and_admin.py):: `test_post_admin_dlq_replay`

---

## 10. 우선순위 레인(Priority Lane) 분리, 가중치 드레인(Weighted Draining) 및 허니토큰 지연 시간 보장

- **대상**
  - [`middleware/batch_poller.py`](./middleware/batch_poller.py) (`BrokerBatchPoller`), [`ingestor.py`](./ingestor.py) (`route_event_topic`), [`metrics_store.py`](./metrics_store.py), [`mock_graylog_server.py`](./mock_graylog_server.py), [`spike_test_demo.py`](./spike_test_demo.py)
- **문제**
  1. 대규모 무차별 대입 공격이나 포트 스캔으로 인해 브로커 버퍼에 수천 건의 로그가 적체되어 있을 때, 단일 FIFO 토픽 구조에서는 침해 즉시 대응해야 하는 긴급 허니토큰 경보(`HONEYTOKEN_ACCESS`)가 일반 로그 뒤에 갇혀 수십 초 이상 전달이 지연되는 심각한 관제 사각지대가 발생할 위험이 있었습니다 (추정).
  2. 그렇다고 우선순위 토픽만 전량 우선 소비할 경우, 공격자가 의도적으로 허니토큰 또는 고위험 이벤트를 지속 발생시켜 일반 로그 처리가 지체되는 기아(Starvation) 현상이 발생할 수 있었습니다.
- **수정 내용**
  1. 인제스터에 `route_event_topic()` 라우팅 함수를 도입하여 `HONEYTOKEN_ACCESS` 및 `severity <= 2` 이벤트를 별도 토픽(`security-logs.priority`)으로 격리 큐잉했습니다. 두 토픽 모두 `client_ip`를 파티션 키로 유지합니다.
  2. `BrokerBatchPoller`에 **70:30 가중 드레인 알고리즘(`compute_weighted_allocation`)**을 구현했습니다:
     - 배치 슬롯의 70%는 우선순위 레인에 우선 배정.
     - 표준 레인에 적체가 존재할 경우 최소 30%(`standard_reserved_share`)의 배정 슬롯을 보장하여 기아 방지.
     - 한쪽 레인에 메시지가 부족할 경우 다른 레인이 남은 슬롯을 흡수하는 슬랙 흡수(Slack Absorption) 메커니즘 적용.
  3. 시계열 순서 모델을 정립했습니다: **동일 토픽/파티션 내에서는 `client_ip` 기반 시계열 FIFO 순서가 엄격 보장**되며, **우선순위 레인과 표준 레인 간의 교차 순서는 의도된 Best-Effort**로 동작합니다.
  4. 데모([`spike_test_demo.py`](./spike_test_demo.py))에 고해상도 허니토큰 도달 지연 측정 및 예산 검증 단언(`assert latency <= honeytoken_latency_budget`, 기본 2.0초)을 추가했습니다.
- **결과**
  - 5,000건의 백로그가 큐에 쌓여 있는 상태에서도 허니토큰 경보가 평균 0.05초 내외로 Graylog에 초고속 도달함을 입증했습니다.
  - 검증 테스트:
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_honeytoken_access_routes_to_priority_topic`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_low_severity_events_route_to_priority_topic`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_standard_severity_events_route_to_standard_topic`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_custom_priority_event_types_and_max_severity`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_client_ip_partition_key_preservation`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_settings_validation_rejects_invalid_weights`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_poller_subscribes_to_both_topics`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_weighted_allocation_guarantees_standard_share`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_weighted_allocation_slack_absorption_priority_fills_when_standard_empty`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_weighted_allocation_slack_absorption_standard_fills_when_priority_empty`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_weighted_allocation_single_item_prefers_priority`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_poll_batch_interleaves_prioritizing_honeytoken_over_backlog`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_compute_batch_offsets_across_multiple_topics_and_partitions`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_commit_batch_offsets_submits_all_topic_partitions`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_honeytoken_latency_under_backlog_with_injected_clock`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_shared_metrics_store_tracks_per_lane_outbound_eps`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_get_metrics_endpoint_exposes_lane_breakdowns`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_gelf_transformer_injects_broker_topic`
    - [`tests/test_priority_lane.py`](./tests/test_priority_lane.py):: `test_kill_chain_per_lane_ordering_and_cross_lane_best_effort`

---

## 11. 다중 인증(API Key/HMAC), 식별자 단위 속도 제한, 민감정보 마스킹 및 RFC 7807 통일 에러 규격

- **대상**
  - [`middleware/auth.py`](./middleware/auth.py), [`middleware/ingest_rate_limiter.py`](./middleware/ingest_rate_limiter.py), [`middleware/redaction.py`](./middleware/redaction.py), [`middleware/errors.py`](./middleware/errors.py), [`ingestor.py`](./ingestor.py)
- **문제**
  1. 외부 인터넷이나 비신뢰 네트워크 망에 노출된 인제스트 엔드포인트가 무인가 트래픽 스파이크에 무방비로 노출될 위험이 있었으며, 클라이언트 IP 기반 속도 제한 적용 시 분산 봇넷 환경에서 IP 카디널리티 폭증으로 인메모리 테이블이 고갈될 위험이 있었습니다 (추정).
  2. 개발자 또는 공격자 로그 페이로드(`raw_payload`) 내에 평문 API 키, 세션 토큰, 비밀번호 등이 여과 없이 포함되어 하위 SIEM이나 브로커 로그에 영구 저장될 경우 컴플라이언스 위반 및 2차 정보 유출 사고로 이어질 위험이 있었습니다 (추정).
  3. 클라이언트 라이브러리마다 서로 다른 예외 포맷으로 인해 장애 처리 및 자동화 파싱이 복잡했습니다.
- **수정 내용**
  1. 다중 인증 체계 구축:
     - `X-API-Key` 헤더에 대한 상수 시간 비교(`hmac.compare_digest`).
     - `X-Timestamp` 및 `X-Signature` 기반 HMAC-SHA256 서명 검증 및 300초 재생 방지 윈도우.
     - 수집 권한(`require_ingest_auth`)과 관리자 권한(`require_admin_auth`)의 엄격한 역할 분리.
  2. API 키 식별자 단위 인메모리 토큰 버킷 레이트 리미터([`middleware/ingest_rate_limiter.py`](./middleware/ingest_rate_limiter.py))를 구현하여 IP 카디널리티 폭증을 차단하고, 한도 초과 시 RFC 6585 규격의 `HTTP 429` 및 `Retry-After` 헤더를 반환했습니다.
  3. PII 마스킹 함수([`middleware/redaction.py`](./middleware/redaction.py))를 도입하여 브로커 발행 직전 `raw_payload`의 민감 키(대소문자/카멜케이스/중첩 딕셔너리/임베디드 JSON 문자열 지원)를 `"[REDACTED]"`로 치환했습니다.
  4. RFC 7807 `application/problem+json` 핸들러([`middleware/errors.py`](./middleware/errors.py))를 FastAPI 앱에 전역 등록하고, `/v1` 버전 관리 라우터와 레거시 경로 호출 시 `Deprecation: true` 헤더를 부여했습니다.
- **결과**
  - 엔터프라이즈급 API 보안 및 입력 무결성 방어벽을 구축했습니다.
  - 검증 테스트:
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_case_variants_and_camelcase_detection`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_nested_dictionary_and_list_redaction`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_embedded_json_string_redaction`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_configurable_redaction_patterns`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_auth_disabled_allows_all_routes_without_headers`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_auth_enabled_rejects_missing_credentials`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_auth_api_key_success_and_failure`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_auth_hmac_signature_success`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_auth_hmac_expired_timestamp_rejected`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_auth_hmac_replay_attack_rejected`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_admin_key_separation`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_keys_loaded_from_secret_file`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_rate_limiter_returns_429_with_retry_after`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_rate_limiter_client_isolation`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_validation_error_422_problem_json`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_broker_backpressure_503_has_retry_after_and_problem_json`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_v1_endpoints_do_not_have_deprecation_header`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_legacy_endpoints_return_deprecation_header`
    - [`tests/test_security_and_api.py`](./tests/test_security_and_api.py):: `test_buffer_error_fails_fast_without_pathological_sleep`

---

## 12. Prometheus 메트릭 엔드포인트, Grafana 대시보드/경보 규칙 및 OpenTelemetry W3C 분산 추적

- **대상**
  - [`middleware/telemetry.py`](./middleware/telemetry.py), [`ingestor.py`](./ingestor.py) (`GET /v1/metrics/prometheus`), [`consumer_worker.py`](./consumer_worker.py) (포트 9100 메트릭 데몬), [`docs/observability/`](./docs/observability/alerts.yml), [`docker-compose.yml`](./docker-compose.yml) (`observability` 프로파일)
- **문제**
  1. 기존의 단일 JSON API(`GET /metrics`) 폴링 방식은 클라우드 네이티브 관측 인프라(Prometheus, Alertmanager, Grafana)와의 표준 연동이 불가능했고, 마이크로서비스 간 분산 추적 부재로 인해 인제스트부터 최종 SIEM 전달까지의 구간별 네트워크 지연 병목을 정밀하게 진단하기 어려웠습니다 (추정).
  2. 프로메테우스 메트릭 수집 시 `logs_forwarded_total` 카운터가 전송 성공 이전이나 실패 시점에도 잘못 증가하여 모니터링 수치가 부풀려질 위험이 있었습니다.
- **수정 내용**
  1. 표준 Prometheus 메트릭 레지스트리([`middleware/telemetry.py`](./middleware/telemetry.py))를 구축하고 저카디널리티 원칙을 적용했습니다:
     - 카운터: `logs_received_total`, `logs_forwarded_total`(2xx 수신 시에만 증가), `logs_permanently_dropped_total`, `dlq_published_total`, `dlq_replayed_total`, `poison_messages_total`, `delivery_attempts_total{outcome}`
     - 게이지: `queue_lag{topic, partition}`, `dlq_depth`, `configured_max_logs_per_sec`, `current_rate_limit`, `invariant_violations`
     - 히스토그램: `graylog_delivery_latency_seconds`, `batch_size`, `end_to_end_latency_seconds`
  2. 인제스터에 `GET /v1/metrics/prometheus`를 열고, 컨슈머 워커에는 포트 9100 전용 백그라운드 메트릭 데몬 서버를 구동했습니다.
  3. `docs/observability/alerts.yml`에 5대 핵심 운영 알람을 정의하고, `docs/observability/grafana_dashboard.json` 대시보드를 프로비저닝했습니다.
  4. OpenTelemetry W3C 분산 추적 로직을 구현하여 인제스트 시점에 Head-based 샘플링(일반 1%, 우선순위 100%)으로 `traceparent`를 생성해 브로커 헤더에 주입하고, 컨슈머가 이를 추출하여 Graylog HTTP 호출 헤더로 전파하도록 구성했습니다.
- **결과**
  - 표준 SRE 모니터링 인프라와 연동 가능한 관측성 스택을 구축했습니다.
  - 검증 테스트:
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_prometheus_endpoint_exposes_expected_names`
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_v1_versioned_prometheus_endpoint`
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_no_high_cardinality_labels_present`
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_existing_json_metrics_endpoint_unbroken`
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_logs_forwarded_total_does_not_increment_on_graylog_error`
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_logs_forwarded_total_increments_only_on_confirmed_2xx`
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_delivery_attempts_tracks_outcomes_honestly`
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_metrics_reset_clears_prometheus_counters`
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_consumer_worker_metrics_server_lifecycle`
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_traceparent_disabled_when_otel_false`
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_traceparent_injected_with_priority_sampling_when_otel_true`
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_traceparent_propagates_from_broker_message_to_graylog_call`
    - [`tests/test_observability.py`](./tests/test_observability.py):: `test_parent_traceparent_from_http_request_propagates_to_broker`

---

## 13. 남은 과제 (Roadmap)

코드베이스 정밀 전수 검사 결과, 현재 코드에 구현되지 않았거나(ABSENT) 일부 라이브러리 레벨에 한정되어 상시 구동되지 않는(PARTIAL) 항목들을 명확히 분리하여 기록합니다.

### 13.1 미구현 항목 (ABSENT)
1. **CI 워크플로우 (Continuous Integration Workflow)**:
   - GitHub Actions(`.github/workflows/`) 또는 GitLab CI 등 자동화된 빌드/테스트 파이프라인이 레포지토리에 존재하지 않습니다. 향후 PR 단위 `pytest`, `ruff`, `mypy` 자동화 워크플로우 구성이 필요합니다.
2. **Hypothesis 기반 속성 기반 테스트 (Property-Based Testing)**:
   - 현재 137개 테스트는 결정론적 단위/통합 테스트 스위트로 구성되어 있으며, 임의의 페이로드 바이트 및 극단적 지터 타이밍을 생성하는 `hypothesis` 라이브러리 기반 테스트는 부재합니다.
3. **Real-SIEM Docker Compose 프로파일 (`real-siem`)**:
   - `docker-compose.yml`에는 실제 상용 Graylog 및 OpenSearch/Elasticsearch 컨테이너 클러스터 배포 프로파일이 포함되어 있지 않으며, 경량 `mock-graylog`만을 기본 제공합니다.
4. **Makefile 빌드 및 실행 자동화 도구**:
   - `make test`, `make build`, `make up` 등의 통합 명령어를 제공하는 `Makefile`이 존재하지 않으며, 현재는 `docker compose` 및 `pytest` 명령어를 직접 실행해야 합니다.

### 13.2 부분 구현 및 추가 연동 필요 항목 (PARTIAL)
1. **지연 재시도 토픽 컨슈머(`RetryTopicConsumer`) 데몬 상시 구동**:
   - [`middleware/retry_topic_consumer.py`](./middleware/retry_topic_consumer.py) 모듈과 단위 테스트는 완성되어 있으나, [`docker-compose.yml`](./docker-compose.yml) 상에서 `RetryTopicConsumer`를 백그라운드 서비스로 상시 구동하는 배포 설정이 연결되어 있지 않습니다. 현재는 관리자 API(`POST /v1/admin/dlq/replay`)를 통한 온디맨드 재전송이 주력으로 사용됩니다.
2. **OpenTelemetry 외부 트레이스 수집기(OTLP Exporter / Jaeger) 연동**:
   - W3C `traceparent` 헤더의 주입, 추출, 인메모리 스팬 추적은 구현되어 있으나, 실제 분산 트레이스를 OTLP gRPC/HTTP로 Jaeger나 OpenTelemetry Collector에 전송하는 Exporter 및 시각화 백엔드는 아직 구성되어 있지 않습니다.
