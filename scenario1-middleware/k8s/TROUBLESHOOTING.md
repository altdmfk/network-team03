# 트러블슈팅 기록

SOAR 로그 버퍼링 미들웨어를 로컬 `kind` 클러스터에 배포하면서 겪은 문제와 해결 과정을 정리했다.

---

## 1. `kind create cluster` 실행 시 443 포트 충돌 (`exit status 125`)

- **날짜**: 2026-11-10
- **증상**:
  `extraPortMappings`(80, 443)를 설정한 `k8s/kind-config.yaml`로 클러스터를 만들 때 아래 에러가 나며 실패했다.
  ```text
  ERROR: failed to create cluster: ...
  docker: Error response from daemon: failed to set up container networking: driver failed programming external connectivity on endpoint soar-cluster-control-plane: Bind for 0.0.0.0:443 failed: port is already allocated
  ```
- **원인**:
  `kind-config.yaml`은 호스트의 80번과 443번 포트를 노드 컨테이너에 연결한다. `docker ps`로 확인해 보니 Docker Desktop을 켤 때 자동 실행된 `wazuh-dashboard` 컨테이너(`0.0.0.0:443->5601/tcp`)가 이미 443번 포트를 쓰고 있었다.
- **해결**:
  443번 포트를 잡고 있던 `wazuh-dashboard`를 중지했다. 로컬 메모리 여유를 확보하고 이후 포트포워딩 포트(8000, 9100, 12201) 충돌을 막기 위해 함께 실행 중이던 기존 컨테이너(`wazuh-indexer`, `wazuh-manager`, `soar-http-ingestor`, `soar-consumer-worker`, `gl-graylog`, `gl-opensearch`, `gl-mongo`)도 `docker stop`으로 함께 내렸다. 이후 클러스터를 다시 생성해 정상 기동을 확인했다.

---

## 2. 첫 배포 직후 전 컴포넌트 `CrashLoopBackOff` (`ValueError: invalid literal for int()`)

- **날짜**: 2026-11-10
- **증상**:
  Docker Compose에서 잘 돌던 `ingestor`, `consumer-worker`, `mock-graylog` 파드가 쿠버네티스에 배포하자마자 모두 `CrashLoopBackOff` 상태에 빠졌다.
- **원인**:
  `kubectl logs -n soar <deployment> --previous` 명령으로 직전 종료 로그를 확인했다. 파드별로 아래 에러가 찍혀 있었다.
  ```text
  # [mock-graylog 로그]
  File "/app/src/config.py", line 249, in load_settings
    ingestor_port = int(source.get("INGESTOR_PORT", "8000"))
  ValueError: invalid literal for int() with base 10: 'tcp://10.96.234.255:8000'

  # [ingestor 및 consumer-worker 로그]
  File "/app/src/config.py", line 254, in load_settings
    mock_graylog_port = int(source.get("MOCK_GRAYLOG_PORT", "12201"))
  ValueError: invalid literal for int() with base 10: 'tcp://10.96.116.146:12201'
  ```
  - 세 컴포넌트는 시작할 때 공통으로 `src/config.py`의 `load_settings()`를 호출한다. 이 함수는 `INGESTOR_PORT`(249행)와 `MOCK_GRAYLOG_PORT`(254행) 환경변수를 순서대로 읽어 정수로 변환한다.
  - 쿠버네티스는 같은 네임스페이스에 있는 Service 이름(`ingestor`, `mock-graylog`)을 따서 `<SERVICE_NAME>_PORT=tcp://<CLUSTER_IP>:<PORT>` 형태의 환경변수를 파드에 자동 주입한다(`enableServiceLinks: true` 기본값).
  - `mock-graylog` 파드는 `soar-config` ConfigMap을 쓰지 않고 자체 `env`에 `MOCK_GRAYLOG_PORT: "12201"`만 선언되어 있었다. 그 결과 쿠버네티스가 주입한 `INGESTOR_PORT=tcp://10.96.234.255:8000`이 그대로 들어와 249행에서 에러가 났다.
  - 반대로 `ingestor`와 `consumer-worker` 파드는 `soar-config` ConfigMap에 선언된 `INGESTOR_PORT: "8000"`이 자동 주입 변수를 덮어써 249행은 통과했다. 하지만 ConfigMap에 `MOCK_GRAYLOG_PORT`는 없었기 때문에 쿠버네티스가 주입한 `MOCK_GRAYLOG_PORT=tcp://10.96.116.146:12201`이 남아서 254행에서 에러가 났다.
- **해결**:
  3개 Deployment(`ingestor`, `consumer-worker`, `mock-graylog`)의 파드 스펙에 `enableServiceLinks: false`를 추가해 쿠버네티스가 `<SERVICE_NAME>_PORT=tcp://...` 환경변수를 주입하지 않도록 막았다. 재배포 후 세 파드 모두 `1/1 Running`으로 올라오는 것을 확인했다.

---

## 3. 배치 로그 전송(`/v1/ingest/batch`) 시 HTTP `422 Unprocessable Entity` 응답

- **날짜**: 2026-11-10
- **증상**:
  장애 실험 1을 준비하며 `/v1/ingest/batch`에 테스트 로그를 보냈더니 HTTP `422` 에러가 반환됐다.
  ```text
  {"status":422,"detail":"body -> BatchIngestRequest -> logs -> 0 -> target_resource: Field required; status_code: Field required; raw_payload: Field required; message: Extra inputs are not permitted"}
  ```
- **원인**:
  수집기의 `SecurityLogEvent` 모델은 기본 설정이 `STRICT_SCHEMA=true`(`extra="forbid"`)다. `client_ip`, `event_type`, `target_resource`, `status_code`, `severity`, `raw_payload` 필드를 모두 넣어야 하는데 정의되지 않은 `message` 필드를 넣어 요청했기 때문이다.
- **해결**:
  `src/ingestor.py`의 `SecurityLogEvent` 스키마에 맞춰 필수 필드(`target_resource`, `status_code`, `raw_payload`)를 모두 채워 다시 보냈다. HTTP `202 Accepted` 응답과 함께 SQLite WAL 파일에 로그가 정상 적재됐다.
