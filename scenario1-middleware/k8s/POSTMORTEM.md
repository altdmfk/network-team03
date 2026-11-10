# 장애 실험 기록

`kind` 클러스터에 배포한 SOAR 로그 버퍼링 미들웨어를 대상으로 장애 실험 3건을 진행했다. 각 실험 결과를 증상, 원인, 조치, 결과 검증, 향후 과제로 나누어 정리했다.

---

## 장애 실험 1: 수집기(`ingestor`) 파드 삭제 후 PVC 디스크 영속성 확인

1. **증상**: 보안 로그 20건을 보내 처리가 끝난 상태(`total_received: 20`, `total_forwarded_to_graylog: 20`, `current_queue_lag: 0`)에서 `kubectl delete pod -n soar -l app=ingestor`로 수집기 파드를 삭제했다.
2. **원인**: 수집기 파드가 다시 뜰 때 기존에 기록된 브로커 오프셋(`broker_wal.db`)과 통계(`metrics.db`)가 초기화되는지 확인하기 위해 파드를 지웠다. 트래픽을 계속 쏘면서 무중단 여부를 본 것이 아니라 디스크 영속성을 확인한 실험이다.
3. **조치**: Deployment의 ReplicaSet 컨트롤러가 새 파드를 만들고(`Recreate` 전략) `/app/state` 경로에 기존 `soar-state-pvc`를 다시 마운트해 Ready 상태가 될 때까지 기다렸다.
4. **결과 검증**: 새로 뜬 파드의 `/v1/metrics`를 조회해 `total_received: 20`, `total_forwarded_to_graylog: 20`, `broker_high_watermark_total: 20`, `consumer_committed_offset_total: 20` 값이 그대로 남아 있는 것을 확인했다.
5. **향후 과제**: PVC를 써서 디스크 데이터는 남지만 `replicas: 1`과 `Recreate` 전략 때문에 파드가 다시 뜨는 수 초 동안은 수집이 멈춘다. 앞으로 상위 전송 클라이언트에 지수 백오프 재시도를 넣거나 다중 레플리카 운영이 가능한 외부 브로커로 바꿀 예정이다.

---

## 장애 실험 2: 하위 서버(`mock-graylog`) 중단(`replicas=0`) 및 복구

1. **증상**: `kubectl scale deployment/mock-graylog -n soar --replicas=0`으로 하위 서버를 내린 뒤 보안 로그 30건을 보냈다. `total_forwarded_to_graylog`는 늘지 않고 `current_queue_lag: 30`으로 큐 적체가 생겼다.
2. **원인**: 하위 로그 서버(`mock-graylog`) 파드가 모두 내려가서 `consumer-worker`의 GELF HTTP 전송이 실패했다.
3. **조치**: 수집기는 하위 서버 장애와 상관없이 `202 Accepted`를 반환하며 30건을 SQLite WAL에 쌓았다(`dropped_logs: 0`). 이후 `kubectl scale deployment/mock-graylog -n soar --replicas=1`로 하위 서버를 다시 살렸다.
4. **결과 검증**: 하위 서버가 살아난 뒤 `consumer-worker`가 밀려 있던 30건을 모두 재전송했다. `current_queue_lag: 0`, `total_forwarded_to_graylog: 31`(기존 1건 포함), `dropped_logs: 0`을 확인했다.
5. **향후 과제**: 하위 서버 장애가 길어지면 PVC 용량(`1Gi`)이 다 찰 수 있다. 앞으로 Alertmanager와 `PrometheusRule`을 켜서 `current_queue_lag` 임계치 알림과 볼륨 사용량 모니터링을 붙일 예정이다.

---

## 장애 실험 3: 잘못된 이미지 태그 배포(`ImagePullBackOff`) 및 `helm rollback` 복구

1. **증상**: `helm upgrade soar-middleware k8s/helm/soar-middleware -n soar --set image.tag=9.9.9-nonexistent` 명령을 실행하자 새 파드들이 `ErrImagePull`과 `ImagePullBackOff` 상태에 빠졌다.
2. **원인**: 없는 이미지 태그(`9.9.9-nonexistent`)를 배포했다. 이때 `Recreate` 전략을 쓰는 `ingestor`와 `consumer-worker`는 기존 파드가 먼저 내려간 뒤 새 이미지를 받지 못해 실행 중인 파드가 0개(서비스 중단)가 됐다. 반면 기본 `RollingUpdate` 전략을 쓰는 `mock-graylog`는 새 파드가 `ErrImagePull`에 걸린 동안에도 기존 파드가 내려가지 않고 `1/1 Running`(무중단)을 유지했다.
3. **조치**: `kubectl describe pod`의 Events에서 이미지 풀 실패 원인을 확인하고 바로 `helm rollback soar-middleware 1 -n soar`를 실행했다.
4. **결과 검증**: Helm 리비전 3(`Rollback to 1`)이 적용되면서 멈췄던 `ingestor`와 `consumer-worker`가 다시 `soar-middleware:1.0.0` 이미지로 올라와 `1/1 Running`이 됐다.
5. **향후 과제**: `Recreate` 전략에서는 이미지 풀 실패가 바로 서비스 중단으로 이어진다. 앞으로 배포 명령에 `helm upgrade --atomic` 옵션을 쓰거나 배포 전에 이미지 태그가 있는지 먼저 확인하는 절차를 넣을 예정이다.
