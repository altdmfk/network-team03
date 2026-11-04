# 시나리오2 연동 — 킬체인 상관분석에 Brute Force 단계 포함

> 번호 변경 안내: 이 문서의 "킬체인"은 번호 재조정으로 시나리오4 → **시나리오3**이 됨. 문서 안의 다른 번호(시나리오2=미들웨어, 시나리오3=API 키 유출)는 그쪽 팀 폴더가 아직 리네임 전이라 옛 번호 그대로 남아있음 — 헷갈리지 않게 "킬체인"이라고 풀어 쓴 부분은 전부 이 시나리오(새 번호 3) 얘기임.

킬체인(이 시나리오)의 Graylog 킬체인 상관분석 규칙(`Killchain CRITICAL`)에 시나리오2(SOAR 미들웨어)의 실제 공격 이벤트를 포함시켰다. 기존에는 `recon_scan` / `api_key_compromised`(시나리오3=API 키 유출) / `device_control`(킬체인) 3종만 합성 테스트(`test_killchain.py`)로 발생시켜 검증했는데, 이제 시나리오2의 `PORT_SCAN` / `BRUTE_FORCE` 실제 이벤트도 같은 규칙에 매칭된다.

## 왜 연동이 가능했나

`scenario2-middleware/simulators/spike_test_demo.py`의 `inject_kill_chain_sequence()`가 이미 `PORT_SCAN → BRUTE_FORCE → IOT_CONTROL` 순서로 로그를 보내는데, 이때 쓰는 필드명이 킬체인 쪽과 동일한 `client_ip`다. 필드명이 같아서 Graylog Event Definition의 `Group by Field(s): client_ip` 그룹핑에 그대로 걸린다.

## 변경 내용

Graylog Event Definition **"Killchain CRITICAL"** (`http://localhost:9000/alerts/definitions/6ae008a0ee6dd635315af865/edit`)의 Search Query를 아래처럼 확장했다.

변경 전:
```text
event_type:(recon_scan OR api_key_compromised OR device_control)
```

변경 후:
```text
event_type:(recon_scan OR PORT_SCAN OR api_key_compromised OR BRUTE_FORCE OR device_control)
```

나머지 설정(`Group by Field(s): client_ip`, `card(event_type) >= 3`, 10분 윈도우, 1분 주기)은 그대로 유지했다 — 서로 다른 event_type이 3종 이상 같은 IP로 모이면 발동하는 구조라 타입을 늘려도 조건식은 안 건드려도 된다.

## 재현 방법

시나리오2 쪽 환경 구축과 로그 발생 방법은 [`scenario2-middleware/SCENARIO2_SETUP_GUIDE.md`](../../scenario2-middleware/SCENARIO2_SETUP_GUIDE.md) 참고. 핵심은:

1. `scenario2-middleware`의 미들웨어 + Graylog 연동을 가이드대로 기동
2. `python simulators/spike_test_demo.py --spike-count 20000` 실행 시 내부적으로 `inject_kill_chain_sequence()`가 공격자 IP(`KILL_CHAIN_IP`, 코드 기준 `10.0.0.99`)로 `PORT_SCAN → BRUTE_FORCE → IOT_CONTROL`을 순차 전송
3. 같은 IP로 시나리오3(API 키 유출)의 `api_key_compromised` 이벤트까지 10분 내 들어오면 — 또는 `device_control`(킬체인)까지 포함되면 — `event_type` 종류가 3개 이상 모여 `Killchain CRITICAL` 알림 발동
4. 알림 → n8n 웹훅(`/webhook/killchain-alert`) → 티켓 생성 → 공용 대시보드(`:5001/dashboard`)에 인시던트 기록까지는 기존 킬체인 플로우와 동일

## 참고

- 실제 시나리오2 공격(`PORT_SCAN`/`BRUTE_FORCE`)만으로는 `event_type` 종류가 2개뿐이라 단독으로는 CRITICAL이 안 뜬다. 시나리오3(API 키 유출) 또는 킬체인 단계 중 최소 1개가 같은 IP·같은 10분 윈도우 안에 추가로 발생해야 3종 조건을 채운다.
- 이 문서는 2026-11-02 기준 설정 변경 내역이며, Graylog UI에서 직접 Search Query를 수정해 반영했다(워크플로우 파일이나 Event Definition export는 별도로 보관하지 않음 — 변경 필요 시 위 쿼리 문자열을 그대로 다시 입력하면 됨).
