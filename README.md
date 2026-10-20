# 네트워크 팀 프로젝트 3조 (Network Team 03)

본 저장소는 네트워크 팀 프로젝트 3조의 협업 및 통합 코드베이스입니다.

---

## 프로젝트 모듈 구성 (Modules)

| 모듈 경로 | 담당 기능 및 시나리오 | 상세 문서 |
| :--- | :--- | :--- |
| [`middleware/`](./middleware/) | **시나리오 2: SOAR 경량 로그 버퍼링 및 트래픽 제어 미들웨어**<br/>• 대규모 보안 이벤트 스파이크(5,000 EPS) 완충 및 평탄화<br/>• `Total Sent == Total Stored` (0.00% 무손실) 보장<br/>• 공격자 IP 기반 Kill-Chain 순서 보존 및 70:30 우선순위 레인<br/>• SQLite WAL 기반 자체 경량 파티셔닝 브로커 (`broker_wal.db`) | [`middleware/README.md`](./middleware/README.md) |
| *(추가 예정)* | 팀원별 기능 및 추가 시나리오 모듈 | - |

---

## 빠른 시작 (Quick Start)

### 1. 시나리오 2 로그 버퍼링 미들웨어 테스트 실행
```bash
# 전체 단위 / 통합 / 장애 주입 테스트 137개 실행
pytest -v
```

### 2. 미들웨어 서비스 실행 (Docker Compose)
```bash
cd middleware
docker compose up -d --build
```
자세한 실행 가이드 및 아키텍처 명세는 [`middleware/README.md`](./middleware/README.md)를 참고하십시오.
