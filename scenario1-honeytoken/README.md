# 시나리오 1 — 허니토큰 기만 탐지

정상 사용자는 쓰지 않는 미끼 계정을 심어두고, 그 계정으로 로그인하는 순간 1회 만에 침입으로 확정해 자동 차단합니다.
> **폴더 구성**: `app/`은 메인 API 서버(Flask 게시판, `gamedh823-cmd/Aleph-Board-Team3` 기준)에서 시나리오 1을 위해 추가·수정한 파일입니다. 같은 경로에 덮어쓰거나 해당 부분을 옮겨 붙여 사용합니다. `wazuh/`, `n8n/`은 아래 설정 순서에서 그대로 사용합니다.

```
미끼 계정 로그인 → 메인 API 서버: 401 위장 응답 + 미끼 사용 기록
  ├─ logs/security.log → Wazuh 에이전트 → 룰 100500 (레벨 15)
  └─ GELF → Graylog 이벤트 → n8n → IP 차단 → 메신저 알림 · 인시던트 티켓
```

## 바뀐 파일

| 파일 | 내용 |
|---|---|
| `models/honeytoken.py`, `models/__init__.py` | 미끼 목록 표(`honeytokens`) |
| `app.py` | 미끼 심기 명령 `seed-honeytoken` |
| `controllers/auth_controller.py` | 로그인 시 미끼 탐지, 401 위장 응답, Graylog 전송 |
| `controllers/seclog.py` | security.log에 `honeytoken_used` 기록 |
| `wazuh/scenario1_decoder.xml`, `wazuh/scenario1_rules.xml` | Wazuh 디코더·룰(100500) |
| `n8n/scenario1_honeytoken.json` | n8n 대응 워크플로우 (토큰·키는 `YOUR_...`로 비워둠) |
| `controllers/admin_controller.py` | 허니토큰 현황·생성·회수 API, 가짜 관리자 키 탐지 |
| `controllers/page_controller.py` | 관리자 페이지에 가짜 관리자 키 심기 |
| `templates/admin.html` | 관리 콘솔 "허니토큰(미끼) 관리" 섹션 (10초 자동 갱신) |
| `graylog/scenario1_content_pack.json` | Graylog 알림·이벤트 정의 콘텐츠 팩 |

## 설정 순서

### 1. 미끼 계정 심기
서버를 한 번 실행해 표를 만든 뒤(`python app.py`), `team-board` 폴더에서:
```bash
python -m flask --app app.py seed-honeytoken HT-001 backup_admin
```

### 2. Wazuh
```bash
docker cp wazuh/scenario1_decoder.xml wazuh-manager:/var/ossec/etc/decoders/scenario1_decoder.xml
docker cp wazuh/scenario1_rules.xml wazuh-manager:/var/ossec/etc/rules/scenario1_rules.xml
docker exec wazuh-manager chown wazuh:wazuh /var/ossec/etc/decoders/scenario1_decoder.xml /var/ossec/etc/rules/scenario1_rules.xml
docker exec wazuh-manager /var/ossec/bin/wazuh-control restart
```
Windows 에이전트 설정(`C:\Program Files (x86)\ossec-agent\ossec.conf`, 관리자 권한)의 `</ossec_config>` 위에 추가 후 에이전트 재시작(`Restart-Service -Name wazuh`):
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>본인경로\team-board\logs\security.log</location>
</localfile>
```

### 3. Graylog
**빠른 설정:** System → Content Packs → Upload → `graylog/scenario1_content_pack.json` 업로드 → Install. 알림과 이벤트 정의가 한 번에 만들어집니다. URL 허용 목록은 아래처럼 따로 추가해야 합니다.
- **URL 허용 목록**(System → Configurations → URL Whitelist): `http://host.docker.internal:5678/webhook/honeytoken` (Exact match)
- **알림**(Alerts → Notifications): `S1 n8n Webhook (honeytoken)`, Custom HTTP Notification, POST, 위 URL, 본문:
  ```json
  {
    "event_type": "honeytoken_used",
    "src_ip": "${event.fields.src_ip}",
    "token_id": "${event.fields.token_id}",
    "placement": "${event.fields.placement}",
    "username": "${event.fields.username}",
    "timestamp": "${event.timestamp}",
    "title": "${event_definition_title}"
  }
  ```
- **이벤트 정의**(Alerts → Event Definitions): `S1 Honeytoken used`, Priority High
  - 조건: Filter, 검색어 `rule:honeytoken`, 10초 범위 / 10초마다 실행, 집계 없음
  - 필드: `src_ip`, `token_id`, `placement`, `username` (각각 Template `${source.필드명}`)
  - 알림: 위 알림 연결, Grace Period 0

### 4. n8n
1. 워크플로우 화면 → Import from File → `n8n/scenario1_honeytoken.json`
2. `YOUR_...` 자리에 값 넣기: 디스코드·슬랙 웹후크 주소, 텔레그램 봇 토큰·채팅방 번호, `IP 차단`·`인시던트 티켓` 노드의 `X-API-Key`(= `.env`의 `ADMIN_API_KEY`)
3. Publish

## 시험 방법

```powershell
# 1) 정상 로그인 → 알림 없어야 함
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/auth/login -ContentType 'application/json' -Body '{"username":"normal_user","password":"test1234"}'
# 2) 미끼 로그인 → 401 응답, 약 10초 뒤 메신저 알림
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/auth/login -ContentType 'application/json' -Body '{"username":"backup_admin","password":"1234"}'
# 3) 재접속 → 403 (차단된 IP)
```
차단 해제: `POST /api/admin/unblock` + 헤더 `X-API-Key`, 본문 `{"ip":"127.0.0.1"}`

### 관리 콘솔
관리자로 로그인 → `/admin` → "허니토큰(미끼) 관리"에서 미끼 계정·관리자 키를 심고 회수할 수 있습니다.
가짜 관리자 키는 관리자 페이지 소스 주석에 숨겨져 있으며, 이 키로 관리자 API를 호출하면 401 위장 응답과 함께 탐지·차단됩니다.

## 시험 결과 (2026-10-22)

| 확인 항목 | 결과 |
|---|---|
| 위장 응답 | 일반 로그인 실패와 같은 401 |
| 즉시 탐지 | 1회 사용으로 Wazuh 레벨 15, Graylog 이벤트 발생 |
| 대응 시간 | 공격부터 차단까지 약 10초 (목표 30초 이내) |
| 차단 | 공격 IP 재접속 시 403 |
| 오탐 | 정상 계정 로그인 시 탐지 0건 |

## 참고
- 공통 JSON 규격(`client_ip`, `event_type` 등)에 맞춘 필드명 변경은 규격 확정 후 반영 예정입니다.
- 차단은 현재 메인 API 서버의 차단 기능으로 동작하며, pfSense 연동은 팀 망 구성 후 확장합니다.
