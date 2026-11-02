# 시나리오 1 — 허니토큰 기만 탐지

정상 사용자는 쓰지 않는 미끼 계정을 EngineSquare 회원 목록에 섞어 두고, 그 계정으로 로그인하는 순간 1회 만에 침입으로 확정해 자동 차단합니다.

```
공격자가 5001 로그인에 미끼 계정 입력
  → 웹앱: 일반 로그인 실패와 같은 화면(200) + 미끼 사용 기록
  → GELF(rule=honeytoken) → Graylog 이벤트 "S1 Honeytoken used"
  → n8n Webhook(honeytoken)
  → 공용 API POST /automation/honeytoken-response
      → 인시던트 티켓(INC-HONEY-xxx) · 거부 이벤트 · 공용 IP 차단(blocked_ips)
  → 응답 changed=true 일 때만 디스코드 알림
```

차단 목록은 시나리오 3과 같은 `blocked_ips`를 씁니다. 차단된 IP는 5001 웹앱 전체에 403을 받습니다(관리자용 localhost는 예외).

## 코드 위치

시나리오 1 코드는 이 폴더가 아니라 공용 웹앱·API에 들어 있습니다.

| 위치 | 내용 |
|---|---|
| `web-app/app.py` 끝의 시나리오 1 블록 | 미끼 로그인 탐지·위장 응답, Graylog·Middleware 신고, 차단 IP 403, 미끼 세션 차단, 미끼 심기(`/admin/honeytoken`, `seed-honeytoken`) |
| `web-app/security_store.py` | `honeytokens` 표, 미끼 조회·사용 기록, 관리자 화면 현황 |
| `web-app/templates/admin.html` | 관리자 화면 '시나리오 관리' 박스(미끼 현황·미끼 심기) |
| `app.py`(공용 API) `/automation/honeytoken-response` | 티켓·이벤트·차단 처리, `changed` 반환 |

이 폴더에는 설정 파일만 있습니다.

| 파일 | 내용 |
|---|---|
| `graylog/scenario1_content_pack.json` | Graylog 알림·이벤트 정의 콘텐츠 팩 |
| `n8n/scenario1_honeytoken.json` | n8n 대응 워크플로우(디스코드 주소는 `YOUR_...`로 비워둠) |

## 설정 순서

### 1. 서버 실행
프로젝트 최상위 `README.md`의 안내대로 Docker(MySQL·Middleware·Graylog·n8n)를 켠 뒤, 최상위 폴더 PowerShell에서:
```powershell
.\start-enginesquare.ps1
```
웹앱이 처음 실행될 때 `honeytokens` 표가 자동으로 만들어집니다.

### 2. 미끼 계정 심기
관리자 로그인 → 관리자 → '시나리오 관리' 박스 → 미끼 번호 `HT-001`, 계정 이름 `backup_admin` → 미끼 심기.

또는 `web-app` 폴더에서:
```bash
python -m flask --app app seed-honeytoken HT-001 backup_admin
```
같은 이름의 계정이 이미 있으면 덮어쓰지 않고 안내만 합니다. 미끼 계정의 비밀번호는 아무도 모르는 랜덤 값이며, 로그인은 항상 일반 실패 화면으로 응답합니다.

### 3. Graylog
System → Content Packs → Upload → `graylog/scenario1_content_pack.json` → Install. 알림과 이벤트 정의가 한 번에 만들어집니다.
- **URL 허용 목록**(System → Configurations → URL Whitelist): `http://host.docker.internal:5678/webhook/honeytoken` (Exact match)
- **이벤트 정의** `S1 Honeytoken used`: Filter `rule:honeytoken`, 10초 범위 / 10초마다 실행, 필드 `src_ip`·`token_id`·`placement`·`username`
- **알림** `S1 n8n Webhook (honeytoken)`: POST, 위 URL, 본문:
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

### 4. n8n
1. Create Workflow → ⋯ → Import from File → `n8n/scenario1_honeytoken.json`
2. `디스코드` 노드 URL의 `YOUR_DISCORD_WEBHOOK_URL`을 실제 웹후크 주소로 바꾸기
3. Save → Publish

`IP 차단 (공용 API)` 노드는 `http://host.docker.internal:5000/automation/honeytoken-response`로 보냅니다. n8n과 API가 다른 PC에 있으면 `host.docker.internal`을 API 서버 PC의 IP로 바꿉니다. n8n은 노드에서 환경변수 읽기를 기본으로 막기 때문에 주소는 고정값으로 넣었습니다.

## 시험 방법

**n8n 이후 단계만 확인**(Graylog 없이, Git Bash):
```bash
curl -s -X POST http://localhost:5678/webhook/honeytoken -H "Content-Type: application/json" -d '{"src_ip":"10.10.10.10","token_id":"HT-001","username":"backup_admin","placement":"users_table","timestamp":"2026-11-02T02:30:00.000Z"}'
```
- 디스코드 알림 1회, 대시보드에 시나리오 1 티켓(`INC-HONEY-...`), 관리자 화면 차단 IP 목록에 `10.10.10.10`
- 같은 요청을 다시 보내면 알림 없이 티켓 횟수만 증가(`changed=false`)
- 확인 후 관리자 화면에서 차단 해제

**전체 흐름**(Kali → 5001):
```bash
curl -i -X POST "http://<Windows IP>:5001/login" -d "username=backup_admin&password=1234"
```
- 응답은 일반 로그인 실패와 같은 화면(200, "아이디 또는 비밀번호가 올바르지 않습니다.")
- 10초 안팎으로 디스코드 알림, 이후 같은 IP의 5001 접속은 403
- Kali에서 접속하려면 웹앱이 `0.0.0.0`으로 실행되어 있어야 합니다(`web-app` 폴더에서 `python -m flask --app app run --host 0.0.0.0 --port 5001`).

## 참고
- 로그 전송(Graylog·Middleware) 실패는 로그인 화면에 드러내지 않고 웹앱 서버 로그에 경고로 남깁니다(`.runtime-logs/web.err.log`).
- 탐지 건수는 티켓별 `occurrence_count` 합계입니다. Graylog가 10초 단위로 검사하므로 짧은 시간의 여러 시도는 한 번으로 묶일 수 있습니다.
- 시나리오 1과 3은 같은 차단 목록을 쓰므로, 시연 사이에는 관리자 화면에서 차단을 해제합니다.
