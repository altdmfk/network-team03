# 시나리오 1 - 허니토큰(미끼 계정) 탐지

EngineSquare 회원 목록에 정상 사용자는 쓰지 않는 **미끼 계정**을 섞어 둡니다.
누군가 그 계정으로 로그인하면 1회 만에 침입으로 확정해 출발지 IP를 자동 차단합니다.

```text
Kali → 5001 로그인에 미끼 계정 입력
  -> 웹앱: 일반 로그인 실패와 같은 화면(200) + Middleware /ingest로 HONEYTOKEN_ACCESS 전송
  -> Middleware: 허니토큰 우선 차선(security-logs.priority) -> Graylog GELF HTTP(TCP 12201)
  -> Graylog 이벤트 "S1 Honeytoken used" -> n8n /webhook/honeytoken
  -> 공용 API /automation/honeytoken-response: 티켓(INC-HONEY-...)·이벤트·IP 차단
  -> changed=true일 때만 Discord 알림
```

## 내 PC에 시나리오 1 적용하기

### 무엇이 자동이고 무엇을 직접 해야 하나

| 구분 | 항목 | 할 일 |
|---|---|---|
| `git pull`로 자동 | 웹앱·API 코드, `honeytokens` 표(웹앱 첫 실행 시 생성), 관리자 '시나리오 관리' 박스 | 없음 |
| **직접 설정 (PC마다 1회)** | ① Middleware 실행 + Graylog GELF **HTTP** 입력 | 아래 1단계 |
| | ② Graylog 콘텐츠 팩 + URL 허용 목록 | 아래 2단계 |
| | ③ n8n 워크플로 가져오기 + Discord 주소 | 아래 3단계 |
| | ④ 미끼 계정 심기 | 아래 4단계 |

**전제**: 팀 공통 환경이 이미 동작하는 PC입니다. Docker의 MySQL·Middleware·Graylog·n8n, 루트 `.env`,
`start-enginesquare.ps1` 실행은 [루트 README](../README.md)와 [시나리오 3 README](../scenario3-api-key-compromised/README.md)를 따릅니다.
시작 전에 `git pull`로 최신 main을 받습니다.

### 1단계. Middleware와 Graylog GELF HTTP 입력 확인

시나리오 1 탐지 기록은 **Middleware를 거쳐** Graylog로 들어갑니다. 시나리오 2와 같은 경로라서, [시나리오 2 가이드](../scenario2-middleware/SCENARIO2_SETUP_GUIDE.md)대로 이미 설정한 PC라면 추가 작업이 없습니다.

1. Middleware 컨테이너가 실행 중인지 확인합니다(`scenario2-middleware` 폴더에서 `docker compose ps`).
2. Graylog → System → Inputs에 **GELF HTTP**(TCP 12201) 입력이 RUNNING인지 확인합니다. 없으면 [시나리오 2 가이드 2-1](../scenario2-middleware/SCENARIO2_SETUP_GUIDE.md#2-1-gelf-http-인풋-생성)대로 만듭니다.
3. 루트 `.env`의 `MIDDLEWARE_INGEST_URL`·`MIDDLEWARE_API_KEY`가 Middleware 설정과 같은지 확인합니다.

✅ **확인**: 미끼 로그인 후 Graylog에서 `event_type:HONEYTOKEN_ACCESS AND source:security-middleware` 검색 시 기록이 보이고, `broker_topic`이 `security-logs.priority`(허니토큰 우선 차선)

> GELF HTTP 입력이 없으면 Middleware 로그에 `Graylog delivery failed ... Server disconnected without sending a response`가 30초마다 반복됩니다. 입력을 만들면 Middleware가 붙잡아 둔 기록을 자동으로 다시 보냅니다.
>
> 웹앱은 예전 방식대로 GELF UDP 12201로도 같은 기록을 보내지만, 탐지 규칙은 Middleware 기록만 보므로 **UDP 입력은 필요 없습니다.** Graylog가 다른 PC라면 Middleware의 `GRAYLOG_GELF_URL`(시나리오 2 `.env`)만 맞추면 됩니다.

### 2단계. Graylog 이벤트·알림 가져오기

1. System → Content Packs → **Upload** → `graylog/scenario1_content_pack.json` → 목록에서 Install
2. System → Configurations → **URL Whitelist** → `http://host.docker.internal:5678/webhook/honeytoken` 추가(Exact match)

콘텐츠 팩이 만드는 것:
- 이벤트 정의 `S1 Honeytoken used`: Filter `event_type:HONEYTOKEN_ACCESS AND source:security-middleware`, 10초 범위 / 10초마다, 필드 `src_ip`(=`${source.client_ip}`)·`raw_payload`(=`${source.raw_payload}`)
- n8n이 `raw_payload`(JSON 글자)를 풀어 미끼 번호(`decoy_id`)를 꺼냅니다

> 예전 콘텐츠 팩(rev 1, `rule:honeytoken`)을 설치했던 PC는 Alerts → Event Definitions에서 `S1 Honeytoken used`의 검색어와 필드를 위처럼 바꾸고, Notifications의 본문을 콘텐츠 팩과 같게 바꿉니다.
- 알림 `S1 n8n Webhook (honeytoken)`: POST `http://host.docker.internal:5678/webhook/honeytoken`

✅ **확인**: Alerts → Event Definitions에 `S1 Honeytoken used`, Notifications에 `S1 n8n Webhook (honeytoken)`

### 3단계. n8n 워크플로 가져오기

1. n8n → Create Workflow → 오른쪽 위 ⋯ → **Import from File** → `n8n/scenario1_honeytoken.json`
2. `디스코드` 노드를 열어 URL의 `YOUR_DISCORD_WEBHOOK_URL`을 **본인 Discord 웹후크 주소**로 바꿉니다.
3. Save → **Publish**

- 다른 노드는 수정하지 않습니다. `IP 차단 (공용 API)` 노드는 `http://host.docker.internal:5000/automation/honeytoken-response`로 보냅니다.
  n8n과 API 서버가 다른 PC라면 `host.docker.internal`만 API 서버 PC의 IP로 바꿉니다.
- 같은 경로(`honeytoken`)를 쓰는 예전 시나리오 1 워크플로가 있다면 끄거나 지웁니다. 둘 다 켜지면 충돌합니다.

✅ **확인**: API(5000)를 켠 상태에서 Git Bash로 아래를 보냅니다.
```bash
curl -s -X POST http://localhost:5678/webhook/honeytoken -H "Content-Type: application/json" -d '{"src_ip":"10.10.10.10","token_id":"HT-001","username":"backup_admin","placement":"users_table","timestamp":"2026-11-02T02:30:00.000Z"}'
```
`{"message":"Workflow was started"}` → Discord 알림 1회, 대시보드에 `INC-HONEY-...` 티켓, 관리자 차단 IP 목록에 `10.10.10.10`.
같은 명령을 한 번 더 보내면 알림 없이 티켓 횟수만 늘어야 합니다. 확인 후 관리자에서 `10.10.10.10` **차단 해제**.

### 4단계. 미끼 계정 심기

`admin`으로 `http://127.0.0.1:5001/admin` → **시나리오 관리** 박스 → 미끼 번호 `HT-001`, 계정 이름 `backup_admin` → **미끼 심기**

또는 `web-app` 폴더에서 `python -m flask --app app seed-honeytoken HT-001 backup_admin`

- 같은 이름의 계정이 이미 있으면 덮어쓰지 않고 안내만 합니다.
- 미끼 계정 비밀번호는 아무도 모르는 32자리 랜덤 값입니다.
- 미끼 계정은 회원 관리 목록에서 일반 회원과 구분되지 않습니다(의도된 동작).

**미끼가 만들어지는 위치** (MySQL `enginesquare` DB, 미끼 하나에 두 줄)

회원 목록과 미끼 표시가 저장된 절대 위치는 **`mysql-server` 컨테이너 → `enginesquare` DB → `users`·`honeytokens` 표**입니다(`enginesquare.users`, `enginesquare.honeytokens`).
디스크 파일로는 컨테이너 안 `/var/lib/mysql/enginesquare/users.ibd`이지만, 직접 열어 보는 형식이 아니므로 아래 DB 명령으로 확인합니다.

| 표 | 들어가는 값 | 역할 |
|---|---|---|
| `users` | `username`=`backup_admin`, `password_hash`=랜덤 값의 해시, `role`=`member` | 공격자에게 보이는 "진짜 같은" 회원 |
| `honeytokens` | `token_id`=`HT-001`, `token_type`=`account`, `token_value`=`backup_admin`, `placement`=`users_table`, `status`=`active` | 이 회원이 미끼라는 표시. 웹앱은 로그인 때 이 표를 보고 미끼를 알아봅니다 |

미끼가 처음 쓰이면 `honeytokens`의 `status`가 `used`로 바뀌고 `used_at`·`used_by_ip`가 채워집니다. `used`여도 탐지는 계속 동작합니다.

✅ **확인 1 (화면) — 미끼가 심긴 위치 직접 보기**

> **회원 목록 위치**: `admin`으로 로그인 → 위쪽 메뉴 **관리자** → "보안 관리" 화면에서 위쪽 오른편이 **시나리오 관리** 박스, 그 바로 아래가 **회원 관리** 목록입니다.
> 주소로는 `http://127.0.0.1:5001/admin#members`입니다. 회원이 많으면 목록 오른쪽 위의 **이전/다음**으로 페이지를 넘겨 찾습니다.
> 미끼 줄로 바로 가는 주소는 일부러 두지 않았습니다. 미끼는 일반 회원과 구분되지 않아야 하기 때문입니다.

1. `admin`으로 로그인한 뒤 `http://127.0.0.1:5001/admin#scenario-management` → 시나리오 관리 박스에서 미끼 계정 이름을 확인합니다(`HT-001 / backup_admin / 대기`).
2. 같은 화면 아래 `http://127.0.0.1:5001/admin#members`(회원 관리)에서 **같은 이름을 찾습니다.** 그 줄이 미끼가 실제로 심긴 자리입니다.
3. 그 줄이 `일반 회원`으로 보이면 정상입니다. 공격자가 회원 목록을 빼냈을 때 보게 되는 모습과 같습니다.

`placement`(심은 위치) 값과 화면 위치는 이렇게 대응합니다.

| `placement` 값 | 심긴 곳 | 화면에서 보는 곳 |
|---|---|---|
| `users_table` | `users` 표(회원 목록)의 한 줄 | 관리자 → 회원 관리(`/admin#members`) |

디스코드 알림의 "심은 위치: users_table"도 같은 뜻입니다.

✅ **확인 2 (DB)** — Git Bash 또는 PowerShell:
```bash
docker exec mysql-server mysql -uroot -p123456 enginesquare -e "SELECT token_id, token_value, placement, status, used_at, used_by_ip FROM honeytokens; SELECT username, role FROM users WHERE username='backup_admin';"
```
`honeytokens`에 `HT-001 | backup_admin | users_table | active`, `users`에 `backup_admin | member`가 나오면 정상입니다.
(DB 비밀번호가 다르면 `-p` 뒤를 본인 값으로 바꿉니다. 비밀번호 경고 한 줄은 정상입니다.)

> 심긴 것을 확인하려고 미끼로 직접 로그인해 보지는 않습니다. 탐지→차단→알림이 실제로 실행됩니다. 로그인 시험은 아래 "시연하기"에서 합니다.

여기까지 하면 적용 완료입니다.

## 시연하기 (Kali → 5001)

### 1. 서버 실행

프로젝트 루트 PowerShell에서 공용 실행 파일로 API(5000)와 웹앱(5001)을 함께 켭니다.

```powershell
.\start-enginesquare.ps1
```

웹앱은 `0.0.0.0`으로 실행되므로 같은 PC의 WSL Kali에서도 5001에 접속할 수 있습니다. 실행 창은 켜 두고, Enter를 누르면 두 서버가 함께 종료됩니다. 서버 로그는 `.runtime-logs/`에 남습니다.

### 2. Kali에서 공격

```powershell
wsl -d kali-linux -u root
```

```bash
GW=$(ip route show default | awk '{print $3; exit}')
ip route get "$GW"
curl -i -X POST "http://$GW:5001/login" -d "username=backup_admin&password=1234"
```

- `src` 뒤가 Kali 출발지 IP입니다. 이미 차단된 IP라면 관리자에서 먼저 해제합니다.
- 응답은 **HTTP 200**과 `아이디 또는 비밀번호가 올바르지 않습니다.` 일반 로그인 실패와 똑같아서 공격자는 함정을 알 수 없습니다.

### 3. 결과 확인 (10~20초 후)

1. **Discord**: `🍯 [허니토큰 탐지] INC-HONEY-... / 미끼 HT-001(backup_admin) 사용 → 공격 IP ... 즉시 차단`
2. **대시보드**: 시나리오 1 티켓(`허니토큰 미끼 계정 사용 (HT-001)`, 조치 `IP 차단`), 최근 이벤트 `시나리오 1 · 허니토큰 사용 탐지 / 거부`
3. **관리자**: 차단 IP 목록에 Kali IP, 시나리오 관리 박스의 미끼 `사용됨`·탐지·차단 건수
4. **Kali 재접속**: `curl -i "http://$GW:5001/login"` → **403** `차단된 IP입니다(관리자에게 문의).`

### 4. 시연 후 정리

- 관리자에서 Kali IP **차단 해제**(시나리오 3과 같은 차단 목록).
- 열린 티켓은 검토 후 종료. 미끼는 그대로 두어도 됩니다(`사용됨` 상태에서도 탐지는 계속 동작).

## 문제 해결

| 증상 | 원인·조치 |
|---|---|
| Kali에서 5001 접속 안 됨 | 최신 main을 받았는지 확인(웹앱이 `0.0.0.0`으로 실행되는 버전). Windows 방화벽이 5001을 막는지 확인 |
| 미끼 로그인 후 아무 반응 없음 | Graylog에서 `event_type:HONEYTOKEN_ACCESS AND source:security-middleware` 검색. 없으면 Middleware 로그(`docker compose logs --tail 40`)와 1단계(GELF HTTP 입력) 확인 |
| Discord에 `미끼 미상` | 이벤트 정의 Fields에 `raw_payload`(`${source.raw_payload}`)가 빠짐 |
| n8n을 고쳤는데 예전대로 동작 | Publish된 워크플로는 수정 후 **다시 Publish**해야 반영됨 |
| Graylog에 로그는 있는데 n8n 미실행 | 2단계 URL 허용 목록, 이벤트 정의의 알림 연결 확인 |
| `webhook "POST honeytoken" is not registered` | n8n 워크플로가 Publish되지 않음 |
| n8n에서 `access to env vars denied` | IP 차단 노드 URL에 `$env`가 남음 → 파일을 다시 가져오거나 고정 주소로 교체 |
| Discord 알림만 안 옴 | 이미 차단된 IP(`changed=false`) → 차단 해제 후 재시도. 또는 Discord 주소 확인 |
| 내 PC 브라우저로 미끼 로그인했는데 접속이 막히지 않음 | 정상입니다. 관리자용 `127.0.0.1`은 차단 대상에서 제외됩니다. 탐지·티켓·알림은 동작하며, 차단 확인은 Kali처럼 다른 IP에서 합니다 |
| 로그 전송 실패 여부 | 화면에는 표시하지 않고 웹앱 서버 로그에 `Scenario 1 ... failed` 경고로 남음 |

## 자주 묻는 질문

- **공격자가 미끼의 랜덤 비밀번호를 맞히면?** 로그인되지 않습니다. 미끼 계정은 비밀번호 확인 전에 걸러서 항상 실패 화면을 보내고 탐지합니다. 억지로 세션을 만들어도 다음 요청에서 로그아웃되고, 첫 시도에 차단되므로 대입 공격도 이어갈 수 없습니다.
- **정상 사용자가 실수로 미끼를 쓰면?** 미끼 이름은 실제 사용자와 겹치지 않게 정하고 공개하지 않습니다. 오탐이 사실상 없다는 것이 허니토큰의 장점입니다.
- **왜 Wazuh는 쓰지 않나요?** 미끼는 한 번 사용만으로 공격이 확정되어 상관 분석이 필요 없습니다. Graylog → n8n 한 경로로 대응하며, Wazuh 이중화는 확장 과제입니다.
- **왜 Middleware를 거치나요?** 팀 구조(서비스 → Middleware → Graylog)에 맞추고, Middleware의 장점을 시나리오 1도 쓰기 위해서입니다. Graylog가 잠시 꺼져 있어도 Middleware가 기록을 디스크에 쥐고 있다가 다시 보내 유실이 없고, 허니토큰은 우선 차선으로 처리돼 로그가 몰려도 탐지가 밀리지 않습니다. 대신 **Middleware가 꺼져 있으면 시나리오 1 탐지도 멈춥니다.** 처음에는 Middleware 연동 전에 만들어 Graylog로 직접(UDP) 보냈고, 지금은 Middleware 경로로 바꿨습니다.
- **`changed`는 무엇인가요?** 공용 API가 "이번에 이 IP를 **새로** 차단했는지"를 알려 주는 값입니다. 처음 차단하면 `true`, 이미 차단돼 있던 IP면 `false`입니다. n8n은 `true`일 때만 Discord로 알려서, 공격자가 여러 번 시도해도 알림은 한 번만 갑니다. 관리자가 차단을 해제한 뒤 다시 걸리면 다시 `true`가 됩니다.
- **탐지 건수가 시도 횟수와 다르면?** 탐지 건수는 티켓별 `occurrence_count` 합계입니다. Graylog가 10초 단위로 검사하므로 짧은 시간의 여러 시도는 한 번으로 묶일 수 있습니다.

## 코드 위치 (참고)

| 위치 | 내용 |
|---|---|
| `web-app/app.py` 끝의 시나리오 1 블록 | 미끼 로그인 탐지·위장 응답, Graylog·Middleware 전송, 차단 IP 403, 미끼 세션 차단, 미끼 심기 |
| `web-app/security_store.py` | `honeytokens` 표, 미끼 조회·사용 기록, 관리자 박스 현황 |
| `web-app/templates/admin.html` | 관리자 '시나리오 관리' 박스 |
| `app.py` `/automation/honeytoken-response` | 티켓·이벤트·차단 처리, `changed` 반환 |
