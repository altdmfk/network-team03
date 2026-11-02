# 시나리오 1 - 허니토큰(미끼 계정) 탐지

EngineSquare 회원 목록에 정상 사용자는 쓰지 않는 **미끼 계정**을 섞어 둡니다.
누군가 그 계정으로 로그인하면 1회 만에 침입으로 확정해 출발지 IP를 자동 차단합니다.

```text
Kali → 5001 로그인에 미끼 계정 입력
  -> 웹앱: 일반 로그인 실패와 같은 화면(200) + GELF UDP(rule=honeytoken) 전송
  -> Graylog 이벤트 "S1 Honeytoken used" -> n8n /webhook/honeytoken
  -> 공용 API /automation/honeytoken-response: 티켓(INC-HONEY-...)·이벤트·IP 차단
  -> changed=true일 때만 Discord 알림
```

## 내 PC에 시나리오 1 적용하기

### 무엇이 자동이고 무엇을 직접 해야 하나

| 구분 | 항목 | 할 일 |
|---|---|---|
| `git pull`로 자동 | 웹앱·API 코드, `honeytokens` 표(웹앱 첫 실행 시 생성), 관리자 '시나리오 관리' 박스 | 없음 |
| **직접 설정 (PC마다 1회)** | ① Graylog GELF **UDP** 입력 | 아래 1단계 |
| | ② Graylog 콘텐츠 팩 + URL 허용 목록 | 아래 2단계 |
| | ③ n8n 워크플로 가져오기 + Discord 주소 | 아래 3단계 |
| | ④ 미끼 계정 심기 | 아래 4단계 |

**전제**: 팀 공통 환경이 이미 동작하는 PC입니다. Docker의 MySQL·Middleware·Graylog·n8n, 루트 `.env`,
`start-enginesquare.ps1` 실행은 [루트 README](../README.md)와 [시나리오 3 README](../scenario3-api-key-compromised/README.md)를 따릅니다.
시작 전에 `git pull`로 최신 main을 받습니다.

### 1단계. Graylog GELF UDP 입력 만들기

시나리오 1 웹앱은 Graylog로 **GELF UDP 12201**을 직접 보냅니다.
팀 Middleware가 쓰는 **GELF HTTP** 입력과는 별개라서 따로 만들어야 합니다.

1. Graylog → System → Inputs → 드롭다운에서 **GELF UDP** → Launch new input
2. Title `S1 GELF UDP`, Port `12201`, Global 체크 → Save
3. Graylog 컨테이너가 UDP 포트를 열어 두었는지 확인합니다.
   docker 설정의 포트에 `12201:12201/udp`가 있어야 합니다. 없으면 추가 후 컨테이너를 다시 만듭니다.

✅ **확인**: Inputs 목록에서 `S1 GELF UDP`가 RUNNING

### 2단계. Graylog 이벤트·알림 가져오기

1. System → Content Packs → **Upload** → `graylog/scenario1_content_pack.json` → 목록에서 Install
2. System → Configurations → **URL Whitelist** → `http://host.docker.internal:5678/webhook/honeytoken` 추가(Exact match)

콘텐츠 팩이 만드는 것:
- 이벤트 정의 `S1 Honeytoken used`: Filter `rule:honeytoken`, 10초 범위 / 10초마다, 필드 `src_ip`·`token_id`·`placement`·`username`
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

✅ **확인**: 시나리오 관리 박스에 `HT-001 / backup_admin / 대기`

여기까지 하면 적용 완료입니다.

## 시연하기 (Kali → 5001)

### 1. 웹앱을 0.0.0.0으로 실행

Kali에서 5001에 접속해야 합니다. 현재 `start-enginesquare.ps1`은 웹앱을 127.0.0.1로만 실행하므로 시나리오 1 시연 때는 두 창으로 실행합니다.

PowerShell 창 1 (프로젝트 루트, 공용 API):
```powershell
python app.py
```

PowerShell 창 2 (`web-app` 폴더, 웹앱):
```powershell
$env:MIDDLEWARE_INGEST_URL = "http://localhost:8000/ingest"
$env:MIDDLEWARE_API_KEY = "팀에서 공유한 ingest 키"
python -m flask --app app run --host 0.0.0.0 --port 5001
```

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
| Kali에서 5001 접속 안 됨 | 웹앱이 127.0.0.1로 실행됨 → 시연하기 1번처럼 `--host 0.0.0.0` |
| 미끼 로그인 후 아무 반응 없음 | Graylog에서 `rule:honeytoken` 검색. 로그가 없으면 1단계(GELF UDP 입력·`12201/udp` 포트) 확인 |
| Graylog에 로그는 있는데 n8n 미실행 | 2단계 URL 허용 목록, 이벤트 정의의 알림 연결 확인 |
| `webhook "POST honeytoken" is not registered` | n8n 워크플로가 Publish되지 않음 |
| n8n에서 `access to env vars denied` | IP 차단 노드 URL에 `$env`가 남음 → 파일을 다시 가져오거나 고정 주소로 교체 |
| Discord 알림만 안 옴 | 이미 차단된 IP(`changed=false`) → 차단 해제 후 재시도. 또는 Discord 주소 확인 |
| 로그 전송 실패 여부 | 화면에는 표시하지 않고 웹앱 서버 로그에 `Scenario 1 ... failed` 경고로 남음 |

## 자주 묻는 질문

- **공격자가 미끼의 랜덤 비밀번호를 맞히면?** 로그인되지 않습니다. 미끼 계정은 비밀번호 확인 전에 걸러서 항상 실패 화면을 보내고 탐지합니다. 억지로 세션을 만들어도 다음 요청에서 로그아웃되고, 첫 시도에 차단되므로 대입 공격도 이어갈 수 없습니다.
- **정상 사용자가 실수로 미끼를 쓰면?** 미끼 이름은 실제 사용자와 겹치지 않게 정하고 공개하지 않습니다. 오탐이 사실상 없다는 것이 허니토큰의 장점입니다.
- **왜 Wazuh는 쓰지 않나요?** 미끼는 한 번 사용만으로 공격이 확정되어 상관 분석이 필요 없습니다. Graylog → n8n 한 경로로 대응하며, Wazuh 이중화는 확장 과제입니다.
- **탐지 건수가 시도 횟수와 다르면?** 탐지 건수는 티켓별 `occurrence_count` 합계입니다. Graylog가 10초 단위로 검사하므로 짧은 시간의 여러 시도는 한 번으로 묶일 수 있습니다.

## 코드 위치 (참고)

| 위치 | 내용 |
|---|---|
| `web-app/app.py` 끝의 시나리오 1 블록 | 미끼 로그인 탐지·위장 응답, Graylog·Middleware 전송, 차단 IP 403, 미끼 세션 차단, 미끼 심기 |
| `web-app/security_store.py` | `honeytokens` 표, 미끼 조회·사용 기록, 관리자 박스 현황 |
| `web-app/templates/admin.html` | 관리자 '시나리오 관리' 박스 |
| `app.py` `/automation/honeytoken-response` | 티켓·이벤트·차단 처리, `changed` 반환 |
