# EngineSquare 공통 웹앱

메인 화면·회원가입·로그인·게시판·대시보드·관리자 기능을 제공하는 Flask 웹앱입니다.

웹 서버는 `127.0.0.1:5001`, 프로젝트 루트의 공용 API 서버는 `127.0.0.1:5000`에서 실행합니다. 두 서버는 같은 MySQL의 API 키·IP 차단 상태를 사용합니다. SQLite는 사용하지 않습니다.

## MySQL 연결

기존 Docker 컨테이너 `mysql-server`가 실행 중이어야 합니다. 현재 로컬 실습 환경의 기본 설정은 다음과 같습니다.

| 환경변수 | 기본값 |
| --- | --- |
| `ENGINESQUARE_DB_HOST` | `127.0.0.1` |
| `ENGINESQUARE_DB_PORT` | `3306` |
| `ENGINESQUARE_DB_USER` | `root` |
| `ENGINESQUARE_DB_PASSWORD` | `123456` |
| `ENGINESQUARE_DB_NAME` | `enginesquare` |

설정이 다르면 각 서버를 실행할 PowerShell 창에 같은 환경변수를 지정합니다. 아래 비밀번호는 실제 MySQL 설정값으로 바꿉니다.

```powershell
$env:ENGINESQUARE_DB_HOST = "127.0.0.1"
$env:ENGINESQUARE_DB_PORT = "3306"
$env:ENGINESQUARE_DB_USER = "root"
$env:ENGINESQUARE_DB_PASSWORD = "본인 MySQL 비밀번호"
$env:ENGINESQUARE_DB_NAME = "enginesquare"
```

웹앱의 DB 연결과 스키마 준비는 이 폴더의 `app.py`, 두 서버가 공유하는 키·차단 데이터 처리는 `security_store.py`에 있습니다.

## 테이블과 저장 범위

| 테이블 | 용도 |
| --- | --- |
| `users` | 회원 아이디, 비밀번호 해시, 가입 시각, 등급(`member` / `admin`) |
| `posts` | 게시글 제목·내용·작성자·작성일 |
| `security_events` | n8n이 전달한 탐지 이벤트와 API가 직접 저장한 정상 허용 이벤트. 반복 이벤트도 별도 행으로 저장 |
| `incident_tickets` | 인시던트 상태, 반복 횟수, 생성·종료 시각 |
| `blocked_ips` | 현재 차단 중인 IP와 사유·관련 인시던트 |
| `api_keys` | 키 식별자, 키 해시, 이름, 허용 IP, 활성·폐기 상태, 발급·폐기 시각 |
| `incident_registry` | 이벤트 유형·출발지 IP·키 식별자별 인시던트 ID 연결 |
| `incident_counters` | 재시작 후에도 유지되는 인시던트 번호의 마지막 값 |

- 수동 발급 키 원본은 복사 버튼이 있는 팝업에서 한 번 표시하고 DB에는 SHA-256 해시를 저장합니다.
- 자동 교체 키는 이전 키 식별자와 관련 인시던트를 함께 기록합니다. 목록의 `[교체]` 표시 또는 키 이름을 누르면 연결 정보를 확인할 수 있습니다.
- 자동 교체 키 원본은 관리자 전달 전까지 암호화해 DB에 임시 보관합니다. 관리자의 `새 키 확인` 요청이 성공하면 암호문을 삭제하며, 다시 조회할 수 없습니다. 키 폐기 시 미확인 원본도 삭제됩니다.
- 암호화 키는 기본적으로 `web-app/.instance/key-delivery.secret`에 자동 생성하며 Git에서 제외합니다. API·웹앱은 같은 암호화 키를 사용해야 합니다. 서로 다른 PC에서 같은 DB에 연결한다면 동일한 Fernet 키를 `ENGINESQUARE_KEY_DELIVERY_SECRET` 환경변수로 설정해야 합니다. `.instance`를 삭제하면 미확인 교체 키를 복호화할 수 없습니다.
- 원본이 이미 사라진 기존 키는 복구할 수 없습니다. 관리자가 `새 키로 교체`를 선택하면 기존 활성 키를 폐기하고 새 키를 팝업으로 전달합니다. IP 차단 상태는 유지됩니다.
- 키 발급·폐기와 IP 차단 상태는 API 요청 시 DB에서 확인하므로 서버 재시작 없이 반영됩니다. 서버 재시작 후에도 DB 상태가 유지됩니다.
- `blocked_ips`에서 IP를 삭제하면 차단 판정은 해제됩니다. 폐기된 키와 허용 IP 검사는 별개이며, 새 탐지가 발생하면 다시 차단될 수 있습니다.
- 티켓 종료는 처리 상태만 바꾸며 API 키 폐기나 IP 차단을 해제하지 않습니다.
- 정상 API 요청(`api_request_allowed`, HTTP 200)은 API 서버가 DB에 직접 저장하므로 최근 이벤트의 `허용` 필터에서 볼 수 있습니다. 티켓·차단 기록은 생성하지 않으며 기존 Middleware/Graylog 로그 전송은 유지합니다.
- API 키 이상 요청은 API가 즉시 이벤트와 티켓을 저장합니다. 같은 이벤트 유형·IP·키는 티켓을 공유하며 실제 요청마다 횟수만 증가합니다. 차단된 IP의 요청도 최근 이벤트에서 확인할 수 있습니다. n8n 결과 수신은 조치만 갱신하며 요청 횟수를 중복 집계하지 않습니다.
- 활성 키의 이상 요청은 같은 IP·키별 5분 동안 한 번만 `api_key_compromised`로 전달합니다. 그 사이의 반복 및 폐기된 키의 차단 요청은 `api_request_blocked`로 Middleware에 전달하므로 반복 알림을 만들지 않습니다. 다른 활성 키는 즉시 별도 탐지 대상입니다.
- Graylog 시나리오 3 규칙은 검색 범위/실행 주기 각각 15초, 이벤트 키 `api_key_id`, `client_ip`, 알림 유예 5분을 사용합니다. 다른 규칙과 n8n 노드는 변경하지 않습니다. 대시보드 기록은 즉시 저장되지만 알림은 다음 탐지 실행과 전달 시간만큼 지연될 수 있습니다.
- 기본 `admin`을 제외한 신규 회원은 일반 회원입니다. 관리자는 회원 관리에서 등급을 변경할 수 있으며 기본 `admin`과 본인 등급은 변경할 수 없습니다.
- 회원 목록 번호는 화면 순번이며 DB 고유 ID와 다릅니다. 테스트 계정을 삭제해도 DB의 자동 증가 ID는 되돌리지 않습니다.
- 인시던트 ID는 공용 API와 웹앱이 같은 DB 레지스트리에서 관리합니다. 같은 이벤트 유형·IP·키는 동일한 ID를 사용하고, 다른 키는 새 ID를 받습니다. 서버 재시작이나 데이터 삭제로 번호를 되돌리지 않습니다.
- 이벤트·티켓·반복 횟수·차단 기록은 하나의 트랜잭션으로 저장합니다. 실패 시 일부 행만 남기지 않습니다. ID 충돌은 HTTP 409, 연결·일시적 운영 오류는 503, 기타 저장 오류는 500으로 구분합니다.
- 공용 API의 요청 횟수와 조회용 메모리 이벤트 목록은 여전히 재시작 시 초기화됩니다.

## 처음 실행하거나 기존 DB를 사용할 때

1. MySQL을 실행한 뒤 웹앱을 먼저 시작합니다.
2. 웹앱이 데이터베이스와 필요한 테이블을 없을 때만 생성합니다.
3. 기존 `users`에 `role` 열이 없으면 추가하고, 기존 일반 회원은 `member`, 기본 `admin`은 `admin`으로 설정합니다.
4. `admin` 계정이 없을 때만 초기 계정(`admin` / `1234`)을 만듭니다. 기존 계정의 비밀번호는 덮어쓰지 않습니다.
5. 공용 API 서버를 별도 창에서 시작합니다.

기존 데이터를 삭제하거나 자동으로 초기화하는 절차는 없습니다. 웹앱 재시작 시 과거 티켓에서 차단 IP를 다시 생성하지 않습니다.

## 실행 명령

최초 의존성 설치는 프로젝트 루트에서 실행합니다.

```powershell
cd D:\KRY\Teamproject\network-team03
python -m pip install -r requirements.txt -r web-app/requirements.txt
```

웹앱:

```powershell
cd D:\KRY\Teamproject\network-team03\web-app
python app.py
```

공용 API는 별도 PowerShell 창에서 실행합니다. 실제 Middleware ingest 키는 실행 환경에 입력하고 문서·코드에 저장하지 않습니다.

```powershell
cd D:\KRY\Teamproject\network-team03
$env:MIDDLEWARE_INGEST_URL = "http://localhost:8000/ingest"
$env:MIDDLEWARE_API_KEY = "팀에서 공유한 실제 ingest 키"
python app.py
```

접속 주소:

- 메인: `http://127.0.0.1:5001/`
- 회원가입: `http://127.0.0.1:5001/register`
- 대시보드: `http://127.0.0.1:5001/dashboard`
- 관리자: `http://127.0.0.1:5001/admin`
- API 상태: `http://127.0.0.1:5000/health`

## 구버전 메모리 키 상태 이관

`migrate_legacy_keys.py`는 메모리 방식의 구버전 API가 아직 실행 중일 때 사용하는 일회성 보조 도구입니다. 기존 기본 테스트 키와 구버전의 `-renewed` 키 체인을 조회해 해시·활성/폐기 상태를 보존합니다. 임의로 발급된 모든 키를 복원하는 도구가 아닙니다.

이미 DB 방식으로 전환한 현재 환경에서는 매번 실행할 필요가 없습니다. 구버전 서버를 먼저 종료하면 그 메모리 상태는 복구할 수 없습니다.

## 검증

프로젝트 루트에서 실행합니다.

```powershell
python web-app/test_admin_security.py
```

실제 MySQL을 사용해 회원가입·권한·게시글·필터·페이지 이동·IP 차단 해제·키 폐기·티켓 종료를 검증합니다. 테스트 전용 행을 생성하고 해당 행만 정리합니다. 테스트로 인해 자동 증가 ID에 빈 번호가 생길 수 있습니다.
