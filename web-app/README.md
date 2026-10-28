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
| `security_events` | n8n이 전달한 개별 보안 이벤트. 반복 이벤트도 별도 행으로 저장 |
| `incident_tickets` | 인시던트 상태, 반복 횟수, 생성·종료 시각 |
| `blocked_ips` | 현재 차단 중인 IP와 사유·관련 인시던트 |
| `api_keys` | 키 식별자, 키 해시, 이름, 허용 IP, 활성·폐기 상태, 발급·폐기 시각 |

- 키 원본은 발급 결과에서 한 번 표시하고 DB에는 SHA-256 해시를 저장합니다. 관리자 목록에서는 원본을 다시 조회할 수 없습니다.
- 키 발급·폐기와 IP 차단 상태는 API 요청 시 DB에서 확인하므로 서버 재시작 없이 반영됩니다. 서버 재시작 후에도 DB 상태가 유지됩니다.
- `blocked_ips`에서 IP를 삭제하면 차단 판정은 해제됩니다. 폐기된 키와 허용 IP 검사는 별개이며, 새 탐지가 발생하면 다시 차단될 수 있습니다.
- 티켓 종료는 처리 상태만 바꾸며 API 키 폐기나 IP 차단을 해제하지 않습니다.
- 기본 `admin`을 제외한 신규 회원은 일반 회원입니다. 관리자는 회원 관리에서 등급을 변경할 수 있으며 기본 `admin`과 본인 등급은 변경할 수 없습니다.
- 회원 목록 번호는 화면 순번이며 DB 고유 ID와 다릅니다. 테스트 계정을 삭제해도 DB의 자동 증가 ID는 되돌리지 않습니다.
- 공용 API의 요청 횟수와 자체 인시던트 번호 생성용 메모리 상태까지 DB로 이전한 것은 아닙니다. DB에 저장된 티켓·키·차단 상태와 구분해야 합니다.

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
