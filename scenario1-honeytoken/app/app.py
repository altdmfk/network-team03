"""엔트리포인트 — 앱 팩토리(create_app) 패턴.
구조: config.py(설정, .env 로딩) · extensions.py(db·jwt 인스턴스) ·
models/(User·Post·SecurityEvent) · controllers/(page·auth·post·travel·security·admin·gold, 블루프린트) ·
templates/(화면)
실행: python app.py → http://localhost:5000
"""
import json
import socket
import sys
import time

sys.stdout.reconfigure(encoding='utf-8')

import click
from flask import Flask, current_app, jsonify, request
from sqlalchemy import inspect, text

from config import Config
from controllers import all_blueprints
from controllers.seclog import write_404log
from extensions import client_ip, db, jwt


def _report_web_scan_to_graylog(src_ip, path):
    """404 가 나올 때마다 GELF로 Graylog에 신고 — 같은 src_ip가 짧은 시간에
    404 를 대량 유발하면(디렉터리 스캐너 지문) Graylog가 집계해 n8n에 알린다.
    (auth_controller._report_login_failure_to_graylog 와 같은 방식 재사용)"""
    payload = {
        'version': '1.1',
        'host': socket.gethostname(),
        'short_message': f"404 probe {path} from {src_ip}",
        'timestamp': time.time(),
        'level': 5,
        '_rule': 'web-scan',
        '_src_ip': src_ip,
        '_path': path,
        '_code': 404,
    }
    data = json.dumps(payload).encode('utf-8')
    host = current_app.config.get('GRAYLOG_HOST', 'localhost')
    port = current_app.config.get('GRAYLOG_GELF_PORT', 12201)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, (host, port))
    except OSError:
        pass  # Graylog가 꺼져 있어도 응답 자체는 막지 않는다(가용성 우선)


def _ensure_schema():
    """db.create_all() 은 '없는 표'만 만든다. 이미 있던 users/security_events 표에
    RBAC(4장) 컬럼이 없으면 ALTER 로 보강한다 — 여러 번 켜도 안전(있으면 통과)."""
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    with db.engine.connect() as conn:
        if 'users' in tables:
            cols = {c['name'] for c in inspector.get_columns('users')}
            if 'role' not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'"))
            if 'role_granted_by' not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN role_granted_by VARCHAR(80)"))
            if 'role_granted_at' not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN role_granted_at DATETIME"))
            if 'role_reason' not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN role_reason VARCHAR(255)"))
            if 'locked' not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN locked BOOLEAN NOT NULL DEFAULT FALSE"))
            if 'locked_reason' not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN locked_reason VARCHAR(200)"))
            if 'locked_at' not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN locked_at DATETIME"))
        if 'security_events' in tables:
            cols = {c['name'] for c in inspector.get_columns('security_events')}
            if 'source' not in cols:
                conn.execute(text("ALTER TABLE security_events ADD COLUMN source VARCHAR(30)"))
            if 'username' not in cols:
                conn.execute(text("ALTER TABLE security_events ADD COLUMN username VARCHAR(80)"))
        conn.commit()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # 확장 초기화
    db.init_app(app)
    jwt.init_app(app)

    # 컨트롤러(블루프린트) 등록
    for bp in all_blueprints:
        app.register_blueprint(bp)

    @app.before_request
    def _block_ip_guard():
        """실차단(active response) — 라우트에 닿기 전에 여기서 끊는다.
        /api/admin 은 예외: 미들웨어가 관리자 API까지 막으면, 운영자 PC가 실수로 차단됐을 때
        해제할 방법이 사라진다(복구 불능). 그래서 관리 통로는 항상 열어 둔다."""
        if request.path.startswith('/api/admin'):
            return None
        from models import BlockedIP
        ip = client_ip()
        if ip and db.session.get(BlockedIP, ip):
            return jsonify({'msg': '차단된 IP 입니다(관리자에게 문의).', 'ip': ip, 'blocked': True}), 403
        return None

    @app.after_request
    def _web_scan_probe(response):
        """스캐너(nikto·gobuster 등)는 없는 경로에 404를 대량 유발한다.
        404를 ① Wazuh security.log(에이전트가 읽어 wazuh-dashboard 집계)와
        ② 기존 GELF(rule='web-scan', Graylog→n8n) 양쪽에 다 기록한다.
        /api/admin 은 제외(운영·n8n 트래픽 오탐 방지, _block_ip_guard와 같은 이유)."""
        try:
            if response.status_code == 404 and not request.path.startswith('/api/admin'):
                ip, path = client_ip(), request.path[:120]
                try:
                    write_404log(ip, path)              # ① Wazuh security.log
                except Exception:
                    pass
                _report_web_scan_to_graylog(ip, path)   # ② 기존 Graylog
        except Exception:
            pass  # 신고 실패가 응답을 막지 않게
        return response

    # 테이블 생성 (models 를 import 한 뒤여야 한다 — controllers 가 이미 import 함)
    with app.app_context():
        db.create_all()
        _ensure_schema()

    @app.cli.command('bootstrap-admin')
    @click.argument('username')
    @click.argument('password')
    def bootstrap_admin(username, password):
        """관리자가 하나도 없으면 /admin 에 아무도 로그인할 수 없다. SQL 없이 최초 admin 을 만든다.
        사용법: flask --app app.py bootstrap-admin zz_admin <비밀번호>"""
        from werkzeug.security import generate_password_hash

        from models import User

        user = User.query.filter_by(username=username).first()
        if user:
            user.role = 'admin'
        else:
            user = User(username=username, password=generate_password_hash(password), role='admin')
            db.session.add(user)
        db.session.commit()
        click.echo(f'{username} 를 admin 으로 설정했습니다.')

    @app.cli.command('seed-honeytoken')
    @click.argument('token_id')
    @click.argument('username')
    def seed_honeytoken(token_id, username):
        """미끼 계정을 users 표에 심고 honeytokens 표에 등록한다.
        사용법: flask --app app.py seed-honeytoken HT-001 backup_admin"""
        import secrets

        from werkzeug.security import generate_password_hash

        from models import Honeytoken, User

        # 같은 미끼를 두 번 심지 않게
        if db.session.get(Honeytoken, token_id) or Honeytoken.query.filter_by(token_value=username).first():
            click.echo(f'{token_id} 또는 {username} 은(는) 이미 등록된 허니토큰입니다.')
            return
        # 진짜 사용자 계정을 미끼로 덮어쓰지 않게
        if User.query.filter_by(username=username).first():
            click.echo(f'{username} 은(는) 이미 있는 실제 계정입니다. 다른 이름을 쓰세요.')
            return

        decoy = User(username=username,
                     password=generate_password_hash(secrets.token_hex(16)),  # 아무도 모르는 랜덤 비밀번호
                     role='user')
        token = Honeytoken(token_id=token_id, token_type='account',
                           token_value=username, placement='users_table')
        db.session.add_all([decoy, token])
        db.session.commit()
        click.echo(f'{token_id}: 미끼 계정 {username} 을(를) 심었습니다.')
        
    return app

    
app = create_app()

if __name__ == '__main__':
    # host='0.0.0.0' 이면 같은 공유기의 다른 기기에서도 접속 가능.
    # 도커 안 n8n 에서는 http://host.docker.internal:5000 으로 부른다.
    app.run(debug=True, host='0.0.0.0', port=5000)
