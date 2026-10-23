"""회원가입 / 로그인 / 내 정보(등급 확인)."""
import json
import socket
import time
from datetime import datetime

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import client_ip, db
from models import Honeytoken, User

from .seclog import write_honeytoken_log, write_seclog
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


def _report_login_failure_to_graylog(username, ip, locked=False):
    """로그인 실패마다 GELF로 Graylog에 신고 — 같은 src_ip에서 반복되면 Graylog가 집계해 n8n에 알린다.
    locked=True 면 이미 잠긴 계정에 재시도한 것 — [114] 인시던트 승격 룰(locked:1)이 이 필드를 본다."""
    payload = {
        'version': '1.1',
        'host': socket.gethostname(),
        'short_message': f"login failure: '{username}' from {ip}",
        'timestamp': time.time(),
        'level': 5,
        '_rule': 'login-bruteforce',
        '_username': username,
        '_src_ip': ip,
        '_locked': 1 if locked else 0,
    }
    data = json.dumps(payload).encode('utf-8')
    host = current_app.config.get('GRAYLOG_HOST', 'localhost')
    port = current_app.config.get('GRAYLOG_GELF_PORT', 12201)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, (host, port))
    except OSError:
        pass


def _report_honeytoken_to_graylog(token, ip):
    """시나리오1: 미끼 사용을 GELF로 Graylog에 즉시 신고 — 1회만으로 CRITICAL(n8n 자동 대응 트리거)."""
    payload = {
        'version': '1.1',
        'host': socket.gethostname(),
        'short_message': f"honeytoken used: {token.token_id} ('{token.token_value}') from {ip}",
        'timestamp': time.time(),
        'level': 2,
        '_rule': 'honeytoken',
        '_token_id': token.token_id,
        '_username': token.token_value,
        '_placement': token.placement,
        '_src_ip': ip,
    }
    data = json.dumps(payload).encode('utf-8')
    host = current_app.config.get('GRAYLOG_HOST', 'localhost')
    port = current_app.config.get('GRAYLOG_GELF_PORT', 12201)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, (host, port))
    except OSError:
        pass


def _handle_honeytoken_hit(token, ip):
    """시나리오1: 미끼 계정 사용 감지. 처음 쓰인 거라면 '사용됨'으로 표시한다.
    정상 사용자는 절대 쓰지 않는 계정이라, 1회만으로 침입 확정."""
    # 신고는 매번 — 몇 번 시도했는지도 증거가 된다
    write_honeytoken_log(token.token_id, token.token_value, ip)
    _report_honeytoken_to_graylog(token, ip)
    # '사용됨' 표시는 처음 한 번만 — 첫 사용 시각·IP를 지킨다
    if token.status == 'active':
        token.status = 'used'
        token.used_at = datetime.now()
        token.used_by_ip = ip
        db.session.commit()


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"msg": "이미 존재하는 사용자입니다."}), 400

    hashed_password = generate_password_hash(data['password'])
    # 가입은 항상 일반(user) 등급 — 등급 상승은 관리자 페이지에서만.
    new_user = User(username=data['username'], password=hashed_password, role='user')
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "회원가입 성공"}), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    # ── 시나리오1: 미끼 계정이면 탐지 후 평범한 실패로 위장 ──
    token = Honeytoken.query.filter_by(
        token_value=data.get('username', ''), token_type='account').first()
    if token:
        _handle_honeytoken_hit(token, client_ip())
        return jsonify({"msg": "아이디 또는 비밀번호가 잘못되었습니다."}), 401
    user = User.query.filter_by(username=data['username']).first()
    if user and user.locked:
        _report_login_failure_to_graylog(data.get('username', ''), client_ip(), locked=True)
        write_seclog('login_failed', data.get('username') or '(unknown)', client_ip())
        return jsonify({"msg": "잠긴 계정입니다(관리자에게 문의).", "locked": True}), 423
    if not user or not check_password_hash(user.password, data['password']):
        _report_login_failure_to_graylog(data.get('username', ''), client_ip())
        write_seclog('login_failed', data.get('username') or '(unknown)', client_ip())
        return jsonify({"msg": "아이디 또는 비밀번호가 잘못되었습니다."}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify(access_token=access_token, **user.to_dict())


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    """현재 로그인한 사용자의 최신 등급 — 등급이 바뀐 뒤 재로그인 없이 화면 분기에 쓴다."""
    user = User.query.get(int(get_jwt_identity()))
    if not user:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404
    return jsonify(user.to_dict())
