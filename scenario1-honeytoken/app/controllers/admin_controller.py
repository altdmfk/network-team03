"""관리자 전용 API — 회원 권한(인가) 관리.
접근 방식 두 가지: 기계(회수봇·n8n)는 X-API-Key: <ADMIN_API_KEY>, 사람은 JWT + role=admin.
회수(POST /revoke)는 반드시 두 경로 모두 허용해야 회수봇/n8n 이 사람 로그인 없이 자동 호출할 수 있다."""
import json
import socket
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, current_app, g, jsonify, request
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request

from extensions import client_ip, db
from models import ROLE_LEVEL, BlockedIP, Honeytoken, Incident, Post, SecurityEvent, User

from .auth_controller import _handle_honeytoken_hit

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


def _report_privilege_violation_to_graylog(username, granted_by, old_role):
    """허용목록 밖 admin 부여를 감지한 그 순간 GELF로 Graylog에 즉시 신고한다.
    (회수봇의 폴링을 기다리지 않고, grant 호출 시점에 바로 보냄)
    old_role — 부여 직전 등급. 회수 시 'user'로 무조건 내리지 않고 이 등급으로 복원하기 위해 같이 신고한다."""
    payload = {
        'version': '1.1',
        'host': socket.gethostname(),
        'short_message': f"privilege violation: '{username}' has unauthorized admin",
        'timestamp': time.time(),
        'level': 4,
        '_rule': 'priv-unauthorized-admin',
        '_user': username,
        '_granted_by': granted_by or '-',
        '_old_role': old_role or 'user',
        '_src_ip': '-',
        '_student': current_app.config.get('STUDENT_NAME', 'unknown'),
        '_reason': f"허용목록({sorted(current_app.config.get('ADMIN_ALLOWLIST', []))}) 밖 admin",
    }
    data = json.dumps(payload).encode('utf-8')
    host = current_app.config.get('GRAYLOG_HOST', 'localhost')
    port = current_app.config.get('GRAYLOG_GELF_PORT', 12201)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, (host, port))
    except OSError:
        pass  # Graylog가 꺼져 있어도 권한 부여 자체는 막지 않는다(가용성 우선)


def _api_key_ok():
    """ADMIN_API_KEY 가 비어 있으면 SECURITY_API_KEY 로 대체한다(둘 다 비면 항상 거부)."""
    expected = current_app.config.get('ADMIN_API_KEY') or current_app.config.get('SECURITY_API_KEY')
    return bool(expected) and request.headers.get('X-API-Key', '') == expected


def _admin_jwt_ok():
    """JWT 가 유효하고 role=admin 이면 True. 실패해도 예외를 던지지 않아 API 키 쪽을 이어서 시도할 수 있다."""
    try:
        verify_jwt_in_request()
    except Exception:
        return False
    user = User.query.get(int(get_jwt_identity()))
    if not (user and user.is_admin):
        return False
    g.revoked_by = user.username  # 감사기록용 — "누가" 회수를 실행시켰는지(사람 vs 기계)
    return True


def admin_required(fn):
    """기계(API 키) 또는 사람(관리자 JWT) 둘 중 하나만 통과하면 된다."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # 시나리오1: 관리 콘솔에 심어둔 가짜 관리자 키로 들어오면 탐지 후 일반 실패와 똑같이 거절
        provided = request.headers.get('X-API-Key', '')
        if provided:
            decoy = Honeytoken.query.filter_by(token_value=provided, token_type='api_key').first()
            if decoy:
                _handle_honeytoken_hit(decoy, client_ip())
                return jsonify({'msg': '관리자 권한이 없습니다.'}), 401
        if _api_key_ok():
            g.revoked_by = 'apikey'
            return fn(*args, **kwargs)
        if _admin_jwt_ok():
            return fn(*args, **kwargs)
        return jsonify({'msg': '관리자 권한이 없습니다.'}), 401
    return wrapper


@admin_bp.route('/users', methods=['GET'])
@admin_required
def list_users():
    """?role= 로 특정 등급만 필터 — 회수봇이 role=admin 만 뽑아 허용목록과 대조할 때 쓴다."""
    role = request.args.get('role')
    query = User.query
    if role:
        query = query.filter_by(role=role)
    users = query.order_by(User.id.asc()).all()
    return jsonify({'users': [u.to_dict() for u in users]})


@admin_bp.route('/violations', methods=['GET'])
@admin_required
def list_violations():
    """회수봇이 남긴 신고·회수 기록(source=privilege-guard) — 대시보드/감사용."""
    limit = request.args.get('limit', default=20, type=int)
    rows = (SecurityEvent.query
            .filter_by(source='privilege-guard')
            .order_by(SecurityEvent.id.desc())
            .limit(min(limit, 100)).all())
    return jsonify({'count': len(rows), 'violations': [r.to_dict() for r in rows]})


def _apply_role_change(username, new_role, granted_by, reason):
    user = User.query.filter_by(username=username).first()
    if not user:
        return None, (jsonify({'msg': f"'{username}' 사용자를 찾을 수 없습니다."}), 404)
    if new_role not in ROLE_LEVEL:
        return None, (jsonify({'msg': f"role 은 {list(ROLE_LEVEL)} 중 하나여야 합니다."}), 400)

    old_role = user.role
    user.role = new_role
    user.role_granted_by = granted_by
    user.role_granted_at = datetime.utcnow()
    user.role_reason = reason
    db.session.commit()
    return {'username': user.username, 'old_role': old_role, 'new_role': user.role}, None


@admin_bp.route('/grant', methods=['POST'])
@admin_required
def grant_role():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    role = data.get('role')
    if not username or not role:
        return jsonify({'msg': 'username, role 은 필수입니다.'}), 400

    granted_by = data.get('granted_by') or '관리자'
    result, error = _apply_role_change(
        username, role,
        granted_by=granted_by,
        reason=data.get('reason'),
    )
    if error:
        return error

    if role == 'admin' and username not in current_app.config.get('ADMIN_ALLOWLIST', []):
        _report_privilege_violation_to_graylog(username, granted_by, result['old_role'])

    return jsonify(result), 200


@admin_bp.route('/revoke', methods=['POST'])
@admin_required
def revoke_role():
    """과잉권한 회수 — 회수봇/n8n 이 이 엔드포인트 하나로 role=user 복원 + 감사기록을 처리한다.
    멱등(idempotent): 이미 user 인 계정을 다시 신고해도 등급 변경도 감사기록 중복도 없이 조용히 통과한다."""
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({'msg': 'username 은 필수입니다.'}), 400

    restore_role = data.get('old_role') or 'user'
    if restore_role not in ROLE_LEVEL:
        restore_role = 'user'

    result, error = _apply_role_change(
        username, restore_role,
        granted_by=data.get('granted_by', 'privilege-guard'),
        reason=data.get('reason', '과잉권한 자동 회수'),
    )
    if error:
        return error

    revoked = result['old_role'] != restore_role
    event_id = None
    if revoked:
        ev = SecurityEvent(
            student=data.get('student', 'system'),
            src_ip=data.get('src_ip', '-'),
            decision='deny',
            severity=data.get('severity', 'High'),
            reason=data.get('reason', '과잉권한 자동 회수'),
            rule='priv-unauthorized-admin',
            source='privilege-guard',
            username=username,
        )
        db.session.add(ev)
        db.session.commit()
        event_id = ev.id

    return jsonify({
        'msg': '회수 완료',
        'username': result['username'],
        'old_role': result['old_role'],
        'new_role': result['new_role'],
        'revoked': revoked,
        'event_id': event_id,
        'revoked_by': getattr(g, 'revoked_by', 'admin'),
    }), 200


@admin_bp.route('/lock', methods=['POST'])
@admin_required
def lock_account():
    """계정 잠금 — n8n/브루트포스 탐지 결과로 호출. 멱등: 이미 잠긴 계정은 changed=false로 조용히 통과."""
    d = request.get_json(silent=True) or {}
    username = (d.get('username') or '').strip()
    if not username:
        return jsonify({'msg': 'username 은 필수입니다.'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'msg': f"'{username}' 사용자를 찾을 수 없습니다."}), 404
    if user.locked:
        return jsonify({'msg': '이미 잠긴 계정', 'username': username, 'locked': True, 'changed': False}), 200

    actor = getattr(g, 'revoked_by', 'unknown')
    user.locked = True
    user.locked_reason = (d.get('reason') or f'자동 잠금 by {actor}')[:200]
    user.locked_at = datetime.now()
    ev = SecurityEvent(
        student=(d.get('student') or 'system')[:50],
        src_ip=(d.get('src_ip') or '-'),
        fail_count=int(d.get('fail_count') or 0),
        decision='deny',
        severity=d.get('severity') or 'High',
        reason=f'계정 잠금: {username}'[:200],
        source='login-guard',
        username=username,
    )
    db.session.add(ev)
    db.session.commit()
    return jsonify({'msg': '계정 잠금 완료', 'username': username, 'locked': True, 'changed': True, 'event_id': ev.id}), 200


@admin_bp.route('/unlock', methods=['POST'])
@admin_required
def unlock_account():
    """잠금 해제 — 대응 완료 후 관리자/스크립트가 호출."""
    d = request.get_json(silent=True) or {}
    username = (d.get('username') or '').strip()
    if not username:
        return jsonify({'msg': 'username 은 필수입니다.'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'msg': f"'{username}' 사용자를 찾을 수 없습니다."}), 404
    if not user.locked:
        return jsonify({'msg': '이미 잠기지 않은 계정', 'username': username, 'locked': False, 'changed': False}), 200

    user.locked = False
    user.locked_reason = None
    user.locked_at = None
    db.session.commit()
    return jsonify({'msg': '잠금 해제 완료', 'username': username, 'locked': False, 'changed': True}), 200


@admin_bp.route('/block', methods=['POST'])
@admin_required
def block_ip():
    """실차단 등록 — n8n이 집계 결과를 받아 호출. 멱등: 이미 차단된 IP는 changed=false로 조용히 통과."""
    d = request.get_json(silent=True) or {}
    ip = (d.get('ip') or d.get('src_ip') or '').strip()
    if not ip:
        return jsonify({'msg': 'ip(또는 src_ip) 는 필수입니다.'}), 400

    actor = getattr(g, 'revoked_by', 'unknown')
    if db.session.get(BlockedIP, ip):
        return jsonify({'msg': '이미 차단된 IP', 'ip': ip, 'blocked': True, 'changed': False}), 200

    db.session.add(BlockedIP(ip=ip, reason=(d.get('reason') or f'자동 차단 by {actor}')[:200], blocked_by=actor[:80]))
    ev = SecurityEvent(
        student=(d.get('student') or 'system')[:50],
        src_ip=ip,
        fail_count=int(d.get('fail_count') or 0),
        decision='deny',
        severity=d.get('severity') or 'High',
        reason=f'IP 실차단: {ip}'[:200],
        source='ip-guard',
    )
    db.session.add(ev)
    db.session.commit()
    return jsonify({'msg': 'IP 차단 완료', 'ip': ip, 'blocked': True, 'changed': True, 'event_id': ev.id}), 200


@admin_bp.route('/unblock', methods=['POST'])
@admin_required
def unblock_ip():
    """차단 해제 — 관리자 API는 차단 IP에서도 접근 가능해서, 자기 자신을 차단해 복구 불능이 되는 걸 막는다."""
    d = request.get_json(silent=True) or {}
    ip = (d.get('ip') or '').strip()
    if not ip:
        return jsonify({'msg': 'ip는 필수입니다.'}), 400

    existing = db.session.get(BlockedIP, ip)
    if existing:
        db.session.delete(existing)
        db.session.commit()
        return jsonify({'msg': '차단 해제 완료', 'ip': ip, 'blocked': False}), 200
    return jsonify({'msg': '이미 차단되지 않은 IP', 'ip': ip, 'blocked': False}), 200


@admin_bp.route('/blocked', methods=['GET'])
@admin_required
def list_blocked():
    rows = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return jsonify({'count': len(rows), 'blocked_ips': [r.to_dict() for r in rows]})


@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """회원 탈퇴 처리 — 그 회원이 쓴 게시글도 함께 지운다(author_id 외래키 제약).
    JWT(관리자)로 부른 경우 본인 계정은 여기서 못 지운다(관리자 페이지에서 자기 자신을 지워 잠기는 사고 방지)."""
    try:
        verify_jwt_in_request(optional=True)
        current_id = int(get_jwt_identity()) if get_jwt_identity() else None
    except Exception:
        current_id = None

    if current_id is not None and current_id == user_id:
        return jsonify({'msg': '본인 계정은 관리자 페이지에서 삭제할 수 없습니다.'}), 400

    target = User.query.get(user_id)
    if not target:
        return jsonify({'msg': '사용자를 찾을 수 없습니다.'}), 404

    Post.query.filter_by(author_id=target.id).delete()
    username = target.username
    db.session.delete(target)
    db.session.commit()
    return jsonify({'msg': f"'{username}' 회원이 삭제되었습니다."}), 200


_SEV_RANK = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}


def _build_incident_summary(src_ip, events):
    by_source, actions, worst, lines = {}, set(), 'Low', []
    for e in events:
        by_source[e.source] = by_source.get(e.source, 0) + 1
        if e.decision:
            actions.add(e.decision)
        if _SEV_RANK.get(e.severity, 1) > _SEV_RANK.get(worst, 1):
            worst = e.severity
        when = e.created_at.strftime('%Y-%m-%d %H:%M:%S') if e.created_at else '?'
        lines.append(f"- {when} [{e.severity}/{e.source}] {e.reason or ''} (username={e.username or '-'})")
    summary = (f"[인시던트 요약] 출발지 {src_ip}\n- 관련 이벤트: {len(events)}건 "
               f"({', '.join(f'{k}×{v}' for k, v in sorted(by_source.items(), key=lambda kv: kv[0] or ''))})\n"
               f"- 취해진 조치: {', '.join(sorted(actions)) or '없음'}\n"
               f"- 최고 심각도: {worst}\n[타임라인]\n" + "\n".join(lines[:20]))
    return summary, worst, ', '.join(sorted(actions)) or '없음', len(events)


@admin_bp.route('/incident', methods=['POST'])
@admin_required
def create_incident():
    """출발지(src_ip) 기준으로 security_events 를 자동 취합해 티켓을 생성/갱신한다.
    같은 src_ip 에 열린 티켓이 있으면 갱신(중복 방지), 없으면 신규 생성."""
    d = request.get_json(silent=True) or {}
    src_ip = (d.get('src_ip') or d.get('ip') or '').strip()
    if not src_ip:
        return jsonify({'msg': 'src_ip 는 필수입니다.'}), 400

    since = datetime.now() - timedelta(hours=int(d.get('hours') or 24))
    last_closed = (Incident.query
                   .filter(Incident.src_ip == src_ip, Incident.status == 'closed', Incident.closed_at.isnot(None))
                   .order_by(Incident.closed_at.desc()).first())
    if last_closed and last_closed.closed_at > since:
        since = last_closed.closed_at

    events = (SecurityEvent.query
              .filter(SecurityEvent.src_ip == src_ip, SecurityEvent.created_at >= since)
              .order_by(SecurityEvent.created_at.desc()).all())
    summary, worst, actions, cnt = _build_incident_summary(src_ip, events)

    inc = Incident.query.filter_by(src_ip=src_ip, status='open').first()  # 열린 티켓 1개(중복 방지)
    created = False
    if not inc:
        inc = Incident(src_ip=src_ip, status='open')
        db.session.add(inc)
        created = True

    inc.title = (d.get('title') or f'보안 인시던트: {src_ip} ({cnt}건)')[:200]
    # 심각도는 내려가지 않는다: 요청값·취합 최고값·기존 값 중 최대
    inc.severity = max((d.get('severity') or worst, worst, inc.severity or 'Low'), key=lambda s: _SEV_RANK.get(s, 0))
    inc.summary, inc.event_count, inc.actions = summary, cnt, actions[:255]
    inc.student = (d.get('student') or getattr(g, 'revoked_by', 'unknown'))[:50]
    db.session.commit()

    return jsonify({
        'msg': '인시던트 생성' if created else '인시던트 갱신',
        'created': created,
        'incident': inc.to_dict(),
    }), (201 if created else 200)


@admin_bp.route('/incidents', methods=['GET'])
@admin_required
def list_incidents():
    status = request.args.get('status')
    query = Incident.query
    if status:
        query = query.filter_by(status=status)
    rows = query.order_by(Incident.updated_at.desc()).all()
    return jsonify({'count': len(rows), 'incidents': [r.to_dict() for r in rows]})


@admin_bp.route('/incident/close', methods=['POST'])
@admin_required
def close_incident():
    d = request.get_json(silent=True) or {}
    incident_id = d.get('id')
    if not incident_id:
        return jsonify({'msg': 'id 는 필수입니다.'}), 400

    inc = db.session.get(Incident, incident_id)
    if not inc:
        return jsonify({'msg': f"인시던트 #{incident_id} 를 찾을 수 없습니다."}), 404
    if inc.status == 'closed':
        return jsonify({'msg': '이미 종료된 인시던트', 'incident': inc.to_dict(), 'changed': False}), 200

    inc.status = 'closed'
    inc.closed_at = datetime.now()
    db.session.commit()
    return jsonify({'msg': '인시던트 종료', 'incident': inc.to_dict(), 'changed': True}), 200


# ── 시나리오1: 허니토큰(미끼) 관리 콘솔 ──
def _next_token_id():
    nums = [int(r.token_id.split('-')[1]) for r in Honeytoken.query.all()
            if r.token_id.startswith('HT-') and r.token_id.split('-')[1].isdigit()]
    return f'HT-{(max(nums) + 1) if nums else 1:03d}'


@admin_bp.route('/honeytokens', methods=['GET'])
@admin_required
def list_honeytokens():
    """현황 — 미끼 목록과 상태별 개수."""
    rows = Honeytoken.query.order_by(Honeytoken.token_id).all()
    counts = {s: sum(1 for r in rows if r.status == s) for s in ('active', 'used', 'revoked')}
    return jsonify({'count': len(rows), 'counts': counts, 'honeytokens': [r.to_dict() for r in rows]})


@admin_bp.route('/honeytokens', methods=['POST'])
@admin_required
def create_honeytoken():
    """생성 — 미끼 계정(account) 또는 가짜 관리자 키(api_key). 번호(HT-00N)는 자동."""
    import secrets

    from werkzeug.security import generate_password_hash

    d = request.get_json(silent=True) or {}
    token_type = d.get('token_type') or 'account'
    token_id = _next_token_id()

    if token_type == 'account':
        username = (d.get('username') or '').strip()
        if not username:
            return jsonify({'msg': '미끼 계정명은 필수입니다.'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'msg': '이미 있는 계정명입니다. 다른 이름을 쓰세요.'}), 400
        db.session.add(User(username=username, password=generate_password_hash(secrets.token_hex(16)), role='user'))
        db.session.add(Honeytoken(token_id=token_id, token_type='account', token_value=username, placement='users_table'))
    elif token_type == 'api_key':
        # 진짜 ADMIN_API_KEY와 같은 모양(64자리 16진수)이라 공격자가 구분할 수 없다
        db.session.add(Honeytoken(token_id=token_id, token_type='api_key', token_value=secrets.token_hex(32), placement='admin_console'))
    else:
        return jsonify({'msg': 'token_type은 account 또는 api_key 입니다.'}), 400

    db.session.commit()
    return jsonify({'msg': f'{token_id} 미끼를 심었습니다.', 'token_id': token_id}), 201


@admin_bp.route('/honeytokens/<token_id>/revoke', methods=['POST'])
@admin_required
def revoke_honeytoken(token_id):
    """회수 — 관리 목록에서 '회수됨'으로 표시. 탐지는 계속 유지된다(누가 써도 공격이니까)."""
    token = db.session.get(Honeytoken, token_id)
    if not token:
        return jsonify({'msg': '없는 미끼입니다.'}), 404
    token.status = 'revoked'
    db.session.commit()
    return jsonify({'msg': f'{token_id} 미끼를 회수했습니다.', 'honeytoken': token.to_dict()})


@admin_bp.route('/honeytokens/overview', methods=['GET'])
@admin_required
def honeytoken_overview():
    """시나리오1 관제 화면용 — 미끼 현황 + 탐지 기록(사용 → 차단 → 인시던트)을 한 번에.
    대응 시간 = 차단 시각 - 미끼 사용 시각(초). 화면 시계 오차를 피하려고 server_now도 같이 준다."""
    rows = Honeytoken.query.order_by(Honeytoken.token_id).all()
    counts = {s: sum(1 for r in rows if r.status == s) for s in ('active', 'used', 'revoked')}

    detections = []
    for t in sorted((r for r in rows if r.used_at), key=lambda r: r.used_at, reverse=True):
        ip = t.used_by_ip
        blocked = db.session.get(BlockedIP, ip) if ip else None
        inc = None
        if ip:
            inc = (Incident.query.filter(Incident.src_ip == ip,
                                         Incident.created_at >= t.used_at - timedelta(minutes=1))
                   .order_by(Incident.created_at).first())
        response_sec = None
        if blocked and blocked.blocked_at and blocked.blocked_at >= t.used_at:
            response_sec = round((blocked.blocked_at - t.used_at).total_seconds(), 1)
        d = t.to_dict()
        d.update({
            'ip': ip,
            'blocked': bool(blocked),
            'blocked_at': blocked.blocked_at.isoformat() if blocked and blocked.blocked_at else None,
            'response_sec': response_sec,
            'incident': ({'id': inc.id, 'status': inc.status, 'severity': inc.severity,
                          'created_at': inc.created_at.isoformat() if inc.created_at else None}
                         if inc else None),
        })
        detections.append(d)

    secs = [d['response_sec'] for d in detections if d['response_sec'] is not None]
    blocked_ips = BlockedIP.query.filter(BlockedIP.reason.like('%허니토큰%')).count()
    return jsonify({
        'server_now': datetime.now().isoformat(),
        'counts': counts,
        'honeytokens': [r.to_dict() for r in rows],
        'detections': detections,
        'stats': {
            'detections': len(detections),
            'blocked_ips': blocked_ips,
            'avg_response_sec': round(sum(secs) / len(secs), 1) if secs else None,
        },
    })


# 공격자가 탐낼 만한 계정명 — 백업·서비스·운영·퇴사자 계정처럼 "권한은 높고 아무도 안 쓰는" 느낌
HONEY_NAME_POOL = [
    'backup_admin', 'svc_deploy', 'db_backup', 'sys_ops', 'admin_old', 'root_backup',
    'it_support', 'jenkins_svc', 'ops_monitor', 'vpn_admin', 'payroll_admin', 'hr_admin',
    'dev_admin', 'test_admin', 'admin_temp', 'svc_backup', 'infra_ops', 'sec_audit',
]


@admin_bp.route('/honeytokens/suggest', methods=['GET'])
@admin_required
def suggest_honeytoken_names():
    """미끼 계정명 추천 — 이미 있는 회원 이름은 빼고 무작위 4개."""
    import random

    taken = {u.username for u in User.query.with_entities(User.username).all()}
    pool = [n for n in HONEY_NAME_POOL if n not in taken]
    return jsonify({'names': random.sample(pool, min(4, len(pool)))})
