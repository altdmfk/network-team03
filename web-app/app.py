
import os
import re
import secrets
import hmac
from functools import wraps
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
import pymysql
from pymysql.cursors import DictCursor
from werkzeug.security import check_password_hash, generate_password_hash
from security_store import SecurityStore
from pagination import Page
from itsdangerous import BadSignature, URLSafeTimedSerializer


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("ENGINESQUARE_SESSION_SECRET") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
security_store = SecurityStore()


def bulk_token(kind, identifiers):
    return URLSafeTimedSerializer(app.secret_key, salt="bulk-management").dumps({"kind": kind, "ids": identifiers})


def bulk_targets(token, kind):
    try:
        data = URLSafeTimedSerializer(app.secret_key, salt="bulk-management").loads(token, max_age=900)
    except BadSignature:
        abort(400, "확인 요청이 만료되었습니다. 화면을 새로 열어 주세요.")
    if data.get("kind") != kind or not isinstance(data.get("ids"), list):
        abort(400)
    return data["ids"]


@app.template_global()
def page_url(parameter, number, anchor):
    names = ("members_page", "keys_page", "blocks_page", "key_status") if request.endpoint == "admin" else ("tickets_page", "events_page", "ticket_status", "event_decision")
    args = {name: request.args[name] for name in names if name in request.args}
    args[parameter] = number
    return url_for(request.endpoint, **args)


@app.template_global()
def key_filter_url(value):
    args = {name: request.args[name] for name in ("members_page", "blocks_page") if name in request.args}
    return url_for("admin", keys_page=1, key_status=value, **args)


@app.template_global()
def dashboard_filter_url(parameter, value):
    page_parameter = {"ticket_status": "tickets_page", "event_decision": "events_page"}[parameter]
    args = {name: request.args[name] for name in ("tickets_page", "events_page", "ticket_status", "event_decision") if name in request.args}
    args[parameter] = value
    args[page_parameter] = 1
    return url_for("dashboard", **args)


@app.template_global()
def ticket_action_url():
    args = {name: request.args[name] for name in ("tickets_page", "events_page", "ticket_status", "event_decision") if name in request.args}
    return url_for("close_tickets", **args)


app.config["MYSQL_HOST"] = os.getenv("ENGINESQUARE_DB_HOST", "127.0.0.1")
app.config["MYSQL_PORT"] = int(os.getenv("ENGINESQUARE_DB_PORT", "3306"))
app.config["MYSQL_USER"] = os.getenv("ENGINESQUARE_DB_USER", "root")
app.config["MYSQL_PASSWORD"] = os.getenv("ENGINESQUARE_DB_PASSWORD", "123456")
app.config["MYSQL_DATABASE"] = os.getenv("ENGINESQUARE_DB_NAME", "enginesquare")


class CompatRow(dict):
    """Dict-like MySQL row that also supports the old numeric access style."""

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class MySQLCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, query, params=None):
        self._cursor.execute(query.replace("?", "%s"), params or ())
        return self

    def executemany(self, query, params):
        self._cursor.executemany(query.replace("?", "%s"), params)
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        return CompatRow(row) if row else None

    def fetchall(self):
        return [CompatRow(row) for row in self._cursor.fetchall()]

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount


class MySQLConnection:
    def __init__(self, connection):
        self._connection = connection

    def execute(self, query, params=None):
        cursor = self._connection.cursor()
        return MySQLCursor(cursor).execute(query, params)

    def executemany(self, query, params):
        cursor = self._connection.cursor()
        return MySQLCursor(cursor).executemany(query, params)

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()


def connect_mysql(database=None):
    return pymysql.connect(
        host=app.config["MYSQL_HOST"],
        port=app.config["MYSQL_PORT"],
        user=app.config["MYSQL_USER"],
        password=app.config["MYSQL_PASSWORD"],
        database=database,
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=False,
    )


@app.template_filter("display_time")
def display_time(value):
    if not value:
        return "-"
    raw = str(value).strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone(timedelta(hours=9)))
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return raw.replace("T", " ")[:19]


SCENARIOS = [
    {"id": "01", "name": "허니토큰 기만 탐지", "status": "정상", "count": 7},
    {"id": "02", "name": "로그 버퍼링", "status": "정상", "count": 12},
    {"id": "03", "name": "유출 API 키 탐지", "status": "주의", "count": 3},
    {"id": "04", "name": "킬체인 상관분석", "status": "정상", "count": 5},
]

TICKETS = [
    {"id": "INC-API-003", "title": "비허용 IP의 API 키 사용", "ip": "10.10.10.10", "scenario": "시나리오 3", "event": "api_key_compromised", "action": "키 폐기·IP 차단", "status": "종료", "severity": "높음", "severity_class": "high", "created_at": "2026-10-27 11:01", "closed_at": "2026-10-27 11:02"},
    {"id": "INC-API-002", "title": "반복 인증 실패 감지", "ip": "10.10.10.12", "scenario": "시나리오 1", "event": "authentication_failed", "action": "확인 필요", "status": "열림", "severity": "중간", "severity_class": "medium", "created_at": "2026-10-27 10:42", "closed_at": "-"},
    {"id": "INC-API-001", "title": "로그 버퍼링 지연 확인", "ip": "192.168.3.8", "scenario": "시나리오 2", "event": "queue_lag", "action": "로그 재전송", "status": "종료", "severity": "낮음", "severity_class": "low", "created_at": "2026-10-27 09:18", "closed_at": "2026-10-27 09:20"},
]

TOP_IPS = [
    {"ip": "10.10.10.10", "count": 240},
    {"ip": "10.10.10.12", "count": 70},
    {"ip": "192.168.3.8", "count": 15},
    {"ip": "172.16.0.21", "count": 15},
    {"ip": "172.16.0.30", "count": 13},
]

RECENT_EVENTS = [
    {"id": 272, "user": "kry", "ip": "203.0.113.44", "decision": "거부", "severity": "High", "count": 6, "reason": "공격 출발지 자동 차단: 6회 로그인 실패(동일 IP)", "saved_at": "2026-10-16 13:41:56"},
    {"id": 271, "user": "kry", "ip": "203.0.113.44", "decision": "거부", "severity": "High", "count": 6, "reason": "공격 출발지 자동 차단: 6회 로그인 실패(동일 IP)", "saved_at": "2026-10-16 12:23:58"},
    {"id": 270, "user": "admin", "ip": "0.0.0.0", "decision": "거부", "severity": "Medium", "count": 0, "reason": "관리자 회원 삭제 1명(게시글 0개 포함)", "saved_at": "2026-10-15 14:30:29"},
    {"id": 269, "user": "ahleum", "ip": "203.0.113.30", "decision": "거부", "severity": "High", "count": 5, "reason": "브루트포스 자동 잠금: 5회 로그인 실패", "saved_at": "2026-10-15 14:06:31"},
    {"id": 268, "user": "lab", "ip": "203.0.113.30", "decision": "거부", "severity": "High", "count": 8, "reason": "브루트포스 자동 잠금: 8회 로그인 실패", "saved_at": "2026-10-15 11:11:22"},
    {"id": 267, "user": "lsy", "ip": "203.0.113.96", "decision": "거부", "severity": "High", "count": 5, "reason": "공격 출발지 자동 차단: 5회 로그인 실패(동일 IP)", "saved_at": "2026-10-15 09:58:38"},
    {"id": 266, "user": "lsy", "ip": "203.0.113.98", "decision": "거부", "severity": "High", "count": 5, "reason": "공격 출발지 자동 차단: 5회 로그인 실패(동일 IP)", "saved_at": "2026-10-15 09:54:08"},
]


def get_db():
    if "db" not in g:
        g.db = MySQLConnection(connect_mysql(app.config["MYSQL_DATABASE"]))
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    server = connect_mysql()
    server_cursor = MySQLCursor(server.cursor())
    server_cursor.execute(
        f"CREATE DATABASE IF NOT EXISTS `{app.config['MYSQL_DATABASE']}` "
        "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
    )
    server.commit()
    server.close()

    db = MySQLConnection(connect_mysql(app.config["MYSQL_DATABASE"]))
    for statement in (
        """
        CREATE TABLE IF NOT EXISTS users (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(255) NOT NULL UNIQUE,
            password_hash TEXT,
            created_at VARCHAR(32) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        """
        CREATE TABLE IF NOT EXISTS posts (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author VARCHAR(255) NOT NULL,
            created_at VARCHAR(32) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            event_type VARCHAR(128) NOT NULL,
            incident_id VARCHAR(64),
            api_key_id VARCHAR(255),
            client_ip VARCHAR(64),
            severity VARCHAR(32) NOT NULL DEFAULT '높음',
            status VARCHAR(32) NOT NULL DEFAULT '열림',
            decision VARCHAR(32),
            action VARCHAR(255),
            reason VARCHAR(255),
            event_timestamp VARCHAR(64) NOT NULL,
            created_at VARCHAR(64) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        """
        CREATE TABLE IF NOT EXISTS incident_tickets (
            id VARCHAR(64) PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            ip VARCHAR(64),
            api_key_id VARCHAR(255),
            scenario VARCHAR(128),
            event VARCHAR(128) NOT NULL,
            occurrence_count INT NOT NULL DEFAULT 1,
            action VARCHAR(255),
            status VARCHAR(32) NOT NULL DEFAULT '열림',
            severity VARCHAR(32) NOT NULL DEFAULT '높음',
            severity_class VARCHAR(32) NOT NULL DEFAULT 'high',
            created_at VARCHAR(64) NOT NULL,
            closed_at VARCHAR(64) NOT NULL DEFAULT '-'
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip VARCHAR(64) PRIMARY KEY,
            blocked_at VARCHAR(64) NOT NULL,
            incident_id VARCHAR(64),
            reason VARCHAR(255)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
    ):
        db.execute(statement)

    if db.execute("SHOW COLUMNS FROM users LIKE 'role'").fetchone() is None:
        db.execute("ALTER TABLE users ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'member'")

    admin_password_hash = generate_password_hash("1234")
    admin = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if admin is None:
        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", admin_password_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
    db.execute("UPDATE users SET role = 'admin' WHERE username = ?", ("admin",))
    post_count = db.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
    if post_count == 0:
        db.executemany(
            "INSERT INTO posts (title, content, author, created_at) VALUES (?, ?, ?, ?)",
            [
                (
                    "시나리오 3 API 키 탐지 테스트",
                    "비허용 IP에서 API 키를 사용했을 때 탐지와 자동 대응이 연결되는지 확인합니다.",
                    "관리자",
                    "2026-10-27",
                ),
                (
                    "보안 이벤트 확인 안내",
                    "Graylog와 n8n 연동 결과는 대시보드에서 확인할 수 있습니다.",
                    "관리자",
                    "2026-10-26",
                ),
            ],
        )

    db.commit()
    db.close()


init_db()
security_store.initialize()


@app.before_request
def load_current_user():
    g.current_user = None
    if request.endpoint == "static":
        return
    if session.get("user"):
        g.current_user = get_db().execute(
            "SELECT id, username, role FROM users WHERE username = ?", (session["user"],)
        ).fetchone()
        if g.current_user is None:
            session.clear()


@app.context_processor
def user_context():
    return {"current_user": g.get("current_user")}


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not g.current_user:
            flash("로그인 후 이용해 주세요.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped_view


@app.get("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("아이디와 비밀번호를 입력해 주세요.", "error")
            return render_template("login.html")

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user is None or not user["password_hash"] or not check_password_hash(user["password_hash"], password):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "error")
            return render_template("login.html")

        session.clear()
        session["user"] = user["username"]
        flash(f"{username}님, 환영합니다.", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    session.setdefault("register_csrf", secrets.token_urlsafe(32))
    username = ""
    errors = []
    status = 200
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not hmac.compare_digest(session["register_csrf"], token):
            abort(400, "요청이 만료되었습니다. 회원가입 화면을 새로 열어 주세요.")
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("password_confirm", "")
        if not re.fullmatch(r"[a-z0-9_]{3,32}", username):
            errors.append("아이디는 영문 소문자·숫자·밑줄로 3~32자 입력해 주세요.")
        if username == "admin":
            errors.append("사용할 수 없는 아이디입니다.")
        if not password:
            errors.append("비밀번호를 입력해 주세요.")
        if password != confirmation:
            errors.append("비밀번호 확인이 일치하지 않습니다.")
        if errors:
            status = 400
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password),
                     datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )
                db.commit()
            except pymysql.IntegrityError as error:
                db.rollback()
                if error.args[0] != 1062:
                    raise
                errors.append("이미 사용 중인 아이디입니다.")
                status = 409
            else:
                session.pop("register_csrf", None)
                flash("회원가입이 완료되었습니다. 로그인해 주세요.", "success")
                return redirect(url_for("login"), code=303)
    return render_template("register.html", username=username, errors=errors), status


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped_view(*args, **kwargs):
        if g.current_user["role"] != "admin":
            abort(403)
        if request.method == "POST":
            expected = session.get("admin_csrf", "")
            supplied = request.form.get("csrf_token", "")
            if not expected or not hmac.compare_digest(expected, supplied):
                abort(400, "요청이 만료되었습니다. 관리자 페이지를 새로 열어 주세요.")
        return view(*args, **kwargs)
    return wrapped_view


@app.after_request
def protect_admin_response(response):
    if request.path.startswith("/admin") or request.path in {"/login", "/register"}:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "same-origin"
    return response


@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    issued = None
    status = 200
    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "issue_key":
                issued = security_store.issue(
                    request.form.get("label", ""), request.form.get("allowed_ips", "")
                )
                # A repeated POST cannot accidentally issue another key.
                session["admin_csrf"] = secrets.token_urlsafe(32)
            elif action == "revoke_key":
                changed = security_store.revoke(request.form.get("api_key_id", ""))
                flash("키를 폐기했습니다." if changed else "이미 폐기되었거나 존재하지 않는 키입니다.", "success")
            elif action == "revoke_all_keys":
                targets = bulk_targets(request.form.get("targets", ""), "keys")
                changed = security_store.revoke_many(targets)
                flash(f"활성 키 {changed}개를 폐기했습니다.", "success")
            elif action == "unblock_ip":
                security_store.unblock(request.form.get("ip", "").strip())
                flash("IP 차단을 해제했습니다. 키 폐기와 허용 IP 설정은 별도로 유지됩니다.", "success")
            elif action == "change_role":
                role = request.form.get("role")
                if role not in {"member", "admin"}:
                    abort(400)
                try:
                    member_id = int(request.form.get("member_id", ""))
                except ValueError:
                    abort(400)
                db = get_db()
                member = db.execute("SELECT id, username FROM users WHERE id = ?", (member_id,)).fetchone()
                if member is None:
                    abort(404)
                if member["username"] == "admin" or member_id == g.current_user["id"]:
                    abort(400, "기본 관리자와 본인의 등급은 변경할 수 없습니다.")
                db.execute("UPDATE users SET role = ? WHERE id = ?", (role, member_id))
                db.commit()
                flash("회원 등급을 변경했습니다. 다음 요청부터 반영됩니다.", "success")
            else:
                abort(400)
        except ValueError as error:
            message = str(error) if action == "issue_key" and "IP" not in str(error) else "입력값을 확인해 주세요. IP 주소와 글자 수가 올바르지 않습니다."
            flash(message, "error")
            status = 400
        if issued is None and status == 200:
            args = {name: request.args[name] for name in ("members_page", "keys_page", "blocks_page", "key_status") if name in request.args}
            return redirect(url_for("admin", **args), code=303)
    session.setdefault("admin_csrf", secrets.token_urlsafe(32))
    key_status = request.args.get("key_status", "all")
    if key_status not in {"all", "revoked", "active"}:
        key_status = "all"
    key_page, keys = security_store.key_page(request.args.get("keys_page"), key_status)
    block_page, blocks = security_store.block_page(request.args.get("blocks_page"))
    db = get_db()
    member_page = Page.create(db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                              request.args.get("members_page"))
    members = db.execute(
        "SELECT id, username, role, created_at FROM users ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
        (member_page.size, member_page.offset),
    ).fetchall()
    active_ids = security_store.active_ids()
    return render_template("admin.html", keys=keys, blocks=blocks, issued=issued,
                           key_page=key_page, block_page=block_page,
                           members=members, member_page=member_page, key_status=key_status,
                           active_key_count=len(active_ids), key_bulk_token=bulk_token("keys", active_ids)), status


@app.errorhandler(pymysql.MySQLError)
def database_unavailable(error):
    app.logger.error("Database unavailable: %s", type(error).__name__)
    return "데이터베이스 연결을 확인해 주세요. 잠시 후 다시 시도해 주세요.", 503


@app.post("/api/security-events")
def receive_security_event():
    """Store a normalized event sent by the scenario 3 n8n workflow."""
    payload = request.get_json(silent=True) or {}
    event_type = str(payload.get("event_type", "")).strip().lower()
    if not event_type:
        return {"error": "event_type is required"}, 400

    now = datetime.now().isoformat(timespec="seconds")
    event = {
        "event_type": event_type,
        "incident_id": payload.get("incident_id"),
        "api_key_id": payload.get("api_key_id"),
        "client_ip": str(payload.get("client_ip") or "").strip() or None,
        "severity": payload.get("severity", "높음"),
        "status": payload.get("status", "열림"),
        "decision": payload.get("decision", "거부"),
        "action": payload.get("action", ""),
        "reason": payload.get("reason") or payload.get("detection_reason", ""),
        "event_timestamp": payload.get("timestamp") or now,
    }

    db = get_db()
    matching_ticket = None
    if event_type == "api_key_compromised":
        matching_ticket = db.execute(
            """
            SELECT id FROM incident_tickets
            WHERE event = ? AND ip = ? AND COALESCE(api_key_id, '') = COALESCE(?, '')
            ORDER BY created_at ASC LIMIT 1
            """,
            (event_type, event["client_ip"], event["api_key_id"]),
        ).fetchone()
        if matching_ticket:
            event["incident_id"] = matching_ticket["id"]
        else:
            supplied_id = str(event.get("incident_id") or "").strip()
            if re.fullmatch(r"INC-API-\d{3}", supplied_id):
                event["incident_id"] = supplied_id
            else:
                next_number = db.execute(
                    """
                    SELECT COALESCE(MAX(CAST(SUBSTR(id, 9) AS INTEGER)), 0) + 1
                    FROM incident_tickets WHERE id LIKE 'INC-API-%'
                    """
                ).fetchone()[0]
                event["incident_id"] = f"INC-API-{next_number:03d}"
    cursor = db.execute(
        """
        INSERT INTO security_events (
            event_type, incident_id, api_key_id, client_ip, severity,
            status, decision, action, reason, event_timestamp, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["event_type"], event["incident_id"], event["api_key_id"],
            event["client_ip"], event["severity"], event["status"],
            event["decision"], event["action"], event["reason"],
            event["event_timestamp"], now,
        ),
    )
    db.commit()
    event["id"] = cursor.lastrowid

    if event["decision"] == "거부" and event["client_ip"]:
        db.execute(
            """
            INSERT INTO blocked_ips (ip, blocked_at, incident_id, reason)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                blocked_at = VALUES(blocked_at),
                incident_id = VALUES(incident_id),
                reason = VALUES(reason)
            """,
            (
                event["client_ip"],
                event["event_timestamp"],
                event["incident_id"],
                event["reason"],
            ),
        )
        db.commit()

    if event["event_type"] == "api_key_compromised":
        incident_id = event["incident_id"]
        if matching_ticket is not None:
            db.execute(
                "UPDATE incident_tickets SET occurrence_count = occurrence_count + 1 WHERE id = ?",
                (incident_id,),
            )
        else:
            severity_class = {"높음": "high", "중간": "medium", "낮음": "low"}.get(
                event["severity"], "high"
            )
            db.execute(
                """
                INSERT INTO incident_tickets (
                    id, title, ip, api_key_id, scenario, event, occurrence_count,
                    action, status, severity, severity_class, created_at, closed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    "비허용 IP의 API 키 사용",
                    event["client_ip"],
                    event["api_key_id"],
                    "시나리오 3",
                    event["event_type"],
                    1,
                    event["action"],
                    event["status"],
                    event["severity"],
                    severity_class,
                    event["event_timestamp"],
                    now if event["status"] == "종료" else "-",
                ),
            )
            db.commit()

    return {"status": "stored", "event": event}, 201


@app.route("/board", methods=["GET", "POST"])
@login_required
def board():
    session.setdefault("board_csrf", secrets.token_urlsafe(32))
    title = ""
    content = ""
    compose_error = None
    if request.method == "POST":
        if not hmac.compare_digest(session["board_csrf"], request.form.get("csrf_token", "")):
            abort(400, "요청이 만료되었습니다. 게시판을 새로 열어 주세요.")
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content:
            compose_error = "제목과 내용을 모두 입력해 주세요."
        else:
            db = get_db()
            db.execute(
                """
                INSERT INTO posts (title, content, author, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    title,
                    content,
                    session.get("user", "방문자"),
                    datetime.now().strftime("%Y-%m-%d"),
                ),
            )
            db.commit()
            flash("게시글을 등록했습니다.", "success")
            return redirect(url_for("board"), code=303)

    posts = get_db().execute(
        "SELECT title, content, author, created_at AS date FROM posts ORDER BY id DESC"
    ).fetchall()
    return render_template("board.html", posts=posts, compose_error=compose_error,
                           draft_title=title, draft_content=content), 400 if compose_error else 200


@app.post("/dashboard/tickets")
@admin_required
def close_tickets():
    action = request.form.get("action")
    if action == "close_ticket":
        targets = [request.form.get("ticket_id", "")]
    elif action == "close_all_tickets":
        targets = bulk_targets(request.form.get("targets", ""), "tickets")
    else:
        abort(400)
    changed = 0
    if targets:
        placeholders = ",".join("?" for _ in targets)
        db = get_db()
        cursor = db.execute(
            "UPDATE incident_tickets SET status = ?, closed_at = ? WHERE status = ? AND id IN (" + placeholders + ")",
            ("종료", datetime.now(timezone(timedelta(hours=9))).isoformat(timespec="seconds"), "열림", *targets),
        )
        changed = cursor.rowcount
        db.commit()
    flash(f"티켓 {changed}건을 종료했습니다. IP 차단과 API 키 상태는 유지됩니다.", "success")
    args = {name: request.args[name] for name in ("tickets_page", "events_page", "ticket_status", "event_decision") if name in request.args}
    return redirect(url_for("dashboard", **args), code=303)


@app.get("/dashboard")
@login_required
def dashboard():
    db = get_db()
    open_ids = []
    if g.current_user["role"] == "admin":
        session.setdefault("admin_csrf", secrets.token_urlsafe(32))
        open_ids = [row["id"] for row in db.execute("SELECT id FROM incident_tickets WHERE status = ?", ("열림",)).fetchall()]
    total_events = db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    warning_events = db.execute(
        "SELECT COUNT(*) FROM security_events WHERE decision = ?", ("거부",)
    ).fetchone()[0]
    completed_tickets = db.execute(
        "SELECT COUNT(*) FROM incident_tickets WHERE status = ?", ("종료",)
    ).fetchone()[0]
    blocked_ips = db.execute(
        "SELECT COUNT(*) FROM blocked_ips",
    ).fetchone()[0]

    top_ip_rows = db.execute(
        """
        SELECT client_ip AS ip, COUNT(*) AS count
        FROM security_events
        WHERE decision = ? AND client_ip IS NOT NULL AND client_ip <> ''
        GROUP BY client_ip
        ORDER BY count DESC
        LIMIT 3
        """,
        ("거부",),
    ).fetchall()
    top_ips = [dict(row) for row in top_ip_rows]

    ticket_status = request.args.get("ticket_status", "all")
    if ticket_status not in {"all", "open", "closed"}:
        ticket_status = "all"
    event_decision = request.args.get("event_decision", "all")
    if event_decision not in {"all", "denied", "allowed"}:
        event_decision = "all"
    ticket_where = " WHERE status = ?" if ticket_status != "all" else ""
    ticket_params = ({"open": "열림", "closed": "종료"}[ticket_status],) if ticket_where else ()
    event_where = " WHERE decision = ?" if event_decision != "all" else ""
    event_params = ({"denied": "거부", "allowed": "허용"}[event_decision],) if event_where else ()
    ticket_page = Page.create(db.execute("SELECT COUNT(*) FROM incident_tickets" + ticket_where, ticket_params).fetchone()[0],
                              request.args.get("tickets_page"))
    event_page = Page.create(db.execute("SELECT COUNT(*) FROM security_events" + event_where, event_params).fetchone()[0],
                             request.args.get("events_page"))
    ticket_rows = db.execute(
        "SELECT * FROM incident_tickets" + ticket_where + " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
        ticket_params + (ticket_page.size, ticket_page.offset),
    ).fetchall()
    tickets = [dict(row) for row in ticket_rows]

    event_rows = db.execute(
        """
        SELECT id, event_type, api_key_id, client_ip, decision, severity, reason,
               event_timestamp
        FROM security_events
        """ + event_where + " ORDER BY id DESC LIMIT ? OFFSET ?",
        event_params + (event_page.size, event_page.offset),
    ).fetchall()
    scenario_names = {
        "api_key_compromised": "시나리오 3 · API 키 유출 탐지",
        "authentication_failed": "인증 실패 탐지",
        "queue_lag": "로그 버퍼링 지연",
    }
    recent_events = [
        {
            "id": row["id"],
            "scenario": scenario_names.get(
                (row["event_type"] or "").lower(), row["event_type"] or "-"
            ),
            "ip": row["client_ip"] or "-",
            "decision": row["decision"] or "-",
            "severity": row["severity"],
            "reason": row["reason"] or "-",
            "saved_at": row["event_timestamp"],
        }
        for row in event_rows
    ]

    return render_template(
        "dashboard.html",
        tickets=tickets,
        ticket_page=ticket_page,
        event_page=event_page,
        ticket_status=ticket_status,
        event_decision=event_decision,
        total_events=total_events,
        warning_events=warning_events,
        completed_tickets=completed_tickets,
        blocked_ips=blocked_ips,
        top_ips=top_ips,
        top_ip_max=top_ips[0]["count"] if top_ips else 1,
        recent_events=recent_events,
        open_ticket_count=len(open_ids),
        ticket_bulk_token=bulk_token("tickets", open_ids),
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
