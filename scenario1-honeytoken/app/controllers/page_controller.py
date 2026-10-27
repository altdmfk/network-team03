"""화면(HTML) 라우트만 모음. 데이터는 각 페이지의 JS 가 API 로 가져온다."""
from flask import Blueprint, render_template

page_bp = Blueprint('page', __name__)


@page_bp.route('/')
def index():
    return render_template('index.html')


@page_bp.route('/dashboard')
def dashboard():
    """보안 이벤트 대시보드 (n8n 이 저장한 허용/거부 기록)."""
    return render_template('dashboard.html')


@page_bp.route('/admin')
def admin_page():
    """관리자 페이지 — 페이지 자체는 누구에게나 내려주고, 데이터는 /api/admin/* (서버)가 막는다.
    시나리오1: 회수되지 않은 가짜 관리자 키가 있으면 페이지 소스에 운영 메모처럼 숨겨 둔다(미끼)."""
    from models import Honeytoken

    decoy = (Honeytoken.query
             .filter(Honeytoken.token_type == 'api_key', Honeytoken.placement == 'admin_console',
                     Honeytoken.status != 'revoked')
             .order_by(Honeytoken.token_id).first())
    return render_template('admin.html', decoy_key=decoy.token_value if decoy else None)


@page_bp.route('/honeytoken')
def honeytoken_page():
    """시나리오1 허니토큰 관제 화면 — 페이지는 누구에게나, 데이터는 /api/admin/honeytokens/overview(관리자)가 막는다."""
    return render_template('honeytoken.html')


@page_bp.route('/gold')
def gold_page():
    """골드 전용 페이지 — 페이지는 항상 렌더, 데이터는 /api/gold/posts (서버)가 막는다."""
    return render_template('gold.html')
