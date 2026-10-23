from datetime import datetime

from extensions import db


class Honeytoken(db.Model):
    """허니토큰(미끼) 목록. 정상 사용자는 절대 쓰지 않으니, 쓰이면 그 자체가 침입 증거."""
    __tablename__ = 'honeytokens'
    token_id = db.Column(db.String(20), primary_key=True)                # 예: HT-001
    token_type = db.Column(db.String(20), nullable=False)                # account | api_key
    token_value = db.Column(db.String(100), unique=True, nullable=False) # 미끼 계정명 또는 가짜 키
    placement = db.Column(db.String(50))                                 # 심은 위치: users_table 등
    status = db.Column(db.String(10), nullable=False, default='active')  # active | used | revoked
    created_at = db.Column(db.DateTime, default=datetime.now)
    used_at = db.Column(db.DateTime)                                     # 처음 사용된 시각
    used_by_ip = db.Column(db.String(45))                                # 사용한 IP