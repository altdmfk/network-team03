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

    def to_dict(self):
        """관리 콘솔용. 가짜 관리자 키는 콘솔 화면에서도 앞부분만 보여준다(화면 캡처로 새지 않게)."""
        value = self.token_value
        if self.token_type == 'api_key' and value:
            value = value[:6] + '…'
        return {
            'token_id': self.token_id,
            'token_type': self.token_type,
            'token_value': value,
            'placement': self.placement,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'used_at': self.used_at.isoformat() if self.used_at else None,
            'used_by_ip': self.used_by_ip,
        }
