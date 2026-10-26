# controllers/seclog.py
import os, re
from datetime import datetime
from flask import current_app

_UNSAFE = re.compile(r'[\s\x00-\x1f\x7f]+')   # 공백·개행·제어문자

def _clean(value, limit=64):
  text = _UNSAFE.sub('_', str(value or '-'))
  return text[:limit] or '-'

def write_seclog(event, user, src_ip):
  """event: login_failed | login_success | login_locked"""
  path = current_app.config.get('SECURITY_LOG_PATH')
  if not path:
    return
  first_hop = str(src_ip or '').split(',')[0].strip()      # X-Forwarded-For 첫 홉만
  now = datetime.now()
  stamp = now.strftime('%Y-%m-%d %H:%M:%S.') + f'{now.microsecond // 1000:03d}'   # ★ 밀리초 필수
  line = f'{stamp} {event} user={_clean(user)} src_ip={_clean(first_hop, 45)}\n'
  try:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a', encoding='utf-8') as f:
      f.write(line)
  except OSError:
    pass   # 로그 파일 문제로 로그인이 멈추면 안 된다


def write_404log(src_ip, path):
  """HTTP 404 발생 기록 — Wazuh 탐지용(웹 스캐너 404 폭주)."""
  log_path = current_app.config.get('SECURITY_LOG_PATH')
  if not log_path:
    return
  first_hop = str(src_ip or '').split(',')[0].strip()
  now = datetime.now()
  stamp = now.strftime('%Y-%m-%d %H:%M:%S.') + f'{now.microsecond // 1000:03d}'
  line = f'{stamp} http_404 src_ip={_clean(first_hop, 45)} path={_clean(path, 120)}\n'
  try:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, 'a', encoding='utf-8') as f:
      f.write(line)
  except OSError:
    pass


def write_honeytoken_log(token_id, user, src_ip):
  """시나리오1: 미끼(허니토큰) 사용 기록 — Wazuh 커스텀 룰이 이 줄을 1회만 봐도 CRITICAL."""
  path = current_app.config.get('SECURITY_LOG_PATH')
  if not path:
    return
  first_hop = str(src_ip or '').split(',')[0].strip()
  now = datetime.now()
  stamp = now.strftime('%Y-%m-%d %H:%M:%S.') + f'{now.microsecond // 1000:03d}'
  line = f'{stamp} honeytoken_used token_id={_clean(token_id, 20)} user={_clean(user)} src_ip={_clean(first_hop, 45)}\n'
  try:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a', encoding='utf-8') as f:
      f.write(line)
  except OSError:
    pass