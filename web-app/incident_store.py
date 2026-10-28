"""Durable incident identity shared by the API and dashboard receiver."""

import hashlib
import json
import re


class IncidentConflict(Exception):
    pass


def initialize_incidents(cursor):
    cursor.execute("""CREATE TABLE IF NOT EXISTS incident_registry (
        incident_id VARCHAR(64) PRIMARY KEY,
        fingerprint CHAR(64) NOT NULL UNIQUE,
        event_type VARCHAR(128) NOT NULL,
        client_ip VARCHAR(64) NOT NULL,
        api_key_id VARCHAR(255) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS incident_counters (
        name VARCHAR(32) PRIMARY KEY, last_number BIGINT NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
    cursor.execute("""SELECT COALESCE(MAX(number),0) AS last_number FROM (
        SELECT CAST(SUBSTRING(id,9) AS UNSIGNED) AS number FROM incident_tickets WHERE id REGEXP '^INC-API-[0-9]+$'
        UNION ALL SELECT CAST(SUBSTRING(incident_id,9) AS UNSIGNED) FROM incident_registry WHERE incident_id REGEXP '^INC-API-[0-9]+$'
        UNION ALL SELECT CAST(SUBSTRING(incident_id,9) AS UNSIGNED) FROM security_events WHERE incident_id REGEXP '^INC-API-[0-9]+$'
    ) historical_numbers""")
    maximum = cursor.fetchone()["last_number"]
    cursor.execute("INSERT INTO incident_counters (name,last_number) VALUES ('api',%s) "
                   "ON DUPLICATE KEY UPDATE last_number=GREATEST(last_number,VALUES(last_number))", (maximum,))


def assign_incident(cursor, event_type, ip, key_id, supplied=None):
    """Caller holds a transaction; all allocations use one persistent row lock."""
    event_type, ip, key_id = event_type.lower(), ip or "", key_id or ""
    fingerprint = hashlib.sha256(json.dumps([event_type, ip, key_id], ensure_ascii=False).encode()).hexdigest()
    cursor.execute("SELECT last_number FROM incident_counters WHERE name='api' FOR UPDATE")
    number = int(cursor.fetchone()["last_number"])
    cursor.execute("SELECT incident_id FROM incident_registry WHERE fingerprint=%s", (fingerprint,))
    registered = cursor.fetchone()
    supplied = str(supplied or "").strip()
    if supplied and not re.fullmatch(r"INC-API-\d{3,}", supplied):
        raise IncidentConflict("인시던트 ID 형식이 올바르지 않습니다.")
    if registered:
        if supplied and supplied != registered["incident_id"]:
            raise IncidentConflict("같은 탐지 대상에 서로 다른 인시던트 ID가 전달됐습니다.")
        return registered["incident_id"]
    cursor.execute("SELECT id FROM incident_tickets WHERE event=%s AND COALESCE(ip,'')=%s "
                   "AND COALESCE(api_key_id,'')=%s ORDER BY created_at,id LIMIT 1", (event_type, ip, key_id))
    existing = cursor.fetchone()
    if existing and supplied and existing["id"] != supplied:
        raise IncidentConflict("기존 티켓과 전달된 인시던트 ID가 일치하지 않습니다.")
    identifier = existing["id"] if existing else supplied or f"INC-API-{number + 1:03d}"
    cursor.execute("SELECT event,ip,api_key_id FROM incident_tickets WHERE id=%s", (identifier,))
    owner = cursor.fetchone()
    if owner and [owner["event"].lower(), owner["ip"] or "", owner["api_key_id"] or ""] != [event_type, ip, key_id]:
        raise IncidentConflict("이 인시던트 ID는 다른 키 또는 IP의 티켓에서 사용 중입니다.")
    cursor.execute("SELECT fingerprint FROM incident_registry WHERE incident_id=%s", (identifier,))
    owner = cursor.fetchone()
    if owner and owner["fingerprint"] != fingerprint:
        raise IncidentConflict("이 인시던트 ID는 다른 탐지 대상에서 사용 중입니다.")
    if re.fullmatch(r"INC-API-\d{3,}", identifier):
        cursor.execute("UPDATE incident_counters SET last_number=GREATEST(last_number,%s) WHERE name='api'", (int(identifier[8:]),))
    cursor.execute("INSERT INTO incident_registry (incident_id,fingerprint,event_type,client_ip,api_key_id) VALUES (%s,%s,%s,%s,%s)",
                   (identifier, fingerprint, event_type, ip, key_id))
    return identifier
