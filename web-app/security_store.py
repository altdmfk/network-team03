"""Shared MySQL security state for the API and the administrator screen."""

import hashlib
import ipaddress
import json
import os
import secrets
from datetime import datetime, timezone
from uuid import uuid4

import pymysql
from pymysql.cursors import DictCursor
from pagination import Page


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_ips(value):
    values = value.replace(",", " ").split() if isinstance(value, str) else value
    addresses = sorted({str(ipaddress.ip_address(ip)) for ip in values})
    if not addresses:
        raise ValueError("허용 IP를 하나 이상 입력해 주세요.")
    return addresses


def key_hash(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class SecurityStore:
    def connect(self):
        return pymysql.connect(
            host=os.getenv("ENGINESQUARE_DB_HOST", "127.0.0.1"),
            port=int(os.getenv("ENGINESQUARE_DB_PORT", "3306")),
            user=os.getenv("ENGINESQUARE_DB_USER", "root"),
            password=os.getenv("ENGINESQUARE_DB_PASSWORD", "123456"),
            database=os.getenv("ENGINESQUARE_DB_NAME", "enginesquare"),
            charset="utf8mb4", cursorclass=DictCursor,
            autocommit=True, connect_timeout=2, read_timeout=2, write_timeout=2,
        )

    def initialize(self):
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    api_key_id VARCHAR(255) PRIMARY KEY,
                    key_hash CHAR(64) NOT NULL UNIQUE,
                    label VARCHAR(100) NOT NULL,
                    status VARCHAR(16) NOT NULL DEFAULT 'active',
                    allowed_ips TEXT NOT NULL,
                    created_at VARCHAR(64) NOT NULL,
                    revoked_at VARCHAR(64),
                    revoked_reason VARCHAR(255)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)

    def _record(self, row):
        if row:
            row.pop("key_hash", None)
            row["allowed_ips"] = json.loads(row["allowed_ips"])
        return row

    def find(self, raw):
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT * FROM api_keys WHERE key_hash = %s", (key_hash(raw),))
            return self._record(cursor.fetchone())

    def find_by_id(self, key_id):
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT * FROM api_keys WHERE api_key_id = %s", (key_id,))
            return self._record(cursor.fetchone())

    def keys(self):
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT * FROM api_keys ORDER BY created_at DESC, api_key_id")
            return [self._record(row) for row in cursor.fetchall()]

    def key_page(self, requested, status="all"):
        where = " WHERE status = %s" if status in {"active", "revoked"} else ""
        params = (status,) if where else ()
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM api_keys" + where, params)
            page = Page.create(cursor.fetchone()["total"], requested)
            cursor.execute("SELECT * FROM api_keys" + where + " ORDER BY created_at DESC, api_key_id LIMIT %s OFFSET %s",
                           params + (page.size, page.offset))
            return page, [self._record(row) for row in cursor.fetchall()]

    def issue(self, label, allowed_ips):
        label = label.strip()
        if not label or len(label) > 100:
            raise ValueError("키 이름은 1~100자로 입력해 주세요.")
        ips = normalize_ips(allowed_ips)
        raw = "es_" + secrets.token_urlsafe(32)
        key_id = "key-" + uuid4().hex
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO api_keys (api_key_id, key_hash, label, allowed_ips, created_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (key_id, key_hash(raw), label, json.dumps(ips), timestamp()),
            )
        return {"api_key_id": key_id, "new_api_key": raw}

    def revoke(self, key_id, reason="administrator"):
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE api_keys SET status = 'revoked', revoked_at = %s, revoked_reason = %s "
                "WHERE api_key_id = %s AND status = 'active'",
                (timestamp(), reason, key_id),
            )
            return cursor.rowcount == 1

    def active_ids(self):
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT api_key_id FROM api_keys WHERE status = 'active'")
            return [row["api_key_id"] for row in cursor.fetchall()]

    def revoke_many(self, identifiers):
        if not identifiers:
            return 0
        placeholders = ",".join("%s" for _ in identifiers)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("UPDATE api_keys SET status='revoked', revoked_at=%s, revoked_reason=%s "
                           "WHERE status='active' AND api_key_id IN (" + placeholders + ")",
                           (timestamp(), "administrator_bulk", *identifiers))
            return cursor.rowcount

    def blocks(self):
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC, ip")
            return cursor.fetchall()

    def block_page(self, requested):
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM blocked_ips")
            page = Page.create(cursor.fetchone()["total"], requested)
            cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC, ip LIMIT %s OFFSET %s",
                           (page.size, page.offset))
            return page, cursor.fetchall()

    def is_blocked(self, ip):
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM blocked_ips WHERE ip = %s", (ip,))
            return cursor.fetchone() is not None

    def block(self, ip, reason, incident_id=None):
        ip = str(ipaddress.ip_address(ip))
        if len(reason) > 255:
            raise ValueError("차단 사유는 255자 이내로 입력해 주세요.")
        with self.connect() as connection, connection.cursor() as cursor:
            self._block(cursor, ip, reason, incident_id)

    def _block(self, cursor, ip, reason, incident_id):
        cursor.execute(
            "INSERT INTO blocked_ips (ip, blocked_at, incident_id, reason) VALUES (%s,%s,%s,%s) "
            "ON DUPLICATE KEY UPDATE blocked_at=VALUES(blocked_at), "
            "incident_id=VALUES(incident_id), reason=VALUES(reason)",
            (ip, timestamp(), incident_id, reason),
        )

    def unblock(self, ip):
        ip = str(ipaddress.ip_address(ip))
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("DELETE FROM blocked_ips WHERE ip = %s", (ip,))
            return cursor.rowcount == 1

    def respond(self, key_id, reason, ip, incident_id):
        """Persist key revocation, replacement and IP block in one transaction."""
        block_ip = ip not in {"unknown", "127.0.0.1"}
        if block_ip:
            ip = str(ipaddress.ip_address(ip))
        with self.connect() as connection, connection.cursor() as cursor:
            connection.begin()
            try:
                cursor.execute("SELECT * FROM api_keys WHERE api_key_id = %s FOR UPDATE", (key_id,))
                record = cursor.fetchone()
                if record is None:
                    connection.rollback()
                    return None
                cursor.execute(
                    "UPDATE api_keys SET status='revoked', revoked_at=COALESCE(revoked_at,%s), "
                    "revoked_reason=%s WHERE api_key_id=%s", (timestamp(), reason, key_id),
                )
                raw = None
                replacement_id = None
                # Repeated detections must not mint additional replacement keys.
                if record["status"] == "active":
                    raw = "es_" + secrets.token_urlsafe(32)
                    replacement_id = "key-" + uuid4().hex
                    cursor.execute(
                        "INSERT INTO api_keys (api_key_id,key_hash,label,allowed_ips,created_at) "
                        "VALUES (%s,%s,%s,%s,%s)",
                        (replacement_id, key_hash(raw), record["label"], record["allowed_ips"], timestamp()),
                    )
                if block_ip:
                    self._block(cursor, ip, reason, incident_id)
                connection.commit()
                return {"key_revoked": True, "new_api_key_id": replacement_id,
                        "new_api_key": raw, "ip_blocked": block_ip}
            except Exception:
                connection.rollback()
                raise
