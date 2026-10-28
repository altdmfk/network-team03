"""Run once before replacing the legacy API process; never reactivates keys."""

import json
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import urlopen

from security_store import SecurityStore, key_hash, timestamp


def migrate():
    store = SecurityStore()
    store.initialize()
    key_id, raw = "key-001", "test-key-01"
    for _ in range(30):
        try:
            with urlopen("http://127.0.0.1:5000/api/key/status?" + urlencode({"api_key_id": key_id}), timeout=3) as response:
                record = json.load(response)
        except HTTPError as error:
            if error.code == 404:
                return
            raise
        with store.connect() as connection, connection.cursor() as cursor:
            now = timestamp()
            cursor.execute(
                "INSERT IGNORE INTO api_keys "
                "(api_key_id,key_hash,label,status,allowed_ips,created_at,revoked_at,revoked_reason) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (key_id, key_hash(raw), "기존 테스트 키", record["status"],
                 json.dumps(record["allowed_ips"]), now,
                 now if record["status"] == "revoked" else None,
                 "legacy_migration" if record["status"] == "revoked" else None),
            )
        print(f"Preserved {key_id}: {record['status']}")
        key_id += "-renewed"
        raw += "-renewed"
    raise RuntimeError("Legacy key chain exceeds migration limit")


if __name__ == "__main__":
    migrate()
