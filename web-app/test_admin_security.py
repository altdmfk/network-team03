"""Integration checks against local MySQL; only unique test rows are removed."""

import importlib.util
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor
from tempfile import TemporaryDirectory

from security_store import SecurityStore
from pagination import Page
from werkzeug.security import check_password_hash
import pymysql
from incident_store import initialize_incidents


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parent.parent
api = load("tested_api", ROOT / "app.py")
web = load("tested_web", ROOT / "web-app" / "app.py")


class AdminSecurityTest(unittest.TestCase):
    def setUp(self):
        self.store = SecurityStore()
        self.label = "integration-" + uuid4().hex
        self.member = "member_" + uuid4().hex[:16]
        with self.store.connect() as connection, connection.cursor() as cursor:
            cursor.execute("INSERT INTO users (username,password_hash,created_at) VALUES (%s,%s,%s)",
                           (self.member, "test-session-only", "2026-10-28 00:00:00"))
        self.ip = "192.0.2.234"
        self.assertFalse(self.store.is_blocked(self.ip), "Refusing to overwrite existing block")
        self.client = web.app.test_client()
        self.api = api.app.test_client()
        self.logs = patch.object(api, "write_security_log")
        self.logs.start()
        original_respond = api.security_store.respond
        isolated_response = patch.object(api.security_store, "respond", side_effect=lambda key, reason, ip, incident:
                                         original_respond(key, reason, ip, incident or "INC-API-TEST"))
        isolated_response.start()
        self.addCleanup(isolated_response.stop)

    def tearDown(self):
        self.logs.stop()
        with self.store.connect() as connection, connection.cursor() as cursor:
            cursor.execute("DELETE FROM api_keys WHERE label = %s", (self.label,))
            cursor.execute("DELETE FROM blocked_ips WHERE ip = %s AND reason = %s", (self.ip, self.label))
            cursor.execute("DELETE FROM users WHERE username = %s", (self.member,))
            cursor.execute("DELETE FROM security_events WHERE api_key_id = %s", (self.label,))
            cursor.execute("DELETE FROM incident_tickets WHERE api_key_id = %s", (self.label,))

    def login_admin(self):
        with self.client.session_transaction() as session:
            session["user"] = "admin"
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as session:
            return session["admin_csrf"]

    def post(self, action, **fields):
        with self.client.session_transaction() as session:
            token = session["admin_csrf"]
        return self.client.post("/admin", data={"action": action, "csrf_token": token, **fields})

    def test_admin_access_and_csrf(self):
        self.assertEqual(self.client.get("/admin").status_code, 302)
        with self.client.session_transaction() as session:
            session["user"] = self.member
        self.assertEqual(self.client.get("/admin").status_code, 403)
        self.assertEqual(self.client.post("/admin", data={"action": "issue_key"}).status_code, 403)
        self.login_admin()
        self.assertEqual(self.client.post("/admin", data={"action": "issue_key"}).status_code, 400)
        self.assertEqual(self.post("block_ip", ip=self.ip, reason=self.label).status_code, 400)
        self.assertFalse(self.store.is_blocked(self.ip))
        self.assertEqual(self.post("issue_key", label=self.label, allowed_ips="invalid").status_code, 400)

    def test_independent_pages_and_out_of_range_pages(self):
        self.login_admin()
        with patch.object(web, "render_template", wraps=web.render_template) as render:
            response = self.client.get("/admin?keys_page=2&blocks_page=1")
            self.assertEqual(response.status_code, 200)
            context = render.call_args.kwargs
            self.assertLessEqual(len(context["keys"]), 5)
            self.assertLessEqual(len(context["blocks"]), 5)
            self.assertLessEqual(len(context["members"]), 5)
            self.assertEqual(context["block_page"].number, 1)
            self.assertEqual(context["key_page"].number, min(2, context["key_page"].pages))
            if context["key_page"].pages > 1:
                self.assertIn("blocks_page=1", response.text)
            response = self.client.get("/dashboard?tickets_page=-1&events_page=999999")
            self.assertEqual(response.status_code, 200)
            context = render.call_args.kwargs
            self.assertLessEqual(len(context["tickets"]), 5)
            self.assertLessEqual(len(context["recent_events"]), 5)
            self.assertEqual(context["ticket_page"].number, 1)
            self.assertEqual(context["event_page"].number, context["event_page"].pages)

    def test_key_status_filter_and_pagination(self):
        self.store.issue(self.label, self.ip)
        revoked = self.store.issue(self.label, self.ip)
        self.store.revoke(revoked["api_key_id"])
        self.login_admin()
        all_keys = self.store.keys()
        with patch.object(web, "render_template", wraps=web.render_template) as render:
            for value in ("all", "revoked", "active"):
                response = self.client.get("/admin", query_string={"key_status": value, "keys_page": 999,
                                                                  "members_page": 1, "blocks_page": 2})
                self.assertEqual(response.status_code, 200)
                context = render.call_args.kwargs
                expected = [key for key in all_keys if value == "all" or key["status"] == value]
                self.assertEqual(context["key_status"], value)
                self.assertEqual(context["key_page"].total, len(expected))
                self.assertEqual(context["key_page"].number, context["key_page"].pages)
                self.assertTrue(all(value == "all" or key["status"] == value for key in context["keys"]))
                self.assertLessEqual(len(context["keys"]), 5)
                self.assertIn('class="selected" aria-current="true"', response.text)
                self.assertRegex(response.text, r'href="[^"]*keys_page=1[^"]*key_status=active')
                if context["key_page"].pages > 1:
                    self.assertIn("key_status=" + value, response.text)
            self.client.get("/admin?key_status=invalid")
            self.assertEqual(render.call_args.kwargs["key_status"], "all")

    def test_dashboard_status_filters(self):
        with self.store.connect() as connection, connection.cursor() as cursor:
            for index, (state, decision) in enumerate((("열림", "거부"), ("종료", "허용"))):
                cursor.execute("INSERT INTO incident_tickets (id,title,api_key_id,event,status,created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                               (self.label + str(index), "Filter test", self.label, "api_key_compromised", state, "2099-01-01"))
                cursor.execute("INSERT INTO security_events (event_type,api_key_id,decision,reason,event_timestamp,created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                               ("api_request_allowed" if decision == "허용" else "api_key_compromised", self.label, decision, self.label, "2099-01-01", "2099-01-01"))
        self.login_admin()
        with patch.object(web, "render_template", wraps=web.render_template) as render:
            for state in ("all", "open", "closed"):
                for decision in ("all", "denied", "allowed"):
                    response = self.client.get("/dashboard", query_string={"ticket_status": state, "event_decision": decision,
                                                                          "tickets_page": 999, "events_page": 999})
                    self.assertEqual(response.status_code, 200)
                    context = render.call_args.kwargs
                    self.assertEqual(context["ticket_status"], state)
                    self.assertEqual(context["event_decision"], decision)
                    self.assertTrue(all(state == "all" or ticket["status"] == {"open": "열림", "closed": "종료"}[state]
                                        for ticket in context["tickets"]))
                    self.assertTrue(all(decision == "all" or event["decision"] == {"denied": "거부", "allowed": "허용"}[decision]
                                        for event in context["recent_events"]))
                    if decision == "allowed":
                        self.assertIn('decision allow', response.text)
                    self.assertEqual(context["ticket_page"].number, context["ticket_page"].pages)
                    self.assertEqual(context["event_page"].number, context["event_page"].pages)
                    self.assertIn("ticket_status=" + state, response.text)
                    self.assertIn("event_decision=" + decision, response.text)
            self.client.get("/dashboard?ticket_status=invalid&event_decision=invalid")
            self.assertEqual(render.call_args.kwargs["ticket_status"], "all")
            self.assertEqual(render.call_args.kwargs["event_decision"], "all")

    def test_issue_block_unblock_revoke_and_persistence(self):
        old_token = self.login_admin()
        response = self.post("issue_key", label=self.label, allowed_ips=self.ip)
        self.assertEqual(response.status_code, 200)
        raw = re.search(r'id="new-key"[^>]*value="([^"]+)"', response.text).group(1)
        record = SecurityStore().find(raw)
        self.assertEqual(record["status"], "active")
        self.assertNotIn("key_hash", record)
        with self.store.connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT key_hash FROM api_keys WHERE api_key_id=%s", (record["api_key_id"],))
            self.assertNotEqual(cursor.fetchone()["key_hash"], raw)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertNotIn(raw, self.client.get("/admin").text)
        duplicate = self.client.post("/admin", data={"action": "issue_key", "csrf_token": old_token,
                                    "label": self.label, "allowed_ips": self.ip})
        self.assertEqual(duplicate.status_code, 400)
        headers = {"X-API-Key": raw, "X-Demo-Client-IP": self.ip}
        self.assertEqual(self.api.get("/api/data", headers=headers).status_code, 200)
        denied = self.api.get("/api/data", headers={**headers, "X-Demo-Client-IP": "192.0.2.235"})
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.get_json()["message"], "Client IP is not allowed")
        self.store.block(self.ip, self.label)
        self.assertEqual(self.api.get("/api/data", headers=headers).status_code, 403)
        self.assertEqual(self.post("unblock_ip", ip=self.ip).status_code, 303)
        self.assertEqual(self.api.get("/api/data", headers=headers).status_code, 200)
        self.store.block(self.ip, self.label)
        self.store.unblock(self.ip)  # Direct DB deletion must also take effect immediately.
        self.assertEqual(self.api.get("/api/data", headers=headers).status_code, 200)
        self.post("revoke_key", api_key_id=record["api_key_id"])
        self.assertEqual(self.api.get("/api/data", headers=headers).status_code, 401)
        self.assertEqual(SecurityStore().find(raw)["status"], "revoked")
        fresh_api = load("fresh_api", ROOT / "app.py")
        with patch.object(fresh_api, "write_security_log"):
            self.assertEqual(fresh_api.app.test_client().get("/api/data", headers=headers).status_code, 401)

    def test_automation_revokes_in_database_without_duplicate_replacement(self):
        issued = self.store.issue(self.label, self.ip)
        payload = {"api_key_id": issued["api_key_id"], "client_ip": self.ip, "detection_reason": self.label}
        response = self.api.post("/automation/revoke-key", json=payload)
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertTrue(result["ip_blocked"])
        self.assertEqual(self.store.find(issued["new_api_key"])["status"], "revoked")
        self.assertEqual(self.store.find(result["new_api_key"])["status"], "active")
        again = self.api.post("/automation/revoke-key", json=payload).get_json()
        self.assertIsNone(again["new_api_key"])
        self.assertEqual(len([key for key in self.store.keys() if key["label"] == self.label]), 2)

    def test_replacement_secret_is_encrypted_and_claimed_once(self):
        original = self.store.issue(self.label, self.ip)
        result = self.store.respond(original["api_key_id"], "not_allowed_ip", "unknown", "INC-API-TEST")
        replacement_id = result["new_api_key_id"]
        record = self.store.find_by_id(replacement_id)
        self.assertEqual(record["replaced_from"], original["api_key_id"])
        self.assertTrue(record["can_claim"])
        self.assertNotIn("delivery_token", record)
        with self.store.connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT delivery_token FROM api_keys WHERE api_key_id=%s", (replacement_id,))
            encrypted = cursor.fetchone()["delivery_token"]
            self.assertNotIn(result["new_api_key"], encrypted)
        with ThreadPoolExecutor(max_workers=2) as pool:
            claimed = list(pool.map(lambda _: SecurityStore().claim_replacement(replacement_id), range(2)))
        self.assertEqual(sum(item is not None for item in claimed), 1)
        self.assertEqual(next(item for item in claimed if item)["new_api_key"], result["new_api_key"])
        self.assertFalse(self.store.find_by_id(replacement_id)["can_claim"])

    def test_admin_can_claim_or_replace_but_member_cannot(self):
        original = self.store.issue(self.label, self.ip)
        result = self.store.respond(original["api_key_id"], "not_allowed_ip", "unknown", "INC-API-TEST")
        replacement_id = result["new_api_key_id"]
        with self.client.session_transaction() as session:
            session["user"] = self.member
            session["admin_csrf"] = "test-token"
        self.assertEqual(self.post("claim_key", api_key_id=replacement_id).status_code, 403)
        self.login_admin()
        claimed = self.post("claim_key", api_key_id=replacement_id)
        self.assertEqual(claimed.status_code, 200)
        self.assertIn(result["new_api_key"], claimed.text)
        self.assertEqual(claimed.headers["Cache-Control"], "no-store")
        self.assertNotIn(result["new_api_key"], self.client.get("/admin").text)
        replaced = self.post("replace_key", api_key_id=replacement_id)
        self.assertEqual(replaced.status_code, 200)
        raw = re.search(r'id="new-key"[^>]*value="([^"]+)"', replaced.text).group(1)
        self.assertEqual(self.store.find_by_id(replacement_id)["status"], "revoked")
        self.assertEqual(self.store.find(raw)["replaced_from"], replacement_id)

    def test_revoked_pending_key_cannot_be_claimed(self):
        original = self.store.issue(self.label, self.ip)
        result = self.store.respond(original["api_key_id"], "not_allowed_ip", "unknown", "INC-API-TEST")
        self.store.revoke(result["new_api_key_id"])
        self.assertIsNone(self.store.claim_replacement(result["new_api_key_id"]))


class RegistrationTest(unittest.TestCase):
    def setUp(self):
        self.username = "signup_" + uuid4().hex[:16]
        self.password = "Signup-test-2026!"
        self.client = web.app.test_client()
        self.client.get("/register")
        with self.client.session_transaction() as session:
            self.token = session["register_csrf"]

    def tearDown(self):
        with SecurityStore().connect() as connection, connection.cursor() as cursor:
            cursor.execute("DELETE FROM users WHERE username = %s", (self.username,))

    def submit(self, **changes):
        data = {"username": self.username, "password": self.password,
                "password_confirm": self.password, "csrf_token": self.token}
        data.update(changes)
        return self.client.post("/register", data=data)

    def test_signup_login_and_admin_access_denied(self):
        response = self.submit()
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.location.endswith("/login"))
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        with SecurityStore().connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT password_hash FROM users WHERE username = %s", (self.username,))
            stored = cursor.fetchone()["password_hash"]
        self.assertNotEqual(stored, self.password)
        self.assertTrue(check_password_hash(stored, self.password))
        self.client.get("/register")
        with self.client.session_transaction() as session:
            self.token = session["register_csrf"]
        self.assertEqual(self.submit(username=self.username.upper()).status_code, 409)
        self.client.post("/login", data={"username": self.username, "password": "wrong"})
        with self.client.session_transaction() as session:
            self.assertNotIn("user", session)
        response = self.client.post("/login", data={"username": self.username, "password": self.password})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/board").status_code, 200)
        self.assertEqual(self.client.get("/admin").status_code, 403)
        self.assertEqual(self.client.post("/admin", data={"action": "issue_key"}).status_code, 403)

    def test_registration_validation(self):
        self.assertEqual(self.submit(csrf_token="wrong").status_code, 400)
        for changes in ({"username": "ADMIN"}, {"username": "ab"},
                        {"username": "invalid name"}, {"password": "", "password_confirm": ""},
                        {"password_confirm": "different"}):
            with self.subTest(changes=changes):
                self.assertEqual(self.submit(**changes).status_code, 400)
        with SecurityStore().connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username = %s", (self.username,))
            self.assertIsNone(cursor.fetchone())

    def test_password_length_is_unrestricted(self):
        for password in ("1", "a" * 129):
            with self.subTest(length=len(password)):
                response = self.submit(password=password, password_confirm=password)
                self.assertEqual(response.status_code, 303)
                with SecurityStore().connect() as connection, connection.cursor() as cursor:
                    cursor.execute("SELECT password_hash FROM users WHERE username = %s", (self.username,))
                    self.assertTrue(check_password_hash(cursor.fetchone()["password_hash"], password))
                    cursor.execute("DELETE FROM users WHERE username = %s", (self.username,))
                self.client.get("/register")
                with self.client.session_transaction() as session:
                    self.token = session["register_csrf"]


class BoardComposeTest(unittest.TestCase):
    def setUp(self):
        self.author = "boardtest_" + uuid4().hex
        with SecurityStore().connect() as connection, connection.cursor() as cursor:
            cursor.execute("INSERT INTO users (username,password_hash,created_at) VALUES (%s,%s,%s)",
                           (self.author, "test-session-only", "2026-10-28 00:00:00"))
        self.client = web.app.test_client()
        with self.client.session_transaction() as session:
            session["user"] = self.author
        self.client.get("/board")
        with self.client.session_transaction() as session:
            self.token = session["board_csrf"]

    def tearDown(self):
        with SecurityStore().connect() as connection, connection.cursor() as cursor:
            cursor.execute("DELETE FROM posts WHERE author = %s", (self.author,))
            cursor.execute("DELETE FROM users WHERE username = %s", (self.author,))

    def test_compose_validation_and_save(self):
        self.assertEqual(self.client.post("/board", data={"title": "test", "content": "test"}).status_code, 400)
        invalid = self.client.post("/board", data={"csrf_token": self.token, "title": "Keep draft", "content": " "})
        self.assertEqual(invalid.status_code, 400)
        self.assertIn('data-open="true"', invalid.text)
        self.assertIn('value="Keep draft"', invalid.text)
        saved = self.client.post("/board", data={"csrf_token": self.token, "title": "Popup test", "content": "Saved from compose form"})
        self.assertEqual(saved.status_code, 303)
        page = self.client.get("/board")
        self.assertIn("Popup test", page.text)
        self.assertIn('data-open="false"', page.text)
        with SecurityStore().connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS count FROM posts WHERE author = %s", (self.author,))
            self.assertEqual(cursor.fetchone()["count"], 1)


class MemberRoleTest(unittest.TestCase):
    def setUp(self):
        self.username = "roletest_" + uuid4().hex[:16]
        with SecurityStore().connect() as connection, connection.cursor() as cursor:
            cursor.execute("INSERT INTO users (username,password_hash,created_at) VALUES (%s,%s,%s)",
                           (self.username, "test-session-only", "2026-10-28 00:00:00"))
            self.member_id = cursor.lastrowid
            cursor.execute("SELECT id FROM users WHERE username='admin'")
            self.admin_id = cursor.fetchone()["id"]
        self.admin = web.app.test_client()
        self.member = web.app.test_client()
        with self.admin.session_transaction() as session:
            session["user"] = "admin"
        with self.member.session_transaction() as session:
            session["user"] = self.username
        self.admin.get("/admin")
        with self.admin.session_transaction() as session:
            self.token = session["admin_csrf"]

    def tearDown(self):
        with SecurityStore().connect() as connection, connection.cursor() as cursor:
            cursor.execute("DELETE FROM users WHERE id=%s AND username=%s", (self.member_id, self.username))

    def change(self, member_id, role):
        return self.admin.post("/admin", data={"csrf_token": self.token, "action": "change_role",
                                               "member_id": member_id, "role": role})

    def test_role_changes_take_effect_without_new_login(self):
        self.assertEqual(self.member.get("/admin").status_code, 403)
        self.assertEqual(self.change(self.member_id, "admin").status_code, 303)
        self.assertEqual(self.member.get("/admin").status_code, 200)
        with self.member.session_transaction() as session:
            member_token = session["admin_csrf"]
        self.assertEqual(self.member.post("/admin", data={"csrf_token": member_token, "action": "change_role",
                         "member_id": self.member_id, "role": "member"}).status_code, 400)
        self.assertEqual(self.change(self.member_id, "member").status_code, 303)
        self.assertEqual(self.member.get("/admin").status_code, 403)
        self.assertEqual(self.member.post("/admin", data={"csrf_token": member_token, "action": "issue_key"}).status_code, 403)
        with SecurityStore().connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT role FROM users WHERE id=%s", (self.member_id,))
            self.assertEqual(cursor.fetchone()["role"], "member")

    def test_protected_admin_invalid_role_and_csrf(self):
        self.assertEqual(self.change(self.admin_id, "member").status_code, 400)
        self.assertEqual(self.change(self.member_id, "superuser").status_code, 400)
        self.assertEqual(self.admin.post("/admin", data={"action": "change_role", "member_id": self.member_id,
                                                        "role": "admin"}).status_code, 400)


class BulkManagementTest(unittest.TestCase):
    def setUp(self):
        self.label = "bulk-test-" + uuid4().hex
        self.store = SecurityStore()
        self.client = web.app.test_client()
        with self.client.session_transaction() as session:
            session["user"] = "admin"
        self.client.get("/dashboard")
        with self.client.session_transaction() as session:
            self.csrf = session["admin_csrf"]
        self.ids = [self.label + str(index) for index in range(3)]
        with self.store.connect() as connection, connection.cursor() as cursor:
            for index, identifier in enumerate(self.ids):
                cursor.execute("INSERT INTO incident_tickets (id,title,api_key_id,event,status,created_at,closed_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                               (identifier, "Bulk test", self.label, "api_key_compromised", "종료" if index == 2 else "열림", "2026-10-28", "old-close" if index == 2 else "-"))

    def tearDown(self):
        with self.store.connect() as connection, connection.cursor() as cursor:
            cursor.execute("DELETE FROM incident_tickets WHERE api_key_id=%s", (self.label,))
            cursor.execute("DELETE FROM api_keys WHERE label=%s", (self.label,))

    def ticket_rows(self):
        with self.store.connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT id,status,closed_at FROM incident_tickets WHERE api_key_id=%s", (self.label,))
            return {row["id"]: row for row in cursor.fetchall()}

    def test_individual_and_bulk_ticket_close(self):
        first = {"action": "close_ticket", "ticket_id": self.ids[0], "csrf_token": self.csrf}
        self.assertEqual(self.client.post("/dashboard/tickets", data=first).status_code, 303)
        closed_at = self.ticket_rows()[self.ids[0]]["closed_at"]
        self.client.post("/dashboard/tickets", data=first)
        self.assertEqual(self.ticket_rows()[self.ids[0]]["closed_at"], closed_at)
        token = web.bulk_token("tickets", self.ids)
        newer = self.label + "new"
        with self.store.connect() as connection, connection.cursor() as cursor:
            cursor.execute("INSERT INTO incident_tickets (id,title,api_key_id,event,status,created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                           (newer, "New ticket", self.label, "api_key_compromised", "열림", "2026-10-28"))
        blocks_before = self.store.blocks()
        keys_before = self.store.keys()
        response = self.client.post("/dashboard/tickets?ticket_status=open&events_page=2", data={"action": "close_all_tickets", "targets": token, "csrf_token": self.csrf})
        self.assertEqual(response.status_code, 303)
        self.assertIn("ticket_status=open", response.location)
        rows = self.ticket_rows()
        self.assertEqual(rows[self.ids[1]]["status"], "종료")
        self.assertEqual(rows[self.ids[2]]["closed_at"], "old-close")
        self.assertEqual(rows[newer]["status"], "열림")
        self.assertEqual(self.store.blocks(), blocks_before)
        self.assertEqual(self.store.keys(), keys_before)

    def test_bulk_key_revoke_only_confirmed_active_keys(self):
        issued = [self.store.issue(self.label, "127.0.0.1") for _ in range(3)]
        self.store.revoke(issued[2]["api_key_id"])
        old_time = self.store.find_by_id(issued[2]["api_key_id"])["revoked_at"]
        token = web.bulk_token("keys", [key["api_key_id"] for key in issued])
        newer = self.store.issue(self.label, "127.0.0.1")
        response = self.client.post("/admin?key_status=active", data={"action": "revoke_all_keys", "targets": token, "csrf_token": self.csrf})
        self.assertEqual(response.status_code, 303)
        self.assertIn("key_status=active", response.location)
        self.assertTrue(all(self.store.find_by_id(key["api_key_id"])["status"] == "revoked" for key in issued))
        self.assertEqual(self.store.find_by_id(newer["api_key_id"])["status"], "active")
        self.assertEqual(self.store.find_by_id(issued[2]["api_key_id"])["revoked_at"], old_time)

    def test_invalid_confirmation_and_csrf_cannot_close(self):
        self.assertEqual(self.client.post("/dashboard/tickets", data={"action": "close_all_tickets", "targets": "invalid", "csrf_token": self.csrf}).status_code, 400)
        self.assertEqual(self.client.post("/dashboard/tickets", data={"action": "close_ticket", "ticket_id": self.ids[0]}).status_code, 400)
        self.assertEqual(self.ticket_rows()[self.ids[0]]["status"], "열림")


class IncidentPersistenceTest(unittest.TestCase):
    def setUp(self):
        self.connection = SecurityStore().connect()
        self.addCleanup(self.connection.close)
        with self.connection.cursor() as cursor:
            for table in ("incident_tickets", "security_events", "blocked_ips", "incident_registry", "incident_counters", "api_keys"):
                cursor.execute(f"SHOW CREATE TABLE {table}")
                statement = cursor.fetchone()["Create Table"].replace("CREATE TABLE", "CREATE TEMPORARY TABLE", 1)
                cursor.execute(statement)
            initialize_incidents(cursor)
        self.db = web.MySQLConnection(self.connection)
        self.get_db = patch.object(web, "get_db", return_value=self.db)
        self.get_db.start()
        connection = self.connection
        class ConnectionContext:
            def __enter__(self): return connection
            def __exit__(self, *_args): return False
        self.api_connection = patch.object(api.security_store, "connect", return_value=ConnectionContext())
        self.api_connection.start()
        self.logs = patch.object(api, "write_security_log")
        self.logs.start()
        self.client = web.app.test_client()
        self.api_client = api.app.test_client()

    def tearDown(self):
        self.get_db.stop()
        self.api_connection.stop()
        self.logs.stop()
        # addCleanup closes the connection and discards its temporary tables.

    def send(self, key, identifier=None):
        return self.client.post("/api/security-events", json={"event_type": "api_key_compromised",
            "api_key_id": key, "client_ip": "192.0.2.234", "incident_id": identifier,
            "decision": "거부", "reason": "integration-test"})

    def count(self, table):
        with self.connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) AS total FROM {table}")
            return cursor.fetchone()["total"]

    def test_repeats_commit_but_conflicting_ids_do_not_partially_save(self):
        first = self.send("key-A")
        self.assertEqual(first.status_code, 201)
        identifier = first.get_json()["event"]["incident_id"]
        with patch.object(self.db, "commit", wraps=self.db.commit) as commit:
            self.assertEqual(self.send("key-A", identifier).status_code, 201)
            self.assertEqual(commit.call_count, 1)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT occurrence_count FROM incident_tickets WHERE id=%s", (identifier,))
            self.assertEqual(cursor.fetchone()["occurrence_count"], 2)
        self.assertEqual(self.count("security_events"), 2)
        conflict = self.send("key-B", identifier)
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.get_json()["error"], "incident_conflict")
        self.assertEqual(self.count("security_events"), 2)
        second = self.send("key-B")
        self.assertEqual(second.status_code, 201)
        self.assertNotEqual(second.get_json()["event"]["incident_id"], identifier)
        self.assertEqual(self.count("incident_tickets"), 2)

    def test_save_failure_rolls_back_ticket_counter_and_event(self):
        execute = self.db.execute
        def fail_event(query, params=None):
            if query.startswith("INSERT INTO security_events"):
                raise pymysql.IntegrityError(1062, "simulated failure")
            return execute(query, params)
        with patch.object(self.db, "execute", side_effect=fail_event):
            self.assertEqual(self.send("key-A").status_code, 409)
        for table in ("incident_tickets", "security_events", "blocked_ips", "incident_registry"):
            self.assertEqual(self.count(table), 0)
        self.assertEqual(self.send("key-A").get_json()["event"]["incident_id"], "INC-API-001")

    def test_api_restart_preserves_identity_and_dashboard_receives_same_id(self):
        for index in range(2):
            api.INCIDENTS.clear()  # Simulate losing the API process's in-memory incident history.
            issued = api.security_store.issue("temporary-incident-test", "127.0.0.1")
            response = self.api_client.post("/automation/revoke-key", json={"api_key_id": issued["api_key_id"], "client_ip": "192.0.2.234"})
            self.assertEqual(response.status_code, 200)
            identifier = response.get_json()["incident"]["incident_id"]
            self.assertEqual(identifier, f"INC-API-{index + 1:03d}")
            stored = self.send(issued["api_key_id"], identifier)
            self.assertEqual(stored.status_code, 201)
            self.assertEqual(stored.get_json()["event"]["incident_id"], identifier)
        self.assertEqual(self.count("incident_tickets"), 2)
        api.INCIDENTS.clear()
        repeated = self.api_client.post("/automation/revoke-key", json={"api_key_id": issued["api_key_id"], "client_ip": "192.0.2.234"})
        self.assertEqual(repeated.get_json()["incident"]["incident_id"], identifier)
        self.assertEqual(self.send(issued["api_key_id"], identifier).status_code, 201)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT occurrence_count FROM incident_tickets WHERE id=%s", (identifier,))
            self.assertEqual(cursor.fetchone()["occurrence_count"], 2)



    def test_blocked_requests_count_once_and_different_active_keys_alert(self):
        first = api.security_store.issue("temporary-blocked-A", "127.0.0.1")
        second = api.security_store.issue("temporary-blocked-B", "127.0.0.1")
        api.security_store.block("192.0.2.234", "temporary-test")
        self.logs.stop()
        with TemporaryDirectory() as directory, patch.object(api, "LOG_FILE", Path(directory) / "events.jsonl"), \
             patch.object(api, "_forward_to_middleware", return_value=True) as forward, patch("builtins.print"):
            for key in (first, first, second):
                response = self.api_client.get("/api/data", headers={"X-API-Key": key["new_api_key"], "X-Demo-Client-IP": "192.0.2.234"})
                self.assertEqual(response.status_code, 403)
            self.assertEqual([call.args[0]["event_type"] for call in forward.call_args_list],
                             ["api_key_compromised", "api_request_blocked", "api_key_compromised"])
        self.assertEqual(self.count("security_events"), 3)
        self.assertEqual(self.count("incident_tickets"), 2)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT id,occurrence_count FROM incident_tickets WHERE api_key_id=%s", (first["api_key_id"],))
            ticket = cursor.fetchone()
            self.assertEqual(ticket["occurrence_count"], 2)
        for _ in range(2):
            self.assertEqual(self.send(first["api_key_id"], ticket["id"]).status_code, 200)
        self.assertEqual(self.count("security_events"), 3)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT occurrence_count FROM incident_tickets WHERE id=%s", (ticket["id"],))
            self.assertEqual(cursor.fetchone()["occurrence_count"], 2)
        api.security_store.revoke(second["api_key_id"])
        event = {"event_type": "api_key_compromised", "timestamp": api.utc_timestamp(),
                 "api_key_id": second["api_key_id"], "client_ip": "192.0.2.234", "detection_reason": "blocked_ip"}
        self.assertFalse(api.security_store.record_denied_request(event))

    def test_allowed_api_requests_are_saved_without_tickets_or_blocks(self):
        issued = api.security_store.issue("temporary-allowed-test", "127.0.0.1")
        self.logs.stop()
        with TemporaryDirectory() as directory, patch.object(api, "LOG_FILE", Path(directory) / "events.jsonl"), \
             patch.object(api, "_forward_to_middleware", return_value=True) as forward, patch("builtins.print"):
            for _ in range(2):
                response = self.api_client.get("/api/data", headers={"X-API-Key": issued["new_api_key"]})
                self.assertEqual(response.status_code, 200)
            self.assertEqual(forward.call_count, 2)
            self.assertNotIn(issued["new_api_key"], api.LOG_FILE.read_text(encoding="utf-8"))
        self.assertEqual(self.count("security_events"), 2)
        self.assertEqual(self.count("incident_tickets"), 0)
        self.assertEqual(self.count("blocked_ips"), 0)
        with self.client.session_transaction() as session:
            session["user"] = "admin"
        with patch.object(web, "render_template", wraps=web.render_template) as render:
            response = self.client.get("/dashboard?event_decision=allowed")
            self.assertEqual(response.status_code, 200)
            events = render.call_args.kwargs["recent_events"]
            self.assertEqual(len(events), 2)
            self.assertTrue(all(event["decision"] == "허용" and event["scenario"] == "정상 API 요청" for event in events))


class PaginationBoundaryTest(unittest.TestCase):
    def test_empty_exact_page_and_page_overflow(self):
        for total, requested, number, pages in (
            (0, None, 1, 1), (5, 2, 1, 1), (6, 2, 2, 2),
            (10, 3, 2, 2), (11, 3, 3, 3), (12, "invalid", 1, 3),
        ):
            with self.subTest(total=total, requested=requested):
                page = Page.create(total, requested)
                self.assertEqual((page.number, page.pages), (number, pages))


if __name__ == "__main__":
    unittest.main(verbosity=2)
