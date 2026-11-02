"""Scenario 1 receiver integration: only uniquely labelled test rows are removed."""
import unittest
from unittest.mock import patch
from uuid import uuid4
import app as api


class HoneytokenResponseTest(unittest.TestCase):
    def test_changed_contract_and_atomic_failure(self):
        from unittest.mock import MagicMock
        from security_store import SecurityStore
        event = dict(client_ip='192.0.2.233', token_id='HT-TEST', username='backup_admin',
                     timestamp='2026-10-30T03:37:21.906000+00:00', reason='honeytoken_used')
        for blocked in (False, True):
            store = SecurityStore()
            connection = MagicMock()
            cursor = connection.cursor.return_value.__enter__.return_value
            cursor.fetchone.return_value = {'ip': event['client_ip']} if blocked else None
            with patch.object(store, 'connect') as connect, \
                 patch('security_store.assign_incident', return_value='INC-API-TEST'), \
                 patch.object(store, '_block') as block:
                connect.return_value.__enter__.return_value = connection
                result = store.respond_honeytoken(event)
                self.assertEqual(result['changed'], not blocked)
                self.assertEqual(result['ip_blocked'], True)
                self.assertEqual(block.call_count, int(result['changed']))
                connection.commit.assert_called_once()
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = None
        with patch.object(store, 'connect') as connect, \
             patch('security_store.assign_incident', return_value='INC-API-TEST'), \
             patch.object(store, '_block', side_effect=RuntimeError('write failure')):
            connect.return_value.__enter__.return_value = connection
            with self.assertRaises(RuntimeError):
                store.respond_honeytoken(event)
            connection.rollback.assert_called_once()
            connection.commit.assert_not_called()

    def test_invalid_payload_does_not_write(self):
        client = api.app.test_client()
        with patch.object(api.security_store, 'respond_honeytoken') as save:
            for payload in ([], {}, {'event_type': 'api_key_compromised'},
                            {'event_type': 'honeytoken_used', 'client_ip': 'invalid'}):
                self.assertEqual(client.post('/automation/honeytoken-response', json=payload).status_code, 400)
            save.assert_not_called()

    def test_ip_only_and_optional_metadata(self):
        with patch.object(api.security_store, 'respond_honeytoken', return_value={'changed': True}) as save:
            client = api.app.test_client()
            for payload in ({'client_ip': '192.0.2.233'},
                            {'client_ip': '192.0.2.233', 'timestamp': 'bad', 'token_id': None}):
                self.assertEqual(client.post('/automation/honeytoken-response', json=payload).status_code, 200)
                event = save.call_args.args[0]
                self.assertEqual(event['event_type'], 'honeytoken_used')
                self.assertEqual(event['token_id'], '미상')
                self.assertIn('timestamp', event)

    def test_shared_block_ticket_and_retry(self):
        store = api.security_store
        token = 'HT-TEST-' + uuid4().hex
        ip = '192.0.2.233'
        self.assertFalse(store.is_blocked(ip), 'Existing IP block must not be overwritten by test')
        with store.connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT id FROM incident_tickets WHERE event='honeytoken_used' AND ip=%s", (ip,))
            self.assertIsNone(cursor.fetchone(), 'Existing ticket must not be modified by test')
        payload = dict(event_type='honeytoken_used', client_ip=ip, token_id=token,
                       username='backup_admin', placement='users_table',
                       detection_reason='honeytoken_used', reason=token,
                       severity='높음', timestamp='2026-10-30T03:37:21.906Z')
        client = api.app.test_client()
        try:
            first = client.post('/automation/honeytoken-response', json=payload)
            self.assertEqual(first.status_code, 200, first.get_json())
            result = first.get_json()
            self.assertEqual(result['status'], 'created')
            self.assertTrue(result['ip_blocked'])
            self.assertTrue(result['changed'])
            self.assertEqual(result['ip'], ip)
            retry = client.post('/automation/honeytoken-response', json=payload).get_json()
            self.assertEqual(retry['status'], 'created')
            self.assertFalse(retry['changed'])
            self.assertEqual(retry['incident_id'], result['incident_id'])
            with store.connect() as connection, connection.cursor() as cursor:
                cursor.execute('SELECT * FROM incident_tickets WHERE id=%s', (result['incident_id'],))
                ticket = cursor.fetchone()
                self.assertEqual(ticket['scenario'], '시나리오 1')
                self.assertEqual(ticket['occurrence_count'], 2)
                cursor.execute('SELECT COUNT(*) AS n FROM security_events WHERE api_key_id=%s', (token,))
                self.assertEqual(cursor.fetchone()['n'], 2)
            # The existing scenario 3 API checks the same database block list.
            self.assertTrue(api.is_ip_blocked(ip))
            payload['timestamp'] = '2026-10-30T03:38:21.906Z'
            repeated = client.post('/automation/honeytoken-response', json=payload).get_json()
            self.assertFalse(repeated['changed'])
            self.assertTrue(repeated['ip_blocked'])
            store.unblock(ip)
            self.assertFalse(api.is_ip_blocked(ip))
            # A new received detection after unblock starts a new blocking period.
            self.assertTrue(client.post('/automation/honeytoken-response', json=payload).get_json()['changed'])
        finally:
            with store.connect() as connection, connection.cursor() as cursor:
                cursor.execute('DELETE FROM blocked_ips WHERE ip=%s AND reason=%s', (ip, token))
                cursor.execute('DELETE FROM security_events WHERE api_key_id=%s', (token,))
                cursor.execute("DELETE FROM incident_tickets WHERE event='honeytoken_used' AND ip=%s", (ip,))
                cursor.execute("DELETE FROM incident_registry WHERE event_type='honeytoken_used' AND client_ip=%s", (ip,))


if __name__ == '__main__':
    unittest.main()
