import unittest
from unittest.mock import MagicMock, patch
import app as api


class KillchainResponseTest(unittest.TestCase):
    def payload(self):
        return dict(event_type='killchain_critical', client_ip='10.10.10.10',
                    incident_id='INC-KILLCHAIN-001', status_code=200,
                    action='pfSense 차단 + IoT Lockdown', reason='3단계 충족',
                    timestamp='2026-11-02T13:00:00')

    def test_critical_contract_and_korean_time(self):
        with patch.object(api.security_store, 'record_killchain_result', return_value={'incident_id': 'INC-KILLCHAIN-001'}) as save:
            response = api.app.test_client().post('/automation/killchain-response', json=self.payload())
            self.assertEqual(response.status_code, 200)
            self.assertEqual(save.call_args.args[0]['timestamp'], '2026-11-02T13:00:00+09:00')

    def test_warning_and_invalid_inputs_do_not_write(self):
        with patch.object(api.security_store, 'record_killchain_result') as save:
            client = api.app.test_client()
            response = client.post('/automation/killchain-response', json={'event_type': 'killchain_warning'})
            self.assertFalse(response.get_json()['ticket_created'])
            for payload in ([], {}, self.payload() | {'client_ip': 'bad'},
                            self.payload() | {'incident_id': 'INC-API-001'},
                            self.payload() | {'timestamp': 'bad'}):
                self.assertEqual(client.post('/automation/killchain-response', json=payload).status_code, 400)
            save.assert_not_called()

    def test_store_does_not_block_or_change_keys(self):
        from security_store import SecurityStore
        store = SecurityStore()
        for duplicate in (False, True):
            connection = MagicMock()
            cursor = connection.cursor.return_value.__enter__.return_value
            cursor.fetchone.return_value = {'id': 1} if duplicate else None
            with patch.object(store, 'connect') as connect, \
                 patch('security_store.assign_incident', return_value='INC-KILLCHAIN-001'), \
                 patch.object(store, '_block') as block:
                connect.return_value.__enter__.return_value = connection
                result = store.record_killchain_result(self.payload())
                self.assertFalse(result['shared_block_applied'])
                self.assertEqual(result['ticket_created'], not duplicate)
                block.assert_not_called()
                queries = ' '.join(call.args[0] for call in cursor.execute.call_args_list)
                self.assertNotIn('blocked_ips', queries)
                self.assertNotIn('api_keys', queries)
                connection.commit.assert_called_once()

    def test_storage_failure_rolls_back(self):
        from security_store import SecurityStore
        store = SecurityStore()
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.execute.side_effect = RuntimeError('storage failed')
        with patch.object(store, 'connect') as connect, \
             patch('security_store.assign_incident', return_value='INC-KILLCHAIN-001'):
            connect.return_value.__enter__.return_value = connection
            with self.assertRaises(RuntimeError):
                store.record_killchain_result(self.payload())
            connection.rollback.assert_called_once()
            connection.commit.assert_not_called()


if __name__ == '__main__':
    unittest.main()
