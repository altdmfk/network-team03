import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'web-app'))
from incident_store import assign_incident, IncidentConflict
sys.path.pop(0)


class IncidentPrefixTest(unittest.TestCase):
    def test_separate_counters(self):
        for event, counter, prefix in [('api_key_compromised', 'api', 'INC-API-'),
                                       ('killchain_critical', 'killchain', 'INC-KILLCHAIN-')]:
            cursor = MagicMock()
            cursor.fetchone.side_effect = [{'last_number': 4}, None, None, None, None]
            self.assertEqual(assign_incident(cursor, event, '192.0.2.1', ''), prefix + '005')
            self.assertEqual(cursor.execute.call_args_list[0].args[1], (counter,))
            self.assertEqual(cursor.execute.call_args_list[-2].args[1], (5, counter))

    def test_old_registered_ticket_stays_linked(self):
        cursor = MagicMock()
        cursor.fetchone.side_effect = [{'last_number': 0}, {'incident_id': 'INC-API-012'}]
        self.assertEqual(assign_incident(cursor, 'killchain_critical', '192.0.2.1', ''), 'INC-API-012')

    def test_wrong_scenario_prefix_is_rejected(self):
        cursor = MagicMock()
        cursor.fetchone.side_effect = [{'last_number': 0}, None]
        with self.assertRaises(IncidentConflict):
            assign_incident(cursor, 'killchain_critical', '192.0.2.1', '', 'INC-API-001')


if __name__ == '__main__':
    unittest.main()
