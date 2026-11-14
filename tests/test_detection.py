import copy
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import security_continuous_fixtures as fixtures
from security_continuous_delivery import scope
from lab.detection import evaluate

CLOCK = '2026-11-13T18:00:00Z'
SOURCE = scope('production')['source']

class DetectionTests(unittest.TestCase):
    def test_twelve_original_fixture_scenarios(self):
        for name, signal, rows, count, observed in fixtures.cases():
            with self.subTest(case=name):
                result = evaluate(rows, signal, CLOCK, SOURCE)
                self.assertEqual(len(result), count)
                if count:
                    self.assertEqual(result[0]['observed'], observed)

    def test_different_functions_share_the_same_activity_window(self):
        rows = fixtures.rows('functions', 5)
        for index, row in enumerate(rows):
            row['FunctionName'] = 'routeA' if index < 3 else 'routeB'
        self.assertEqual(evaluate(rows, 'http_denials', CLOCK, SOURCE)[0]['observed'], 5)

    def test_exact_threshold_minus_one_does_not_alert(self):
        self.assertEqual(evaluate(fixtures.rows('four', 4), 'http_denials', CLOCK, SOURCE), [])

    def test_wrong_event_kind_cannot_count_as_a_denial(self):
        rows = fixtures.rows('wrong-kind', 8, EventKind='http_service_unavailable')
        self.assertEqual(evaluate(rows, 'http_denials', CLOCK, SOURCE), [])

    def test_malformed_ids_and_function_names_are_excluded(self):
        for changes in ({'EventId': 'not-an-id'}, {'FunctionName': 'private/path'}):
            self.assertEqual(evaluate(fixtures.rows('malformed', 8, **changes), 'http_denials', CLOCK, SOURCE), [])

    def test_model_never_mutates_supplied_evidence(self):
        rows = fixtures.rows('unchanged', 5)
        before = copy.deepcopy(rows)
        evaluate(rows, 'http_denials', CLOCK, SOURCE)
        self.assertEqual(rows, before)

    def test_unknown_signal_fails_closed(self):
        with self.assertRaises(ValueError):
            evaluate([], 'unknown', CLOCK, SOURCE)

if __name__ == '__main__':
    unittest.main()
