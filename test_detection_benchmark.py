"""Regression tests for defensive detections and the curated benchmark."""
import unittest
from datetime import timedelta
from benchmark_detection import START, cases, evaluate, ssh, web
from log_analyser import analyse_web, analyse_ssh, normalise_request_path

WINDOW = timedelta(minutes=10)


class TestDefensiveRegressions(unittest.TestCase):
    def test_url_percent_encoded_sql_indicator_is_recognised(self):
        alerts = analyse_web([web('/products?id=1%20%55%4e%49%4f%4e%20%53%45%4c%45%43%54')], 5, WINDOW)
        self.assertEqual({a.category for a in alerts}, {'SQL injection'})

    def test_two_layer_encoding_decodes_but_is_bounded(self):
        self.assertEqual(normalise_request_path('/folder/%252e%252e%252fnotes'), '/folder/../notes')
        alerts = analyse_web([web('/folder/%252e%252e%252fnotes')], 5, WINDOW)
        self.assertIn('Path traversal', {a.category for a in alerts})

    def test_repeated_404_for_same_asset_not_scanning(self):
        requests = [web('/favicon.ico', status=404, offset=i*4) for i in range(15)]
        self.assertFalse(any(a.category == 'Directory/URL scanning'
                             for a in analyse_web(requests, 5, WINDOW)))

    def test_distinct_missing_paths_still_flag_scanning(self):
        requests = [web(f'/probe/{i}', status=404, offset=i*4) for i in range(15)]
        self.assertTrue(any(a.category == 'Directory/URL scanning'
                            for a in analyse_web(requests, 5, WINDOW)))

    def test_documentation_filename_not_secret_probe(self):
        alerts = analyse_web([web('/docs/.env-example')], 5, WINDOW)
        self.assertNotIn('Sensitive file probing', {a.category for a in alerts})

    def test_actual_env_file_still_flagged(self):
        alerts = analyse_web([web('/.env')], 5, WINDOW)
        self.assertIn('Sensitive file probing', {a.category for a in alerts})

    def test_benchmark_cases_have_unique_names_and_labels(self):
        data = cases()
        self.assertEqual(len(data), len({c.name for c in data}))
        self.assertGreaterEqual(len(data), 25)
        self.assertGreaterEqual(sum(not c.expected for c in data), 10)

    def test_curated_regression_cases(self):
        result = evaluate()
        failures = [r for r in result['cases'] if not r['passed']]
        self.assertEqual(failures, [], f"Curated scenarios failed: {failures}")
        self.assertEqual(result['benign_cases_with_alerts'], 0)


if __name__ == '__main__':
    unittest.main()
