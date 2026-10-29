import unittest
from datetime import datetime, timedelta
from log_analyser import biggest_burst, analyse_ssh, analyse_web

W = timedelta(minutes=10)
T0 = datetime(2026, 10, 29, 12, 0, 0)


def ev(kind, secs, ip="1.2.3.4", user="bob"):
    return {"ts": T0 + timedelta(seconds=secs), "kind": kind, "user": user, "ip": ip}


class TestDetection(unittest.TestCase):
    def test_burst_counts_only_within_window(self):
        times = [T0, T0 + timedelta(minutes=1), T0 + timedelta(hours=2)]
        self.assertEqual(biggest_burst(times, W)[0], 2)

    def test_brute_force_detected(self):
        alerts = analyse_ssh([ev("failed", i) for i in range(6)], 5, W)
        self.assertTrue(any(a.category == "SSH brute force" for a in alerts))

    def test_few_failures_ignored(self):
        self.assertEqual(analyse_ssh([ev("failed", i) for i in range(2)], 5, W), [])

    def test_success_after_failures_is_critical(self):
        events = [ev("failed", i) for i in range(4)] + [ev("accepted", 10)]
        alerts = analyse_ssh(events, 5, W)
        self.assertTrue(any(a.severity == "CRITICAL" for a in alerts))

    def test_sql_injection_detected(self):
        reqs = [{"ts": T0, "ip": "9.9.9.9", "method": "GET", "path": "/x?id=1+UNION+SELECT+1",
                 "status": 200, "ua": ""}]
        alerts = analyse_web(reqs, 5, W)
        self.assertEqual(alerts[0].category, "SQL injection")

    def test_attack_tool_user_agent(self):
        reqs = [{"ts": T0, "ip": "9.9.9.9", "method": "GET", "path": "/", "status": 200, "ua": "Nikto/2.1"}]
        self.assertEqual(analyse_web(reqs, 5, W)[0].category, "Attack tool detected")


class TestReliabilityRegressions(unittest.TestCase):
    def test_usernames_spread_over_hours_are_not_a_burst(self):
        # Five unique usernames in five hours should not trigger a 10-minute alert.
        events = [ev('failed', i * 3600, user=f'user{i}') for i in range(5)]
        alerts = analyse_ssh(events, 5, W)
        self.assertFalse(any(a.category == 'Multiple usernames targeted' for a in alerts))

    def test_multiple_users_in_one_window_are_flagged(self):
        events = [ev('failed', i * 10, user=f'user{i}') for i in range(5)]
        alerts = analyse_ssh(events, 5, W)
        matches = [a for a in alerts if a.category == 'Multiple usernames targeted']
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].count, 5)
        self.assertEqual(matches[0].mitre, 'T1110')

    def test_successful_different_user_is_not_flagged_as_compromise(self):
        events = [ev('failed', i, user='alice') for i in range(4)]
        events.append(ev('accepted', 10, user='bob'))
        alerts = analyse_ssh(events, 5, W)
        self.assertFalse(any(a.category == 'Possible account compromise' for a in alerts))

    def test_successful_same_user_after_failures_still_alerts(self):
        events = [ev('failed', i, user='bob') for i in range(4)]
        events.append(ev('accepted', 10, user='bob'))
        alerts = analyse_ssh(events, 5, W)
        self.assertTrue(any(a.category == 'Possible account compromise' for a in alerts))

    def test_out_of_order_web_requests_report_actual_time_bounds(self):
        reqs = [
            {'ts': T0 + timedelta(minutes=5), 'ip': '9.9.9.9', 'method': 'GET',
             'path': "/x?id=1'--", 'status': 200, 'ua': ''},
            {'ts': T0, 'ip': '9.9.9.9', 'method': 'GET',
             'path': "/y?id=1'--", 'status': 200, 'ua': ''},
        ]
        alert = next(a for a in analyse_web(reqs, 5, W) if a.category == 'SQL injection')
        self.assertEqual(alert.first_seen, '2026-10-29 12:00:00')
        self.assertEqual(alert.last_seen, '2026-10-29 12:05:00')

    def test_zero_window_threshold_rejected_by_cli(self):
        import subprocess
        import sys
        for flag in ('--window', '--threshold'):
            with self.subTest(flag=flag):
                result = subprocess.run(
                    [sys.executable, 'log_analyser.py', '--ssh', 'auth.log', flag, '0'],
                    capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('positive', result.stderr)


if __name__ == "__main__":
    unittest.main()
