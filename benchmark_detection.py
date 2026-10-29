#!/usr/bin/env python3
"""Offline, deterministic, curated detection-regression benchmark.

These are hand-labelled synthetic cases, NOT field data or a measure of
real-world detection performance. No networking or harmful actions.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from log_analyser import analyse_ssh, analyse_web

START = datetime(2026, 10, 29, 12, 0, 0)
WINDOW = timedelta(minutes=10)
THRESHOLD = 5


def ssh(kind, offset, user='alice', ip='198.51.100.25'):
    return {'ts': START + timedelta(seconds=offset), 'kind': kind, 'user': user, 'ip': ip}


def web(path='/', status=200, offset=0, ip='198.51.100.45', ua='Mozilla/5.0'):
    return {'ts': START + timedelta(seconds=offset), 'path': path, 'status': status,
            'ip': ip, 'ua': ua, 'method': 'GET'}


@dataclass(frozen=True)
class Case:
    name: str
    kind: str
    expected: tuple[str, ...]
    events: list[dict]
    note: str


def cases():
    """Varied positives and benign edge cases, labelled before evaluation."""
    return [
        Case('ssh_failure_burst', 'ssh', ('SSH brute force',),
             [ssh('failed', i*30) for i in range(6)], 'Six failures within 10 minutes'),
        Case('ssh_username_spread', 'ssh', ('SSH brute force', 'Multiple usernames targeted'),
             [ssh('failed', i*30, user=f'user{i}') for i in range(5)], 'Five different usernames within 10 minutes'),
        Case('ssh_success_after_failures', 'ssh', ('Possible account compromise',),
             [ssh('failed', i*30) for i in range(3)] + [ssh('accepted', 100)],
             'Success after recent failures for the same account and IP'),
        Case('ssh_failure_burst_out_of_order', 'ssh', ('SSH brute force',),
             [ssh('failed', i*30) for i in (5, 2, 1, 4, 0, 3)], 'Unsorted log events'),
        Case('ssh_sparse_failures', 'ssh', (),
             [ssh('failed', i*11*60) for i in range(7)], 'Failures spaced across more than one window'),
        Case('ssh_different_account_success', 'ssh', (),
             [ssh('failed', i*30, user='alice') for i in range(3)] + [ssh('accepted', 100, user='bob')],
             'A different account logs in after three failures'),
        Case('ssh_low_volume', 'ssh', (),
             [ssh('failed', i*30) for i in range(2)], 'Two failed logins only'),
        Case('ssh_usernames_over_hours', 'ssh', (),
             [ssh('failed', i*3600, user=f'user{i}') for i in range(7)],
             'Many usernames targeted, but not in the same ten-minute window'),
        Case('ssh_separate_sources', 'ssh', (),
             [ssh('failed', i*30, ip=f'192.0.2.{40+j}') for j in range(3) for i in range(4)],
             'No individual source meets threshold'),
        Case('ssh_success_before_failures', 'ssh', (),
             [ssh('accepted', 0)] + [ssh('failed', i*30+10) for i in range(3)],
             'A prior successful login cannot be caused by later failures'),
        Case('web_sql_plain', 'web', ('SQL injection',),
             [web('/product?id=1+UNION+SELECT+2')], 'SQLi signature in request'),
        Case('web_sql_percent_encoded', 'web', ('SQL injection',),
             [web('/product?id=1%20%55%4e%49%4f%4e%20%53%45%4c%45%43%54%202')],
             'Percent-encoded SQLi indicators'),
        Case('web_traversal_plain', 'web', ('Path traversal', 'Sensitive file probing'),
             [web('/download?file=../../../etc/passwd')], 'Traversal and sensitive file in path'),
        Case('web_traversal_double_encoded', 'web', ('Path traversal',),
             [web('/static/%252e%252e%252fdata.txt')], 'Double-encoded traversal markers'),
        Case('web_xss_plain', 'web', ('Cross-site scripting',),
             [web('/search?q=<script>alert(1)</script>')], 'XSS request indicator'),
        Case('web_xss_encoded', 'web', ('Cross-site scripting',),
             [web('/search?q=%3Cscript%3Ealert(1)%3C/script%3E')], 'Percent-encoded XSS request'),
        Case('web_hidden_env', 'web', ('Sensitive file probing',),
             [web('/.env')], 'Attempt to read a sensitive configuration file'),
        Case('web_bad_user_agent', 'web', ('Attack tool detected',),
             [web('/index', ua='Nikto/2.1')], 'Recognisable scanning user agent'),
        Case('web_many_distinct_404', 'web', ('Directory/URL scanning',),
             [web(f'/guess-{i}', status=404, offset=i*8) for i in range(12)],
             'Twelve distinct 404 paths in a short window'),
        Case('web_repeated_missing_image', 'web', (),
             [web('/favicon.ico', status=404, offset=i*8) for i in range(12)],
             'Repeated request for the same broken static asset'),
        Case('web_env_documentation', 'web', (),
             [web('/docs/.env-example')], 'A public documentation filename containing .env'),
        Case('web_normal_agent', 'web', (),
             [web('/dashboard', ua='Mozilla/5.0 (Macintosh) Safari/605')], 'Benign browser user agent'),
        Case('web_normal_search', 'web', (),
             [web('/search?q=how+to+join+tables')], 'Normal text search'),
        Case('web_benign_200_burst', 'web', (),
             [web('/home', status=200, offset=i*4) for i in range(15)], 'Normal successful browsing'),
        Case('web_sparse_distinct_404', 'web', (),
             [web(f'/missing-{i}', status=404, offset=i*180) for i in range(12)],
             'Distinct 404 paths spread across a much longer period'),
        Case('web_dot_gitignore_file', 'web', (),
             [web('/manual/.gitignore')], 'A non-secret documentation filename'),
        Case('web_benign_encoded_space', 'web', (),
             [web('/search?q=ordinary%20notes')], 'Plain encoded search query'),
    ]


def evaluate():
    records = []
    tp = fp = fn = 0
    benign_total = benign_flagged = 0
    for case in cases():
        detected = analyse_ssh(case.events, THRESHOLD, WINDOW) if case.kind == 'ssh' else analyse_web(case.events, THRESHOLD, WINDOW)
        expected, predicted = set(case.expected), {a.category for a in detected}
        tp += len(expected & predicted)
        fp += len(predicted - expected)
        fn += len(expected - predicted)
        if not expected:
            benign_total += 1
            benign_flagged += bool(predicted)
        records.append({'case': case.name, 'kind': case.kind,
                        'expected': sorted(expected), 'detected': sorted(predicted),
                        'passed': expected == predicted, 'note': case.note})
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {'dataset': 'manually labelled synthetic regression cases',
            'caveat': 'NOT an estimate of real-world precision, recall, false-positive rate or detection coverage',
            'case_count': len(records),
            'passed_cases': sum(x['passed'] for x in records),
            'benign_cases': benign_total, 'benign_cases_with_alerts': benign_flagged,
            'category_true_positives': tp, 'category_false_positives': fp,
            'category_false_negatives': fn,
            'category_precision': precision, 'category_recall': recall,
            'cases': records}


def main():
    p = argparse.ArgumentParser(description='Evaluate the log analyser on labelled, synthetic regression scenarios')
    p.add_argument('--json', type=Path, help='Save reproducible benchmark results as JSON')
    args = p.parse_args()
    report = evaluate()
    print('SENTINEL / curated synthetic regression benchmark')
    print(f"Scenarios: {report['passed_cases']}/{report['case_count']} matching expected alert categories")
    print(f"Benign scenarios flagged: {report['benign_cases_with_alerts']}/{report['benign_cases']}")
    print(f"Category TP={report['category_true_positives']} FP={report['category_false_positives']} FN={report['category_false_negatives']}")
    if report['category_precision'] is not None:
        print(f"Curated-set precision: {report['category_precision']:.1%}")
    if report['category_recall'] is not None:
        print(f"Curated-set recall: {report['category_recall']:.1%}")
    for r in report['cases']:
        if not r['passed']:
            print(f"MISMATCH {r['case']}: expected {r['expected']}, got {r['detected']}")
    print('IMPORTANT: These metrics apply only to constructed examples, NOT real-world detection.')
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(f'Saved {args.json}')


if __name__ == '__main__':
    main()
