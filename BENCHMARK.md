# SENTINEL — Detection Quality Benchmark

This repository includes an **offline, reproducible regression benchmark** for the Python log-analysis engine. It supplements automated unit tests and the original sample demonstration; it is **not** a live cyberattack dataset.

## How to reproduce

\`\`\`bash
python3 benchmark_detection.py --json benchmark_results.json
python3 -m unittest discover -v
\`\`\`

The benchmark uses **27 independently named, hand-labelled synthetic scenarios** (13 suspicious-pattern scenarios and 14 benign scenarios). Labels are defined in the benchmark source. Scenarios cover ordinary and suspicious SSH authentication events and web requests, including split time windows, account/IP separation, URL encoding, and noisy but benign HTTP activity.

| Curated benchmark metric | Previous rules | Updated rules |
| --- | ---: | ---: |
| Scenarios with exactly the expected alert categories | **23 / 27** | **27 / 27** |
| Benign scenarios with at least one unexpected alert | **2 / 14** | **0 / 14** |
| Category-level true positives | 13 | 15 |
| Category-level false positives | 2 | 0 |
| Category-level false negatives | 2 | 0 |
| Precision on **this curated synthetic set only** | 86.7% | 100.0% |
| Recall on **this curated synthetic set only** | 86.7% | 100.0% |

The 13 suspicious scenarios can each have more than one expected category; this is why category true positives can total more than 13. False positives and false negatives above count **category labels per case**, not individual log events or real-world intrusions.

**Crucial limitation:** These synthetic cases were designed while inspecting the detection rules, and some improvements were developed specifically to address their failures. This is an **engineering regression suite, not an unbiased validation set**. The 100% figures are **not** estimates of detection performance, recall, or false-positive rate on real production logs. No real systems were scanned, no live attacks were monitored, and no private logs were collected.

## Issues reproduced and fixed

1. **Encoded indicators missed:** Percent-encoded SQL injection patterns went undetected. The engine now performs bounded URL decoding (up to two passes) for signature comparison, preserving the original raw request for alert reporting.
2. **Double-encoded traversal missed:** A two-layer encoded path marker was not detected. The bounded decoder makes this test case detectable, without a claim of universal obfuscation coverage.
3. **Repeated 404s caused a false scanning alert:** Repeated requests for **one missing image** can occur from an ordinary browser or site misconfiguration. Scanning now requires a burst of 404s **and distinct missing paths within the same sliding time window**.
4. **Documentation filename caused a false sensitive-file alert:** A request for \`/docs/.env-example\` was flagged as \`/.env\` probing. The sensitive-file regex now checks a tighter filename boundary, while a true \`/.env\` probe still triggers.

## What is not covered

The analyser remains a **signature/heuristic-based educational prototype**, not a production SIEM. This test set does not establish coverage against adversarial obfuscation, unseen log formats, IPv6 SSH messages, authentication semantics across infrastructure, device clock errors, large archives or real incident labels. False positives and missed detections remain possible. Further validation on **permitted, independently sourced, appropriately redacted log data** would be required before making real-world accuracy claims.

## Files and evidence

- \`benchmark_detection.py\` — scenario definitions and calculation of category-level metrics
- \`test_detection_benchmark.py\` — regression tests for each discovered gap plus benchmark consistency
- \`evidence/benchmark_before.json\` — baseline results before the fixes (summary)
- \`evidence/benchmark_after.json\` — updated results with the fixes (summary)
- Existing \`test_log_analyser.py\`, \`test_dashboard_helpers.py\` — engine and map tests

The original synthetic demonstration remains unchanged: **55 SSH events, 79 HTTP requests, 11 alerts (1 critical, 3 high, 7 medium)**. The graphical SENTINEL desktop dashboard uses this same detection engine and was smoke-tested separately.
