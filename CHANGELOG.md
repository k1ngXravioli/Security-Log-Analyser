# Review and reliability improvements

## October 2026 — Detection accuracy review

- Updated the multi-username alert to count distinct usernames **inside the chosen time window** rather than across the entire file.
- Required a matching source IP **and** username before correlating a successful SSH login with prior failures, reducing cross-account false positives.
- Changed the multi-username alert mapping from the specific password-spraying subtechnique (`T1110.003`) to general brute force (`T1110`), since SSH login failures do not record the attempted passwords.
- Made HTTP alert timestamps report the minimum and maximum seen times even for out-of-order log lines.
- Converted web timestamps with offsets to UTC for consistent comparisons and skipped malformed timestamp records.
- Validated CLI `--window` and `--threshold` arguments as positive integers.
- Sorted JSON alerts by severity to match the terminal report.
- Expanded the test suite from 6 tests to 12 tests, including regression coverage for false-positive cases.

The project remains a demonstration log-analysis tool. These source-level improvements have been verified by unit tests and by running the included synthetic dataset. Real-world accuracy, false-positive rates, or production performance have not been measured.
