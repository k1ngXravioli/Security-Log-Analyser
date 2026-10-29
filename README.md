# Security Log Analyser

**Python · Blue-Team Security · Log Analysis · Detection Engineering**

A standard-library Python command-line tool that examines **SSH authentication** and **Apache/Nginx-style web access** logs, identifies patterns worth investigating, and produces human-readable or JSON alerts. The project uses time-window analysis, basic event correlation, signature matching and severity-based reporting.

> **Scope:** This is a defensive, offline log analyser. It does not connect to hosts, launch scans, attempt authentication, or block IP addresses. Alerts indicate patterns for review, **not confirmed compromises**.

## Detection coverage

| Input | Detection | How it works | MITRE ATT&CK reference |
| --- | --- | --- | --- |
| SSH | Repeated failed logins | A sliding window counts failures per source IP | [T1110](https://attack.mitre.org/techniques/T1110/) |
| SSH | Multiple usernames targeted | Counts distinct attempted usernames from the same IP **within the window** | [T1110](https://attack.mitre.org/techniques/T1110/) |
| SSH | Successful login after failures | Matches an accepted login to recent failures for the **same IP and username** | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Web | SQL injection, path traversal and XSS patterns | Matches known indicators in requested URL paths | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Web | Sensitive-file probes and 404 bursts | Detects reconnaissance-style requests and repeated not-found responses | [T1595](https://attack.mitre.org/techniques/T1595/) |
| Web | Known scanner User-Agent strings | Flags strings such as `sqlmap` and `nikto` | [T1595](https://attack.mitre.org/techniques/T1595/) |

The ATT&CK mappings provide context. They **do not prove** which attack technique was used. In particular, SSH failure logs alone cannot demonstrate password spraying, since they do not show the passwords attempted.

## Quick start

Requires Python 3.10+; **no third-party packages**.

```bash
python3 -m unittest discover -v
python3 generate_sample_logs.py
python3 log_analyser.py --ssh auth.log --web access.log --year 2026 --json report.json
```

The sample logs are synthetic and use reserved documentation IP addresses. `generate_sample_logs.py` **overwrites** `auth.log` and `access.log` in the current directory; avoid running it in a folder containing real logs with those names.

Sample dataset outcome (29 October 2026):

```text
SSH events parsed  : 55
Web requests parsed: 79
Alerts raised      : 11
By severity        : CRITICAL=1, HIGH=3, MEDIUM=7
```

The highest-severity example is a successful SSH login following repeated failures for the same user and source address. That merits investigation but is **not proof that an account was compromised**.

## Command options

```text
--ssh FILE          SSH syslog-format authentication log
--web FILE          Web server combined-format access log
--threshold N       Failed-login count per time window (default: 5)
--window MINUTES    Window size in minutes (default: 10)
--year YYYY         Year to attach to SSH syslog timestamps
--json FILE         Save alerts as JSON as well as displaying them
```

At least one log input is required. Threshold and window must be positive integers.

## Implementation

- Regex-based parsing extracts timestamps, IPs, account names, HTTP paths, status codes and User-Agent strings.
- **Sliding-window logic** finds failure bursts and clusters of distinct usernames within a chosen time range.
- **Cross-event correlation** checks whether an accepted SSH login follows failures for the same IP and username.
- Alerts carry category, severity, source, count, first/last timestamps and a contextual MITRE ATT&CK identifier.
- JSON export uses the same severity ordering as the printed report.
- Twelve automated tests cover the main detections and edge cases, including false-positive regression scenarios.

## Known limitations

- Heuristic and signature-based detection can yield false positives or miss unfamiliar and obfuscated attack patterns.
- SSH parser assumes common `sshd` syslog messages with IPv4 addresses; IPv6 and other auth formats are not yet supported.
- SSH syslog entries usually omit the year; use `--year` to specify it. Logs spanning a year boundary require preprocessing.
- Parsing reads log files into memory, so very large production archives may need a streaming approach.
- Missing or malformed entries can reduce detection coverage; the tool is not a replacement for a managed security monitoring platform.
- The sample results are from generated data, not a deployed network or production incident.

## Project files

- `log_analyser.py` — parser, detectors and CLI report generator
- `test_log_analyser.py` — automated tests
- `generate_sample_logs.py` — deterministic synthetic test data generator
- `auth.log`, `access.log` — example logs
- `report.json` — example structured alert output
- `CHANGELOG.md` — source-review improvements