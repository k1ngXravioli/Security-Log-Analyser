#!/usr/bin/env python3
"""
Security Log Analyser
=====================
Parses SSH authentication logs (syslog format) and web server access logs
(Apache/Nginx "combined" format) and flags suspicious behaviour.

Detections (each tagged with a MITRE ATT&CK technique ID):
  SSH: brute force, username enumeration, login success after failures
  Web: injection/traversal/XSS attempts, sensitive file probing,
       404 scanning, known attack-tool user agents

Usage:
  python log_analyser.py --ssh auth.log --web access.log --json report.json
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote

# --------------------------------------------------------------------------
# Regex patterns for parsing log lines
# --------------------------------------------------------------------------
SSH_PREFIX = r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s"
SSH_FAILED = re.compile(
    SSH_PREFIX + r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
SSH_ACCEPTED = re.compile(
    SSH_PREFIX + r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d.]+)"
)

WEB_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?'
)

# Signatures for malicious web requests: name -> (regex, ATT&CK id)
WEB_SIGNATURES = {
    "SQL injection": (
        re.compile(r"(union(\s|\+|%20)+select|or(\s|\+|%20)+1=1|'--|sleep\(|information_schema)", re.I),
        "T1190",
    ),
    "Path traversal": (re.compile(r"(\.\./|\.\.%2f|%2e%2e)", re.I), "T1190"),
    "Cross-site scripting": (re.compile(r"(<script|%3cscript|onerror=)", re.I), "T1190"),
    "Sensitive file probing": (
        re.compile(r"((?:^|[/=?])\.env(?:$|[/?.&#])|\.git/|/etc/passwd|wp-login|phpmyadmin|\.htpasswd|/admin\b)", re.I),
        "T1595",
    ),
}
BAD_USER_AGENTS = re.compile(r"(sqlmap|nikto|nmap|hydra|masscan|dirbuster|gobuster)", re.I)


# --------------------------------------------------------------------------
# Data structure for findings
# --------------------------------------------------------------------------
@dataclass
class Alert:
    severity: str      # LOW / MEDIUM / HIGH / CRITICAL
    category: str
    source_ip: str
    description: str
    count: int
    first_seen: str
    last_seen: str
    mitre: str

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
def parse_ssh(path, year):
    """Return a list of SSH events: {ts, kind, user, ip}."""
    events = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        for kind, rx in (("failed", SSH_FAILED), ("accepted", SSH_ACCEPTED)):
            m = rx.match(line)
            if m:
                # syslog timestamps have no year, so we supply one
                try:
                    ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
                except ValueError:
                    continue  # Ignore malformed timestamp entries in mixed log files.
                events.append({"ts": ts, "kind": kind, "user": m["user"], "ip": m["ip"]})
                break
    return events


def parse_web(path):
    """Return a list of web requests: {ts, ip, method, path, status, ua}."""
    requests = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        m = WEB_LINE.match(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue  # Ignore invalid log entries rather than stopping analysis.
        # Convert to UTC so offsets can be compared consistently.
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        requests.append({
            "ts": ts, "ip": m["ip"], "method": m["method"], "path": m["path"],
            "status": int(m["status"]), "ua": m["ua"] or "",
        })
    return requests


# --------------------------------------------------------------------------
# Detection helpers
# --------------------------------------------------------------------------
def biggest_burst(times, window):
    """Sliding window: the largest number of events inside any `window`.
    Returns (count, start_time, end_time)."""
    times = sorted(times)
    best = (0, None, None)
    start = 0
    for end in range(len(times)):
        while times[end] - times[start] > window:
            start += 1
        count = end - start + 1
        if count > best[0]:
            best = (count, times[start], times[end])
    return best


def biggest_username_burst(attempts, window):
    """Return (unique usernames, attempts, first, last) within one time window.

    `attempts` contains (timestamp, username) tuples. Repeated usernames only
    count once towards distinct-user detections.
    """
    attempts = sorted(attempts)
    counts = Counter()
    left = 0
    best = (0, 0, None, None)
    for right, (ts, user) in enumerate(attempts):
        counts[user] += 1
        while ts - attempts[left][0] > window:
            old_user = attempts[left][1]
            counts[old_user] -= 1
            if counts[old_user] == 0:
                del counts[old_user]
            left += 1
        distinct = len(counts)
        total = right - left + 1
        if (distinct, total) > (best[0], best[1]):
            best = (distinct, total, attempts[left][0], ts)
    return best


# --------------------------------------------------------------------------
# SSH detections
# --------------------------------------------------------------------------
def analyse_ssh(events, threshold, window):
    alerts = []
    fails = defaultdict(list)       # ip -> [timestamps]
    username_attempts = defaultdict(list)  # ip -> [(timestamp, username)]
    failures_by_account = defaultdict(list)  # (ip, username) -> [timestamps]
    user_counts = defaultdict(Counter)

    for e in events:
        if e["kind"] == "failed":
            fails[e["ip"]].append(e["ts"])
            username_attempts[e["ip"]].append((e["ts"], e["user"]))
            failures_by_account[(e["ip"], e["user"])].append(e["ts"])
            user_counts[e["ip"]][e["user"]] += 1

    for ip, times in fails.items():
        count, first, last = biggest_burst(times, window)

        # 1. Brute force: many failures in a short window
        if count >= threshold:
            top = ", ".join(u for u, _ in user_counts[ip].most_common(3))
            sev = "HIGH" if count >= threshold * 3 else "MEDIUM"
            alerts.append(Alert(
                sev, "SSH brute force", ip,
                f"{count} failed logins within {int(window.total_seconds() // 60)} min "
                f"(most targeted: {top})",
                count, fmt(first), fmt(last), "T1110"))

        # 2. Multiple accounts targeted within the same rolling window.
        # The SSH logs cannot show whether the same password was used, so
        # we use generic Brute Force T1110 instead of Password Spraying T1110.003.
        unique, attempts, first_user, last_user = biggest_username_burst(
            username_attempts[ip], window
        )
        if unique >= 5:
            alerts.append(Alert(
                "MEDIUM", "Multiple usernames targeted", ip,
                f"{unique} usernames targeted across {attempts} failed attempts "
                f"within {int(window.total_seconds() // 60)} min",
                attempts, fmt(first_user), fmt(last_user), "T1110"))

    # 3. Success after failures = possible compromised account (most important)
    for e in events:
        if e["kind"] != "accepted":
            continue
        # Require a matching source IP AND username. A different account's
        # failures are insufficient to implicate this successful login.
        recent = [t for t in failures_by_account.get((e["ip"], e["user"]), [])
                  if timedelta(0) <= e["ts"] - t <= window]
        if len(recent) >= 3:
            alerts.append(Alert(
                "CRITICAL", "Possible account compromise", e["ip"],
                f"Successful login as '{e['user']}' right after {len(recent)} failed attempts",
                len(recent) + 1, fmt(min(recent)), fmt(e["ts"]), "T1078"))
    return alerts


# --------------------------------------------------------------------------
# Web detections
# --------------------------------------------------------------------------
def normalise_request_path(raw_path):
    """Decode up to two URL-encoding layers for *detection only*.

    Leaves the original request untouched for reports. Encoded strings are not
    automatically attacks: these are only compared against known signatures.
    Bounded decoding avoids indefinite repeated unquoting of hostile inputs.
    """
    path = raw_path
    for _ in range(2):
        decoded = unquote(path, errors='replace')
        if decoded == path:
            break
        path = decoded
    return path


def analyse_web(requests, threshold, window):
    alerts = []
    hits = defaultdict(lambda: defaultdict(list))  # ip -> category -> [(ts, path)]
    not_found = defaultdict(list)                  # ip -> [(ts, raw path)]
    attack_tool = {}

    for r in requests:
        decoded_path = normalise_request_path(r["path"])
        for name, (rx, _) in WEB_SIGNATURES.items():
            if rx.search(decoded_path):
                hits[r["ip"]][name].append((r["ts"], r["path"]))
        if r["status"] == 404:
            not_found[r["ip"]].append((r["ts"], r["path"]))
        if r["ua"] and BAD_USER_AGENTS.search(r["ua"]):
            attack_tool.setdefault(r["ip"], []).append((r["ts"], r["ua"]))

    for ip, cats in hits.items():
        for name, items in cats.items():
            mitre = WEB_SIGNATURES[name][1]
            sev = "HIGH" if name in ("SQL injection", "Path traversal") else "MEDIUM"
            alerts.append(Alert(
                sev, name, ip,
                f"{len(items)} suspicious request(s), e.g. {items[0][1][:60]}",
                len(items), fmt(min(t for t, _ in items)),
                fmt(max(t for t, _ in items)), mitre))

    for ip, attempts in not_found.items():
        # A broken favicon or a missing static asset can yield dozens of 404s.
        # Require both burst volume and diversity of missing paths, in the
        # SAME sliding window, before treating them as reconnaissance.
        unique_paths, count, first, last = biggest_username_burst(attempts, window)
        minimum_distinct = max(3, threshold)
        if count >= threshold * 2 and unique_paths >= minimum_distinct:
            alerts.append(Alert(
                "MEDIUM", "Directory/URL scanning", ip,
                f"{count} 'not found' responses across {unique_paths} distinct paths "
                f"in {int(window.total_seconds() // 60)} min (possible probing)",
                count, fmt(first), fmt(last), "T1595"))

    for ip, items in attack_tool.items():
        alerts.append(Alert(
            "HIGH", "Attack tool detected", ip,
            f"User-Agent identifies a hacking tool: {items[0][1][:50]}",
            len(items), fmt(min(t for t, _ in items)),
            fmt(max(t for t, _ in items)), "T1595"))
    return alerts


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def print_report(alerts, ssh_count, web_count):
    alerts = sorted(alerts, key=lambda a: (SEVERITY_ORDER[a.severity], -a.count))
    print("=" * 72)
    print(" SECURITY LOG ANALYSIS REPORT")
    print("=" * 72)
    print(f" SSH events parsed : {ssh_count}")
    print(f" Web requests parsed: {web_count}")
    print(f" Alerts raised      : {len(alerts)}")
    sev = Counter(a.severity for a in alerts)
    print(" By severity        : " + ", ".join(f"{k}={sev[k]}" for k in SEVERITY_ORDER if sev[k]))
    print("-" * 72)

    for a in alerts:
        print(f"[{a.severity:<8}] {a.category}  ({a.mitre})")
        print(f"   Source IP : {a.source_ip}")
        print(f"   Detail    : {a.description}")
        print(f"   Window    : {a.first_seen} -> {a.last_seen}")
        print()

    ips = Counter(a.source_ip for a in alerts)
    if ips:
        print("-" * 72)
        print(" TOP OFFENDING IPs (by number of alerts)")
        for ip, n in ips.most_common(5):
            print(f"   {ip:<18} {n} alert(s)")
        print(" Recommended action: review alerts and validate context before any response.")
    print("=" * 72)


def main():
    p = argparse.ArgumentParser(description="Analyse SSH and web logs for suspicious activity.")
    p.add_argument("--ssh", help="path to SSH auth log (syslog format)")
    p.add_argument("--web", help="path to web access log (combined format)")
    p.add_argument("--threshold", type=int, default=5, help="failures that trigger an alert (default 5)")
    p.add_argument("--window", type=int, default=10, help="time window in minutes (default 10)")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog timestamps")
    p.add_argument("--json", help="also save the alerts to this JSON file")
    args = p.parse_args()

    if not args.ssh and not args.web:
        p.error("provide at least one of --ssh or --web")
    if args.threshold < 1:
        p.error("--threshold must be a positive integer")
    if args.window < 1:
        p.error("--window must be a positive number of minutes")

    window = timedelta(minutes=args.window)
    alerts, ssh_events, web_reqs = [], [], []
    try:
        if args.ssh:
            ssh_events = parse_ssh(args.ssh, args.year)
            alerts += analyse_ssh(ssh_events, args.threshold, window)
        if args.web:
            web_reqs = parse_web(args.web)
            alerts += analyse_web(web_reqs, args.threshold, window)
    except FileNotFoundError as e:
        sys.exit(f"Error: file not found - {e.filename}")

    alerts.sort(key=lambda a: (SEVERITY_ORDER[a.severity], -a.count))
    print_report(alerts, len(ssh_events), len(web_reqs))
    if args.json:
        Path(args.json).write_text(json.dumps([asdict(a) for a in alerts], indent=2))
        print(f"Saved JSON report to {args.json}")


if __name__ == "__main__":
    main()
