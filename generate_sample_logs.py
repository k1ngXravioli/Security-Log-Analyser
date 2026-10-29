#!/usr/bin/env python3
"""Creates fake (but realistic) log files with attacks hidden in normal traffic,
so you can demo the analyser safely. All IPs are from reserved documentation ranges."""
import random
from datetime import datetime, timedelta

random.seed(42)
BASE = datetime(2026, 10, 29, 0, 0, 0)
GOOD_IPS = ["198.51.100.10", "198.51.100.22", "198.51.100.37"]


def ssh_line(ts, ok, user, ip, invalid=False):
    stamp = ts.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if ts.day < 10 else ts.strftime("%b %d %H:%M:%S")
    pid = random.randint(1000, 9999)
    if ok:
        return f"{stamp} server sshd[{pid}]: Accepted password for {user} from {ip} port {random.randint(30000, 60000)} ssh2"
    inv = "invalid user " if invalid else ""
    return f"{stamp} server sshd[{pid}]: Failed password for {inv}{user} from {ip} port {random.randint(30000, 60000)} ssh2"


def web_line(ts, ip, path, status, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"):
    return (f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET {path} HTTP/1.1" '
            f'{status} {random.randint(200, 5000)} "-" "{ua}"')


ssh, web = [], []

# Normal SSH traffic
for _ in range(25):
    t = BASE + timedelta(minutes=random.randint(0, 1400))
    ssh.append((t, ssh_line(t, True, random.choice(["alice", "bob"]), random.choice(GOOD_IPS))))
    if random.random() < 0.2:  # occasional typo
        ssh.append((t, ssh_line(t - timedelta(seconds=20), False, "alice", random.choice(GOOD_IPS))))

# Attack 1: brute force + username enumeration from 203.0.113.5
t = BASE + timedelta(hours=3)
for i, u in enumerate(["root", "admin", "test", "oracle", "ubuntu", "pi", "root", "root", "admin", "guest",
                       "root", "root", "postgres", "root"]):
    ts = t + timedelta(seconds=i * 7)
    ssh.append((ts, ssh_line(ts, False, u, "203.0.113.5", invalid=u not in ("root",))))

# Attack 2: brute force that SUCCEEDS from 203.0.113.99 (the scary one)
t = BASE + timedelta(hours=14)
for i in range(6):
    ts = t + timedelta(seconds=i * 10)
    ssh.append((ts, ssh_line(ts, False, "bob", "203.0.113.99")))
ts = t + timedelta(seconds=70)
ssh.append((ts, ssh_line(ts, True, "bob", "203.0.113.99")))

# Normal web traffic
for _ in range(60):
    t = BASE + timedelta(minutes=random.randint(0, 1400))
    web.append((t, web_line(t, random.choice(GOOD_IPS), random.choice(["/", "/about", "/contact", "/products"]), 200)))

# Web attack 1: SQLi + traversal + sqlmap
t = BASE + timedelta(hours=5)
for i, p in enumerate(["/products?id=1'--", "/products?id=1+UNION+SELECT+username,password+FROM+users",
                       "/download?file=../../../etc/passwd", "/search?q=<script>alert(1)</script>"]):
    ts = t + timedelta(seconds=i * 3)
    web.append((ts, web_line(ts, "203.0.113.77", p, 500, ua="sqlmap/1.7")))

# Web attack 2: directory scanning
t = BASE + timedelta(hours=9)
for i, p in enumerate(["/.env", "/wp-login.php", "/phpmyadmin", "/backup.zip", "/admin", "/config.php", "/.git/config",
                       "/old", "/test", "/secret", "/db.sql", "/login.bak", "/site.tar.gz", "/staging", "/dev"]):
    ts = t + timedelta(seconds=i * 2)
    web.append((ts, web_line(ts, "203.0.113.150", p, 404)))

for name, rows in (("auth.log", ssh), ("access.log", web)):
    with open(name, "w") as f:
        f.write("\n".join(line for _, line in sorted(rows, key=lambda r: r[0])) + "\n")
print("Created auth.log and access.log")
