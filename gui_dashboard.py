#!/usr/bin/env python3
"""
Security Log Analyser - SOC Dashboard (Tkinter)
===============================================
A dark-themed desktop dashboard that wraps the detection engine in
log_analyser.py. The CLI still works on its own; this is an optional front end.

Run:  python3 gui_dashboard.py
Requires Python with Tkinter (included with python.org installers;
Homebrew users: `brew install python-tk`).
"""

import csv
import json
import subprocess
import sys
import tempfile
import threading
import queue
import tkinter as tk
import tkinter.font as tkfont
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

import log_analyser as la

# ---------------------------------------------------------------- theme ----
BG, PANEL, PANEL2, BORDER = "#0b0f17", "#121826", "#182033", "#232d45"
TEXT, MUTED, ACCENT = "#e6edf7", "#8392ad", "#38bdf8"
SEV = {"CRITICAL": "#ff4d6d", "HIGH": "#ff8a3d", "MEDIUM": "#fbbf24", "LOW": "#4ade80"}
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}

REMEDIATION = {
    "SSH brute force": "Block the IP, enforce key-based auth, disable password login, install fail2ban, "
                       "and rate-limit connections to port 22.",
    "Username enumeration": "Disable root login, avoid default usernames, and alert on many distinct "
                            "usernames from one source.",
    "Possible account compromise": "URGENT: force a password reset, kill active sessions for that user, "
                                   "review shell history and new SSH keys, then enable MFA.",
    "SQL injection": "Use parameterised queries, validate input, deploy a WAF rule, and check the "
                     "database for signs of data extraction.",
    "Path traversal": "Canonicalise and validate file paths, run the web server with least privilege, "
                      "and block ../ sequences at the WAF.",
    "Cross-site scripting": "Encode output, add a Content-Security-Policy header, and sanitise user input.",
    "Sensitive file probing": "Make sure .env, .git and backup files are not web-accessible; remove "
                              "unused admin panels.",
    "Directory/URL scanning": "Rate-limit the source, add a WAF or fail2ban rule for repeated 404s.",
    "Attack tool detected": "Block the IP and the user-agent string, then review what that IP "
                            "requested before it was caught.",
}


def pick_fonts():
    fams = set(tkfont.families())
    ui = next((f for f in ("Helvetica Neue", "Segoe UI", "Helvetica") if f in fams), "TkDefaultFont")
    mono = next((f for f in ("Menlo", "Consolas", "Courier New") if f in fams), "TkFixedFont")
    return ui, mono


# -------------------------------------------------------------- widgets ----
class FlatButton(tk.Label):
    """tk.Button ignores colours on macOS, so buttons are styled Labels."""
    KINDS = {"primary": (ACCENT, "#06121d", "#7dd3fc"),
             "ghost": (PANEL2, TEXT, BORDER),
             "danger": ("#3a1722", SEV["CRITICAL"], "#54202f")}

    def __init__(self, parent, text, command, font, kind="primary"):
        self.bg, fg, self.hover = self.KINDS[kind]
        super().__init__(parent, text=text, bg=self.bg, fg=fg, font=font,
                         padx=16, pady=8, cursor="hand2")
        self.command, self.enabled = command, True
        self.bind("<Enter>", lambda e: self.enabled and self.config(bg=self.hover))
        self.bind("<Leave>", lambda e: self.config(bg=self.bg))
        self.bind("<Button-1>", lambda e: self.enabled and self.command())

    def set_enabled(self, on):
        self.enabled = on
        self.config(bg=self.bg if on else BORDER)


def card(parent, **kw):
    return tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1, **kw)


# ------------------------------------------------------------------ app ----
class App:
    def __init__(self, root):
        self.root = root
        self.ui, self.mono = pick_fonts()
        self.F = lambda size=12, bold=False: (self.ui, size, "bold" if bold else "normal")
        root.title("Security Log Analyser - SOC Dashboard")
        root.geometry("1360x860")
        root.minsize(1100, 700)
        root.configure(bg=BG)

        self.alerts, self.ssh_events, self.web_reqs = [], [], []
        self.view_alerts, self.sort_state = [], {}
        self.queue = queue.Queue()
        self.ssh_path, self.web_path = tk.StringVar(), tk.StringVar()
        self.threshold, self.window = tk.IntVar(value=5), tk.IntVar(value=10)
        self.year = tk.IntVar(value=datetime.now().year)
        self.search, self.sev_filter = tk.StringVar(), tk.StringVar(value="All")
        self.search.trace_add("write", lambda *a: self.refresh_table())

        self.setup_styles()
        self.build_layout()
        self.show_page("overview")
        root.bind("<Command-r>", lambda e: self.start_scan())
        root.bind("<Control-r>", lambda e: self.start_scan())
        root.bind("<Command-o>", lambda e: self.browse(self.ssh_path))
        self.poll_queue()

    # ---- styling -------------------------------------------------------
    def setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                    borderwidth=0, rowheight=30, font=self.F(12))
        s.configure("Treeview.Heading", background=PANEL2, foreground=MUTED, relief="flat",
                    font=self.F(11, True), padding=8)
        s.map("Treeview", background=[("selected", "#1f3350")], foreground=[("selected", TEXT)])
        s.map("Treeview.Heading", background=[("active", BORDER)])
        s.configure("TCombobox", fieldbackground=PANEL2, background=PANEL2, foreground=TEXT,
                    arrowcolor=TEXT, bordercolor=BORDER, lightcolor=PANEL2, darkcolor=PANEL2)
        s.map("TCombobox", fieldbackground=[("readonly", PANEL2)], foreground=[("readonly", TEXT)])
        s.configure("Horizontal.TProgressbar", troughcolor=PANEL2, background=ACCENT,
                    bordercolor=PANEL2, lightcolor=ACCENT, darkcolor=ACCENT)
        s.configure("Horizontal.TScale", background=PANEL, troughcolor=PANEL2)
        s.configure("Vertical.TScrollbar", background=PANEL2, troughcolor=PANEL, bordercolor=PANEL,
                    arrowcolor=MUTED)
        self.root.option_add("*TCombobox*Listbox.background", PANEL2)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)

    # ---- layout --------------------------------------------------------
    def build_layout(self):
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        # sidebar
        side = tk.Frame(self.root, bg=PANEL, width=230, highlightbackground=BORDER, highlightthickness=1)
        side.grid(row=0, column=0, sticky="ns")
        side.grid_propagate(False)
        tk.Label(side, text="🛡  SENTINEL", bg=PANEL, fg=ACCENT, font=self.F(18, True)).pack(
            anchor="w", padx=22, pady=(26, 2))
        tk.Label(side, text="Security Log Analyser", bg=PANEL, fg=MUTED, font=self.F(11)).pack(
            anchor="w", padx=24, pady=(0, 28))
        self.nav = {}
        for key, label in (("overview", "◈  Overview"), ("alerts", "⚠  Alerts"),
                           ("response", "⛨  Response")):
            lbl = tk.Label(side, text=label, bg=PANEL, fg=MUTED, font=self.F(13), anchor="w",
                           padx=22, pady=11, cursor="hand2")
            lbl.pack(fill="x")
            lbl.bind("<Button-1>", lambda e, k=key: self.show_page(k))
            self.nav[key] = lbl
        tk.Label(side, text="⌘R  run scan\n⌘O  open SSH log", bg=PANEL, fg=MUTED,
                 font=self.F(10), justify="left").pack(side="bottom", anchor="w", padx=24, pady=22)

        # main
        main = tk.Frame(self.root, bg=BG)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)

        head = tk.Frame(main, bg=BG)
        head.grid(row=0, column=0, sticky="ew", padx=28, pady=(22, 10))
        self.title_lbl = tk.Label(head, text="", bg=BG, fg=TEXT, font=self.F(22, True))
        self.title_lbl.pack(side="left")
        self.status_dot = tk.Label(head, text="● IDLE", bg=BG, fg=MUTED, font=self.F(11, True))
        self.status_dot.pack(side="right")

        self.pages = {}
        body = tk.Frame(main, bg=BG)
        body.grid(row=1, column=0, sticky="nsew", padx=28)
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)
        for key in ("overview", "alerts", "response"):
            f = tk.Frame(body, bg=BG)
            f.grid(row=0, column=0, sticky="nsew")
            self.pages[key] = f
        self.build_overview(self.pages["overview"])
        self.build_alerts(self.pages["alerts"])
        self.build_response(self.pages["response"])

        # status bar
        bar = tk.Frame(main, bg=BG)
        bar.grid(row=2, column=0, sticky="ew", padx=28, pady=(8, 14))
        self.status_lbl = tk.Label(bar, text="Load log files or use the demo data to begin.",
                                   bg=BG, fg=MUTED, font=self.F(11))
        self.status_lbl.pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=160)

    def show_page(self, key):
        titles = {"overview": "Overview", "alerts": "Alerts", "response": "Response"}
        self.pages[key].tkraise()
        self.title_lbl.config(text=titles[key])
        for k, lbl in self.nav.items():
            lbl.config(fg=ACCENT if k == key else MUTED, bg=PANEL2 if k == key else PANEL)

    # ---- overview page -------------------------------------------------
    def build_overview(self, page):
        page.grid_columnconfigure((0, 1, 2), weight=1, uniform="c")
        page.grid_rowconfigure(2, weight=1)

        # scan setup
        setup = card(page)
        setup.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 14))
        setup.grid_columnconfigure(1, weight=1)
        setup.grid_columnconfigure(4, weight=1)
        pad = {"padx": 12, "pady": 8}
        for r, (label, var) in enumerate((("SSH auth log", self.ssh_path), ("Web access log", self.web_path))):
            tk.Label(setup, text=label, bg=PANEL, fg=MUTED, font=self.F(11)).grid(row=r, column=0, sticky="w", **pad)
            tk.Entry(setup, textvariable=var, bg=PANEL2, fg=TEXT, insertbackground=TEXT, relief="flat",
                     font=(self.mono, 11), highlightthickness=1, highlightbackground=BORDER,
                     highlightcolor=ACCENT).grid(row=r, column=1, sticky="ew", ipady=5, **pad)
            FlatButton(setup, "Browse", lambda v=var: self.browse(v), self.F(11), "ghost").grid(
                row=r, column=2, **pad)

        tk.Label(setup, text="Failure threshold", bg=PANEL, fg=MUTED, font=self.F(11)).grid(row=0, column=3, sticky="w", **pad)
        tk.Label(setup, text="Time window (min)", bg=PANEL, fg=MUTED, font=self.F(11)).grid(row=1, column=3, sticky="w", **pad)
        for r, (var, lo, hi) in enumerate(((self.threshold, 2, 30), (self.window, 1, 120))):
            tk.Spinbox(setup, from_=lo, to=hi, textvariable=var, width=5, bg=PANEL2, fg=TEXT,
                       buttonbackground=PANEL2, relief="flat", insertbackground=TEXT,
                       highlightthickness=1, highlightbackground=BORDER, font=self.F(12)).grid(
                row=r, column=4, sticky="w", **pad)
        btns = tk.Frame(setup, bg=PANEL)
        btns.grid(row=0, column=5, rowspan=2, padx=14)
        self.scan_btn = FlatButton(btns, "▶  Run Security Scan", self.start_scan, self.F(12, True))
        self.scan_btn.pack(fill="x", pady=(0, 6))
        FlatButton(btns, "Load demo data", self.load_demo, self.F(11), "ghost").pack(fill="x")

        # KPI cards
        kpi = tk.Frame(page, bg=BG)
        kpi.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 14))
        kpi.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="k")
        self.kpis = {}
        for i, (key, title, colour) in enumerate((
                ("events", "EVENTS ANALYSED", ACCENT), ("alerts", "ALERTS DETECTED", SEV["MEDIUM"]),
                ("critical", "CRITICAL ALERTS", SEV["CRITICAL"]), ("ips", "FLAGGED IPs", SEV["HIGH"]))):
            c = card(kpi)
            c.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 7, 0 if i == 3 else 7))
            tk.Frame(c, bg=colour, height=3).pack(fill="x")
            num = tk.Label(c, text="0", bg=PANEL, fg=colour, font=self.F(34, True))
            num.pack(anchor="w", padx=18, pady=(12, 0))
            tk.Label(c, text=title, bg=PANEL, fg=MUTED, font=self.F(10, True)).pack(anchor="w", padx=19, pady=(0, 14))
            self.kpis[key] = num

        # charts
        self.donut = self.chart_card(page, "Alerts by severity", 2, 0)
        self.timeline = self.chart_card(page, "Activity by hour of day", 2, 1)
        self.topips = self.chart_card(page, "Highest-risk IP addresses", 2, 2)
        for c, fn in ((self.donut, self.draw_donut), (self.timeline, self.draw_timeline),
                      (self.topips, self.draw_topips)):
            c.bind("<Configure>", lambda e, f=fn: f())

    def chart_card(self, page, title, row, col):
        c = card(page)
        c.grid(row=row, column=col, sticky="nsew", padx=(0 if col == 0 else 7, 0 if col == 2 else 7))
        tk.Label(c, text=title, bg=PANEL, fg=TEXT, font=self.F(12, True)).pack(anchor="w", padx=16, pady=(14, 0))
        cv = tk.Canvas(c, bg=PANEL, highlightthickness=0, height=260)
        cv.pack(fill="both", expand=True, padx=8, pady=8)
        return cv

    # ---- alerts page ---------------------------------------------------
    def build_alerts(self, page):
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)
        bar = tk.Frame(page, bg=BG)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        tk.Entry(bar, textvariable=self.search, bg=PANEL2, fg=TEXT, insertbackground=TEXT, relief="flat",
                 font=self.F(12), width=34, highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).pack(side="left", ipady=6)
        tk.Label(bar, text="  🔍 search IP, category, detail", bg=BG, fg=MUTED, font=self.F(10)).pack(side="left")
        FlatButton(bar, "Export CSV", self.export_csv, self.F(11), "ghost").pack(side="right", padx=(8, 0))
        FlatButton(bar, "Export JSON", self.export_json, self.F(11), "ghost").pack(side="right", padx=(8, 0))
        cb = ttk.Combobox(bar, textvariable=self.sev_filter, state="readonly", width=10,
                          values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        cb.pack(side="right")
        cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_table())

        wrap = card(page)
        wrap.grid(row=1, column=0, sticky="nsew")
        wrap.grid_columnconfigure(0, weight=1)
        wrap.grid_rowconfigure(0, weight=1)
        cols = (("severity", "SEVERITY", 100), ("category", "CATEGORY", 230), ("source_ip", "SOURCE IP", 140),
                ("count", "COUNT", 70), ("first_seen", "FIRST SEEN", 160), ("mitre", "ATT&CK", 90))
        self.tree = ttk.Treeview(wrap, columns=[c[0] for c in cols], show="headings", selectmode="browse")
        for key, title, w in cols:
            self.tree.heading(key, text=title, command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=w, anchor="w")
        for sev, col in SEV.items():
            self.tree.tag_configure(sev, foreground=col)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)

        det = card(page)
        det.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        self.detail = tk.Text(det, height=7, bg=PANEL, fg=TEXT, relief="flat", wrap="word", padx=16, pady=12,
                              font=self.F(12), highlightthickness=0, state="disabled")
        self.detail.pack(fill="x")
        self.detail.tag_configure("h", font=self.F(14, True))
        self.detail.tag_configure("k", foreground=MUTED, font=self.F(11, True))
        self.detail.tag_configure("fix", foreground="#7ee0a8")
        self.set_detail([("Select an alert to see details and recommended remediation.", "k")])

    def set_detail(self, parts):
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        for text, tag in parts:
            self.detail.insert("end", text, tag)
        self.detail.config(state="disabled")

    def show_detail(self, _=None):
        sel = self.tree.selection()
        if not sel:
            return
        a = self.view_alerts[int(sel[0])]
        self.detail.tag_configure("sev", foreground=SEV[a.severity], font=self.F(14, True))
        self.set_detail([
            (f"{a.severity}  ", "sev"), (f"{a.category}\n", "h"),
            ("Source: ", "k"), (f"{a.source_ip}   ", ""), ("Events: ", "k"), (f"{a.count}   ", ""),
            ("Technique: ", "k"), (f"MITRE ATT&CK {a.mitre}\n", ""),
            ("Detail: ", "k"), (f"{a.description}\n", ""),
            ("Window: ", "k"), (f"{a.first_seen} → {a.last_seen}\n", ""),
            ("Recommended action: ", "k"), (REMEDIATION.get(a.category, "Investigate this source."), "fix"),
        ])

    def sort_by(self, key):
        rev = not self.sort_state.get(key, True)
        self.sort_state = {key: rev}
        keyfn = {"severity": lambda a: la.SEVERITY_ORDER[a.severity], "count": lambda a: a.count}.get(
            key, lambda a: str(getattr(a, key)))
        self.view_alerts.sort(key=keyfn, reverse=rev)
        self.fill_tree()

    def refresh_table(self):
        q, sev = self.search.get().lower().strip(), self.sev_filter.get()
        self.view_alerts = sorted(
            [a for a in self.alerts
             if (sev == "All" or a.severity == sev)
             and (not q or q in " ".join(map(str, asdict(a).values())).lower())],
            key=lambda a: (la.SEVERITY_ORDER[a.severity], -a.count))
        self.fill_tree()

    def fill_tree(self):
        self.tree.delete(*self.tree.get_children())
        for i, a in enumerate(self.view_alerts):
            self.tree.insert("", "end", iid=str(i), tags=(a.severity,),
                             values=(a.severity, a.category, a.source_ip, a.count, a.first_seen, a.mitre))

    # ---- response page -------------------------------------------------
    def build_response(self, page):
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)
        bar = tk.Frame(page, bg=BG)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self.fw_type = tk.StringVar(value="ufw (Linux)")
        self.fw_min = tk.StringVar(value="HIGH")
        tk.Label(bar, text="Firewall", bg=BG, fg=MUTED, font=self.F(11)).pack(side="left")
        a = ttk.Combobox(bar, textvariable=self.fw_type, state="readonly", width=16,
                         values=["ufw (Linux)", "iptables (Linux)", "pf (macOS)", "netsh (Windows)"])
        a.pack(side="left", padx=(8, 18))
        tk.Label(bar, text="Flagged IPs with severity ≥", bg=BG, fg=MUTED, font=self.F(11)).pack(side="left")
        b = ttk.Combobox(bar, textvariable=self.fw_min, state="readonly", width=10,
                         values=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        b.pack(side="left", padx=8)
        for w in (a, b):
            w.bind("<<ComboboxSelected>>", lambda e: self.gen_rules())
        FlatButton(bar, "Copy", self.copy_rules, self.F(11), "ghost").pack(side="right", padx=(8, 0))
        FlatButton(bar, "Save script", self.save_rules, self.F(11), "ghost").pack(side="right")

        c = card(page)
        c.grid(row=1, column=0, sticky="nsew")
        self.rules = tk.Text(c, bg=PANEL, fg="#a5f3c4", insertbackground=TEXT, relief="flat",
                             font=(self.mono, 12), padx=18, pady=14, highlightthickness=0)
        self.rules.pack(fill="both", expand=True)
        tk.Label(page, text="⚠ Review before using any rules. Simulated IPs are not real threats. "
                            "Never auto-run unreviewed rules on your Mac or network.",
                 bg=BG, fg=MUTED, font=self.F(10)).grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.gen_rules()

    def hostile_ips(self, min_sev):
        limit = la.SEVERITY_ORDER[min_sev]
        return sorted({a.source_ip for a in self.alerts if la.SEVERITY_ORDER[a.severity] <= limit})

    def gen_rules(self):
        ips, kind = self.hostile_ips(self.fw_min.get()), self.fw_type.get()
        lines = [f"# Generated {datetime.now():%Y-%m-%d %H:%M} - {len(ips)} IP(s) at {self.fw_min.get()} or above", ""]
        if not ips:
            lines.append("# No IPs match. Run a scan first.")
        elif kind.startswith("pf"):
            lines += ["# Add to /etc/pf.conf, then: sudo pfctl -f /etc/pf.conf",
                      "table <blocklist> persist { " + ", ".join(ips) + " }",
                      "block drop in quick from <blocklist> to any"]
        else:
            for ip in ips:
                lines.append({"ufw": f"sudo ufw deny from {ip}",
                              "iptables": f"sudo iptables -A INPUT -s {ip} -j DROP",
                              "netsh": f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
                              }[kind.split()[0]])
        self.rules.delete("1.0", "end")
        self.rules.insert("1.0", "\n".join(lines) + "\n")

    def copy_rules(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.rules.get("1.0", "end"))
        self.set_status("Firewall rules copied to clipboard.")

    def save_rules(self):
        p = filedialog.asksaveasfilename(defaultextension=".sh", initialfile="block_ips.sh")
        if p:
            Path(p).write_text(self.rules.get("1.0", "end"))
            self.set_status(f"Saved {p}")

    # ---- charts --------------------------------------------------------
    def empty_msg(self, c, msg="Run a scan to see data"):
        c.create_text(c.winfo_width() / 2, c.winfo_height() / 2, text=msg, fill=MUTED, font=self.F(12))

    def draw_donut(self):
        c = self.donut
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if not self.alerts:
            return self.empty_msg(c)
        counts = Counter(a.severity for a in self.alerts)
        total = sum(counts.values())
        size = min(w * 0.55, h - 30)
        cx, cy = w / 2, h / 2 - 8
        box = (cx - size / 2, cy - size / 2, cx + size / 2, cy + size / 2)
        start = 90
        for sev in SEV:
            if counts[sev]:
                ext = -360 * counts[sev] / total
                c.create_arc(*box, start=start, extent=ext, style="arc", outline=SEV[sev], width=size * 0.16)
                start += ext
        c.create_text(cx, cy - 6, text=str(total), fill=TEXT, font=self.F(30, True))
        c.create_text(cx, cy + 22, text="ALERTS", fill=MUTED, font=self.F(10, True))
        x = cx - sum(1 for s in SEV if counts[s]) * 48
        for sev in SEV:
            if counts[sev]:
                c.create_oval(x, h - 22, x + 8, h - 14, fill=SEV[sev], outline="")
                c.create_text(x + 13, h - 18, text=f"{sev.title()} {counts[sev]}", fill=MUTED, anchor="w", font=self.F(9))
                x += 96

    def draw_timeline(self):
        c = self.timeline
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if not (self.ssh_events or self.web_reqs):
            return self.empty_msg(c)
        ssh, web = [0] * 24, [0] * 24
        for e in self.ssh_events:
            if e["kind"] == "failed":
                ssh[e["ts"].hour] += 1
        for r in self.web_reqs:
            if r["status"] >= 400:
                web[r["ts"].hour] += 1
        mx = max(max(a + b for a, b in zip(ssh, web)), 1)
        left, bottom, top = 34, 26, 22
        bw = (w - left - 10) / 24
        for i in range(5):
            y = top + (h - top - bottom) * i / 4
            c.create_line(left, y, w - 6, y, fill=BORDER)
            c.create_text(left - 6, y, text=str(round(mx * (4 - i) / 4)), fill=MUTED, anchor="e", font=self.F(9))
        for hr in range(24):
            x0 = left + hr * bw + 2
            base = h - bottom
            for val, col in ((ssh[hr], SEV["HIGH"]), (web[hr], ACCENT)):
                if val:
                    ht = (h - top - bottom) * val / mx
                    c.create_rectangle(x0, base - ht, x0 + bw - 4, base, fill=col, outline="")
                    base -= ht
            if hr % 3 == 0:
                c.create_text(x0 + bw / 2, h - 12, text=f"{hr:02d}", fill=MUTED, font=self.F(9))
        c.create_rectangle(w - 190, 6, w - 182, 14, fill=SEV["HIGH"], outline="")
        c.create_text(w - 178, 10, text="SSH failures", fill=MUTED, anchor="w", font=self.F(9))
        c.create_rectangle(w - 100, 6, w - 92, 14, fill=ACCENT, outline="")
        c.create_text(w - 88, 10, text="Web 4xx/5xx", fill=MUTED, anchor="w", font=self.F(9))

    def risk_scores(self):
        score, worst = defaultdict(int), {}
        for a in self.alerts:
            score[a.source_ip] += SEV_WEIGHT[a.severity]
            if a.source_ip not in worst or la.SEVERITY_ORDER[a.severity] < la.SEVERITY_ORDER[worst[a.source_ip]]:
                worst[a.source_ip] = a.severity
        return sorted(score.items(), key=lambda kv: -kv[1]), worst

    def draw_topips(self):
        c = self.topips
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if not self.alerts:
            return self.empty_msg(c)
        ranked, worst = self.risk_scores()
        ranked = ranked[:6]
        mx = ranked[0][1]
        rh = (h - 10) / max(len(ranked), 1)
        for i, (ip, sc) in enumerate(ranked):
            y = 8 + i * rh
            c.create_text(8, y + rh / 2 - 8, text=ip, anchor="w", fill=TEXT, font=(self.mono, 10))
            bar_w = (w - 24) * sc / mx
            c.create_rectangle(8, y + rh / 2 + 2, 8 + bar_w, y + rh / 2 + 12, fill=SEV[worst[ip]], outline="")
            c.create_text(w - 8, y + rh / 2 - 8, text=f"risk {sc}", anchor="e", fill=MUTED, font=self.F(9))

    # ---- actions -------------------------------------------------------
    def browse(self, var):
        p = filedialog.askopenfilename(title="Select log file")
        if p:
            var.set(p)

    def set_status(self, text):
        self.status_lbl.config(text=text)

    def load_demo(self):
        gen = Path(__file__).with_name("generate_sample_logs.py")
        if not gen.exists():
            return messagebox.showerror("Missing file", "generate_sample_logs.py not found next to the dashboard.")
        d = Path(tempfile.mkdtemp(prefix="sentinel_demo_"))
        subprocess.run([sys.executable, str(gen)], cwd=d, check=True, capture_output=True)
        self.ssh_path.set(str(d / "auth.log"))
        self.web_path.set(str(d / "access.log"))
        self.year.set(2026)
        self.set_status("Demo logs generated. Starting scan…")
        self.start_scan()

    def start_scan(self):
        if not (self.ssh_path.get() or self.web_path.get()):
            return messagebox.showinfo("No input", "Choose at least one log file, or click 'Load demo data'.")
        self.scan_btn.set_enabled(False)
        self.status_dot.config(text="● SCANNING", fg=SEV["MEDIUM"])
        self.progress.pack(side="right")
        self.progress.start(12)
        args = (self.ssh_path.get(), self.web_path.get(), self.threshold.get(),
                timedelta(minutes=self.window.get()), self.year.get())
        threading.Thread(target=self.scan_worker, args=args, daemon=True).start()

    def scan_worker(self, ssh, web, thr, win, year):
        """Runs off the UI thread so the window never freezes on big logs."""
        try:
            alerts, ssh_ev, web_rq = [], [], []
            if ssh:
                ssh_ev = la.parse_ssh(ssh, year)
                alerts += la.analyse_ssh(ssh_ev, thr, win)
            if web:
                web_rq = la.parse_web(web)
                alerts += la.analyse_web(web_rq, thr, win)
            self.queue.put(("ok", alerts, ssh_ev, web_rq))
        except Exception as exc:  # report any error to the UI instead of dying silently
            self.queue.put(("err", str(exc)))

    def poll_queue(self):
        try:
            msg = self.queue.get_nowait()
        except queue.Empty:
            pass
        else:
            self.progress.stop()
            self.progress.pack_forget()
            self.scan_btn.set_enabled(True)
            if msg[0] == "err":
                self.status_dot.config(text="● ERROR", fg=SEV["CRITICAL"])
                messagebox.showerror("Scan failed", msg[1])
            else:
                _, self.alerts, self.ssh_events, self.web_reqs = msg
                self.finish_scan()
        self.root.after(100, self.poll_queue)

    def finish_scan(self):
        crit = sum(a.severity == "CRITICAL" for a in self.alerts)
        self.status_dot.config(text="● CRITICAL" if crit else "● NO ALERTS" if not self.alerts else "● ALERTS",
                               fg=SEV["CRITICAL"] if crit else SEV["LOW"] if not self.alerts else SEV["MEDIUM"])
        self.animate_kpi("events", len(self.ssh_events) + len(self.web_reqs))
        self.animate_kpi("alerts", len(self.alerts))
        self.animate_kpi("critical", crit)
        self.animate_kpi("ips", len({a.source_ip for a in self.alerts}))
        self.refresh_table()
        self.gen_rules()
        for fn in (self.draw_donut, self.draw_timeline, self.draw_topips):
            fn()
        self.set_status(f"Scan complete at {datetime.now():%H:%M:%S} - {len(self.alerts)} alert(s).")

    def animate_kpi(self, key, target, step=0, steps=20):
        self.kpis[key].config(text=str(round(target * (step / steps) ** 0.5)))
        if step < steps:
            self.root.after(25, self.animate_kpi, key, target, step + 1, steps)

    def export_json(self):
        p = filedialog.asksaveasfilename(defaultextension=".json", initialfile="report.json")
        if p:
            Path(p).write_text(json.dumps([asdict(a) for a in self.alerts], indent=2))
            self.set_status(f"Exported {len(self.alerts)} alerts to {p}")

    def export_csv(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="report.csv")
        if p and self.alerts:
            with open(p, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(asdict(self.alerts[0])))
                w.writeheader()
                w.writerows(asdict(a) for a in self.alerts)
            self.set_status(f"Exported {len(self.alerts)} alerts to {p}")


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()