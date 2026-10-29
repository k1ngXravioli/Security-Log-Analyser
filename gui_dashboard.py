#!/usr/bin/env python3
"""SENTINEL // SOC — offline log analysis with an optional live file-watch map.

Uses Python's standard library and Tkinter. Geographic lookups are local-only,
from an optional MaxMind-compatible .mmdb database via the optional geoip2 package.
No network queries, live packet capture, blocking, or fake operational telemetry.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import math
import tempfile
import threading
import queue
import subprocess
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import log_analyser as engine

APP_DIR = Path(__file__).resolve().parent
BG = '#080e1a'
SIDEBAR = '#0d1525'
CARD = '#111b2c'
CARD2 = '#152236'
BORDER = '#253248'
FG = '#eff4fc'
MUTED = '#8e9db4'
BLUE = '#398cff'
CYAN = '#49c8fc'
GREEN = '#29ce92'
AMBER = '#f4a639'
ORANGE = '#ff873e'
RED = '#ff5362'
PURPLE = '#a47bff'
SEVERITIES = {'CRITICAL':RED, 'HIGH':ORANGE, 'MEDIUM':AMBER, 'LOW':CYAN}

# Reserved documentation IP addresses; fictional positions exist *only* in demo mode.
# Never use these positions to describe the actual geographic origin of a request.
DEMO_POINTS = {
    '203.0.113.77': (-74.0, 40.7, 'Demo source A'),
    '203.0.113.99': (116.4, 39.9, 'Demo source B'),
    '203.0.113.150': (77.2, 28.6, 'Demo source C'),
    '203.0.113.5': (-46.6, -23.5, 'Demo source D'),
}
DEMO_NODE = (-0.12, 51.51)  # Fictional destination for demonstration only


def public_ip(ip: str) -> bool:
    """Only public globally routable IP addresses can be locally geo-located."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def project(lon: float, lat: float, x: float, y: float, w: float, h: float) -> tuple[float,float]:
    """Equirectangular mapping for the embedded offline world outline."""
    lat = max(-85, min(85, lat))
    return x+(lon+180.0)/360.0*w, y+(85.0-lat)/170.0*h


def visible_sources(alerts, demo=False, lookup=None):
    """Return positions only when demo is explicitly enabled or lookup yields coords.

    No guess from IP string, hostname, User-Agent, or country label.
    """
    counts = Counter(a.source_ip for a in alerts)
    result = []
    for ip, count in counts.most_common():
        pos = DEMO_POINTS.get(ip) if demo else (lookup(ip) if lookup and public_ip(ip) else None)
        if pos:
            lon, lat, label = pos
            if -180 <= lon <= 180 and -90 <= lat <= 90:
                result.append((ip, count, float(lon), float(lat), str(label)))
    return result


class LocalGeoIP:
    def __init__(self):
        self.reader = None
        self.path = None

    def load(self, path):
        try:
            import geoip2.database
        except ImportError as exc:
            raise RuntimeError('Local GeoIP requires optional package: python3 -m pip install geoip2') from exc
        new_reader = geoip2.database.Reader(str(path))
        prior = self.reader
        self.reader, self.path = new_reader, Path(path)
        if prior:
            prior.close()

    def lookup(self, ip):
        if not self.reader or not public_ip(ip):
            return None
        try:
            r = self.reader.city(ip)
            if r.location.latitude is None or r.location.longitude is None:
                return None
            label = r.country.name or r.continent.name or 'Unspecified region'
            return (r.location.longitude, r.location.latitude, label)
        except Exception:
            return None

    def close(self):
        if self.reader:
            self.reader.close()
            self.reader = None


class Pill(tk.Label):
    def __init__(self, parent, label, command, *, primary=False, color=None):
        self.base = color or (BLUE if primary else CARD2)
        self.hover = '#58a4ff' if primary else '#213653'
        self.click = command
        super().__init__(parent, text=label, bg=self.base, fg='#071020' if primary else FG,
                         font=('Helvetica', 11, 'bold'), padx=17, pady=10,
                         cursor='hand2', anchor='center')
        self.bind('<Enter>', lambda _: self.config(bg=self.hover))
        self.bind('<Leave>', lambda _: self.config(bg=self.base))
        self.bind('<Button-1>', lambda _: self.click())


def panel(parent, *, bg=CARD):
    return tk.Frame(parent, bg=bg, highlightbackground=BORDER, highlightthickness=1)


def text(parent, msg, size=11, color=FG, bold=False, bg=None, **kw):
    return tk.Label(parent, text=msg, font=('Helvetica', size, 'bold' if bold else 'normal'),
                    bg=bg or parent.cget('bg'), fg=color, **kw)


class Sentinel:
    def __init__(self, root):
        self.root = root
        root.title('SENTINEL  |  Security Operations Dashboard')
        root.geometry('1536x932')
        root.minsize(1180, 730)
        root.configure(bg=BG)
        self.ssh_file = tk.StringVar()
        self.web_file = tk.StringVar()
        self.search = tk.StringVar()
        self.severity = tk.StringVar(value='ALL')
        self.year = tk.StringVar(value='2026')
        self.threshold = tk.StringVar(value='5')
        self.window = tk.StringVar(value='10')
        self.demo = False
        self.alerts, self.ssh_events, self.web_events = [], [], []
        self.geo = LocalGeoIP()
        self.live = False
        self.watch_state = {}
        self.busy = False
        self.messages = queue.Queue()
        self.coasts = self._read_coasts()
        self.active_page = 'dashboard'
        self._configure_style()
        self._build()
        self.switch('dashboard')
        self.search.trace_add('write', lambda *_: self.refresh_tables())
        root.after(150, self._poll)
        root.after(2000, self._check_files)
        root.protocol('WM_DELETE_WINDOW', self.close)

    def _configure_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Sentinel.Treeview', background=CARD, fieldbackground=CARD,
                        foreground=FG, borderwidth=0, rowheight=32, font=('Helvetica', 10))
        style.configure('Sentinel.Treeview.Heading', background=CARD2, foreground=MUTED,
                        font=('Helvetica', 10, 'bold'), borderwidth=0, padding=8)
        style.map('Sentinel.Treeview', background=[('selected', '#24476c')], foreground=[('selected',FG)])
        style.configure('Sentinel.Vertical.TScrollbar', background=CARD2, troughcolor=CARD)

    def _read_coasts(self):
        try:
            return json.loads((APP_DIR/'assets/world_coastline.json').read_text(encoding='utf-8'))
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _build(self):
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.sidebar = tk.Frame(self.root, bg=SIDEBAR, width=226, highlightthickness=1, highlightbackground=BORDER)
        self.sidebar.grid(row=0, column=0, sticky='ns')
        self.sidebar.grid_propagate(False)
        brand = tk.Frame(self.sidebar, bg=SIDEBAR)
        brand.pack(fill='x', padx=20, pady=(24,32))
        shield = tk.Canvas(brand, bg=SIDEBAR, height=49, width=46, highlightthickness=0)
        shield.pack(side='left', padx=(0,12))
        shield.create_polygon(23,3,40,10,38,29,23,44,8,29,6,10, fill='#14335d',outline=BLUE,width=2)
        shield.create_text(23,23,text='+',fill=CYAN,font=('Helvetica',25,'bold'))
        b = tk.Frame(brand,bg=SIDEBAR)
        b.pack(side='left')
        text(b,'SENTINEL',17,FG,True,bg=SIDEBAR,anchor='w').pack(anchor='w')
        text(b,'SECURITY OPERATIONS',8,MUTED,True,bg=SIDEBAR).pack(anchor='w',pady=(1,0))
        text(self.sidebar,'WORKSPACE',9,MUTED,True,bg=SIDEBAR).pack(anchor='w',padx=24,pady=(0,8))
        self.nav = {}
        for key, label in [('dashboard','▦   Dashboard'),('alerts','◉   Security alerts'),('sources','◈   Live file monitor'),('about','ⓘ   About & methods')]:
            item = tk.Label(self.sidebar,text=label,fg=MUTED,bg=SIDEBAR,font=('Helvetica',12),anchor='w',padx=19,pady=14,cursor='hand2')
            item.pack(fill='x',padx=10,pady=3)
            item.bind('<Button-1>', lambda e,k=key:self.switch(k))
            self.nav[key]=item
        tk.Frame(self.sidebar,bg=BORDER,height=1).pack(fill='x',padx=20,pady=(20,16))
        text(self.sidebar,'DATA SOURCES',9,MUTED,True,bg=SIDEBAR).pack(anchor='w',padx=22,pady=(0,6))
        self.src_label=text(self.sidebar,'● SSH logs      ○ Waiting\n● Web logs      ○ Waiting',10,MUTED,bg=SIDEBAR,justify='left')
        self.src_label.pack(anchor='w',padx=22,pady=7)
        self.left_bottom = text(self.sidebar,'OFFLINE ANALYSIS\nNo network capture\nNo IP data sent externally',9,MUTED,bg=SIDEBAR,justify='left')
        self.left_bottom.pack(side='bottom',anchor='w',padx=22,pady=30)

        self.container=tk.Frame(self.root,bg=BG)
        self.container.grid(row=0,column=1,sticky='nsew')
        self.container.grid_columnconfigure(0,weight=1)
        self.container.grid_rowconfigure(1,weight=1)
        header=tk.Frame(self.container,bg=BG,height=68)
        header.grid(row=0,column=0,sticky='ew',padx=22)
        text(header,'SECURITY OPERATIONS    /    MONITORING',10,MUTED,True,bg=BG).pack(side='left',pady=21)
        self.header_state=text(header,'●  ENGINE READY',10,GREEN,True,bg=BG)
        self.header_state.pack(side='right',pady=21)
        self.body=tk.Frame(self.container,bg=BG)
        self.body.grid(row=1,column=0,sticky='nsew',padx=22)
        self.body.grid_rowconfigure(0,weight=1)
        self.body.grid_columnconfigure(0,weight=1)
        self.pages={}
        for key in ('dashboard','alerts','sources','about'):
            self.pages[key]=tk.Frame(self.body,bg=BG)
            self.pages[key].grid(row=0,column=0,sticky='nsew')
        self._make_dashboard(self.pages['dashboard'])
        self._make_alerts(self.pages['alerts'])
        self._make_sources(self.pages['sources'])
        self._make_about(self.pages['about'])
        footer=tk.Frame(self.container,bg=BG,height=34)
        footer.grid(row=2,column=0,sticky='ew',padx=22)
        self.footer=text(footer,'Ready. Load demo data or choose local log files.',10,MUTED,bg=BG,anchor='w')
        self.footer.pack(side='left',pady=(5,10))
        text(footer,'LOCAL • PRIVATE • PYTHON',9,MUTED,True,bg=BG).pack(side='right')

    def switch(self,key):
        self.active_page=key
        self.pages[key].tkraise()
        for k,lab in self.nav.items():
            lab.config(bg='#162a47' if k==key else SIDEBAR,fg=CYAN if k==key else MUTED)
        if key=='dashboard':
            self._update_charts()
        elif key=='alerts':
            self.refresh_tables()

    def _make_dashboard(self,page):
        page.grid_columnconfigure(0,weight=1)
        page.grid_rowconfigure(2,weight=1)
        page.grid_rowconfigure(3,weight=1)
        titlebar=tk.Frame(page,bg=BG)
        titlebar.grid(row=0,column=0,sticky='ew',pady=(2,14))
        h=tk.Frame(titlebar,bg=BG)
        h.pack(side='left')
        text(h,'Security overview',24,FG,True,bg=BG).pack(anchor='w')
        text(h,'Source activity, detection patterns and geographic context',10,MUTED,bg=BG).pack(anchor='w',pady=(3,0))
        Pill(titlebar,'▶  LOAD DEMO',self.load_demo,primary=True).pack(side='right',padx=(8,0),pady=5)
        Pill(titlebar,'RUN SCAN',self.scan).pack(side='right',pady=5)
        metrics=tk.Frame(page,bg=BG)
        metrics.grid(row=1,column=0,sticky='ew',pady=(0,14))
        for i in range(5):metrics.grid_columnconfigure(i,weight=1,uniform='metric')
        self.kpi={}
        for i,(key,label,col,icon) in enumerate([
                ('events','LOG EVENTS',BLUE,'▦'),('alerts','TOTAL ALERTS',RED,'⚠'),
                ('critical','CRITICAL ALERTS',ORANGE,'◇'),('sources','FLAGGED SOURCES',PURPLE,'◈'),
                ('status','MONITOR STATUS',GREEN,'◉')]):
            c=panel(metrics)
            c.grid(row=0,column=i,sticky='ew',padx=(0,10 if i<4 else 0))
            top=tk.Frame(c,bg=CARD)
            top.pack(fill='x',padx=14,pady=(12,0))
            text(top,icon,17,col,True,bg=CARD).pack(side='left')
            text(top,label,9,MUTED,True,bg=CARD).pack(side='left',padx=9)
            number=text(c,'0' if key!='status' else 'IDLE',27,FG,True,bg=CARD,anchor='w')
            number.pack(fill='x',padx=16,pady=(1,3))
            sub=text(c,'Ready for analysis',9,MUTED,bg=CARD,anchor='w')
            sub.pack(fill='x',padx=16,pady=(0,12))
            self.kpi[key]=(number,sub)

        mid=tk.Frame(page,bg=BG)
        mid.grid(row=2,column=0,sticky='nsew',pady=(0,14))
        mid.grid_columnconfigure(0,weight=3)
        mid.grid_columnconfigure(1,weight=1)
        mid.grid_rowconfigure(0,weight=1)
        mc=panel(mid)
        mc.grid(row=0,column=0,sticky='nsew',padx=(0,12))
        mh=tk.Frame(mc,bg=CARD)
        mh.pack(fill='x',padx=17,pady=(13,0))
        text(mh,'Geographic source activity',13,FG,True,bg=CARD).pack(side='left')
        self.geo_badge=text(mh,'●  NO GEO DATA',9,AMBER,True,bg=CARD)
        self.geo_badge.pack(side='right')
        self.map_note=text(mc,'SOURCE → ANALYSIS NODE  •  ILLUSTRATIVE LINKS, NOT PACKET ROUTES',9,MUTED,bg=CARD,anchor='w')
        self.map_note.pack(fill='x',padx=17,pady=(3,0))
        self.map=tk.Canvas(mc,bg='#0e1828',highlightthickness=0,height=280,cursor='crosshair')
        self.map.pack(fill='both',expand=True,padx=12,pady=(12,7))
        self.map.bind('<Configure>',lambda _ :self.draw_map())
        self.geo_footer=text(mc,'Load demo data, or open a local GeoIP database for public IP locations.',9,MUTED,bg=CARD,anchor='w')
        self.geo_footer.pack(fill='x',padx=17,pady=(0,10))

        right=tk.Frame(mid,bg=BG)
        right.grid(row=0,column=1,sticky='nsew')
        right.grid_rowconfigure(0,weight=3)
        right.grid_rowconfigure(1,weight=2)
        right.grid_columnconfigure(0,weight=1)
        dc=panel(right)
        dc.grid(row=0,column=0,sticky='nsew',pady=(0,12))
        text(dc,'Alert distribution',13,FG,True,bg=CARD).pack(anchor='w',padx=16,pady=(12,0))
        self.donut=tk.Canvas(dc,bg=CARD,height=185,highlightthickness=0)
        self.donut.pack(fill='both',expand=True,padx=8,pady=6)
        self.donut.bind('<Configure>',lambda _ : self.draw_donut())
        status=panel(right)
        status.grid(row=1,column=0,sticky='nsew')
        text(status,'System status',13,FG,True,bg=CARD).pack(anchor='w',padx=16,pady=(11,8))
        self.system_lines={}
        for label in ('Detection engine','Geolocation','Local file watch'):
            rr=tk.Frame(status,bg=CARD)
            rr.pack(fill='x',padx=16,pady=5)
            text(rr,label,10,MUTED,bg=CARD).pack(side='left')
            txt=text(rr,'READY' if label=='Detection engine' else 'OFF',10,GREEN if label=='Detection engine' else MUTED,True,bg=CARD)
            txt.pack(side='right')
            self.system_lines[label]=txt

        bottom=tk.Frame(page,bg=BG)
        bottom.grid(row=3,column=0,sticky='nsew',pady=(0,0))
        bottom.grid_columnconfigure(0,weight=3)
        bottom.grid_columnconfigure(1,weight=1)
        bottom.grid_rowconfigure(0,weight=1)
        recent=panel(bottom)
        recent.grid(row=0,column=0,sticky='nsew',padx=(0,12))
        th=tk.Frame(recent,bg=CARD)
        th.pack(fill='x',padx=14,pady=(11,7))
        text(th,'Recent detections',13,FG,True,bg=CARD).pack(side='left')
        tk.Label(th,text='View all  →',fg=CYAN,bg=CARD,font=('Helvetica',10,'bold'),cursor='hand2').pack(side='right')
        th.winfo_children()[-1].bind('<Button-1>',lambda _ :self.switch('alerts'))
        columns=('severity','category','source','events')
        self.recent=self._table(recent,columns,('SEVERITY','DETECTION','SOURCE IP','EVENTS'),(95,280,145,65))
        self.recent[0].pack(fill='both',expand=True,padx=12,pady=(0,12))
        sources=panel(bottom)
        sources.grid(row=0,column=1,sticky='nsew')
        text(sources,'Top flagged sources',13,FG,True,bg=CARD).pack(anchor='w',padx=15,pady=(12,6))
        self.source_canvas=tk.Canvas(sources,bg=CARD,highlightthickness=0,height=150)
        self.source_canvas.pack(fill='both',expand=True,padx=12,pady=(0,8))
        self.source_canvas.bind('<Configure>',lambda _ :self.draw_source_bars())

    def _table(self,parent,cols,titles,widths):
        wrapper=tk.Frame(parent,bg=CARD)
        wrapper.grid_rowconfigure(0,weight=1)
        wrapper.grid_columnconfigure(0,weight=1)
        tree=ttk.Treeview(wrapper,columns=cols,show='headings',style='Sentinel.Treeview',selectmode='browse',height=5)
        for name,title,w in zip(cols,titles,widths):
            tree.heading(name,text=title)
            tree.column(name,width=w,minwidth=55,stretch=name in ('category','detail'),anchor='w')
        tree.grid(row=0,column=0,sticky='nsew')
        scr=ttk.Scrollbar(wrapper,orient='vertical',command=tree.yview)
        scr.grid(row=0,column=1,sticky='ns')
        tree.configure(yscrollcommand=scr.set)
        for s,c in SEVERITIES.items():tree.tag_configure(s,foreground=c)
        return wrapper,tree

    def _make_alerts(self,page):
        page.grid_columnconfigure(0,weight=1)
        page.grid_rowconfigure(2,weight=1)
        title=tk.Frame(page,bg=BG)
        title.grid(row=0,column=0,sticky='ew',pady=(2,15))
        text(title,'Security alerts',24,FG,True,bg=BG).pack(side='left')
        Pill(title,'EXPORT JSON',lambda :self.export('json')).pack(side='right',padx=(8,0))
        Pill(title,'EXPORT CSV',lambda :self.export('csv')).pack(side='right')
        toolbar=panel(page)
        toolbar.grid(row=1,column=0,sticky='ew',pady=(0,12))
        text(toolbar,'SEARCH',9,MUTED,True,bg=CARD).pack(side='left',padx=(14,9))
        tk.Entry(toolbar,textvariable=self.search,bg=CARD2,fg=FG,insertbackground=FG,font=('Helvetica',11),
                 relief='flat',width=36,highlightthickness=1,highlightbackground=BORDER).pack(side='left',padx=(0,15),pady=10,ipady=6)
        text(toolbar,'SEVERITY',9,MUTED,True,bg=CARD).pack(side='left',padx=(0,9))
        cb=ttk.Combobox(toolbar,textvariable=self.severity,state='readonly',width=11,
                        values=('ALL','CRITICAL','HIGH','MEDIUM','LOW'))
        cb.pack(side='left')
        cb.bind('<<ComboboxSelected>>',lambda _ :self.refresh_tables())
        self.count_alerts=text(toolbar,'0 detections',10,MUTED,bg=CARD)
        self.count_alerts.pack(side='right',padx=15)
        box=panel(page)
        box.grid(row=2,column=0,sticky='nsew')
        wrap,self.full_tree=self._table(box,('severity','category','source','count','seen','mitre'),
                                         ('SEVERITY','DETECTION','SOURCE IP','EVENTS','FIRST SEEN','ATT&CK'),
                                         (110,310,158,65,180,80))
        wrap.pack(fill='both',expand=True,padx=12,pady=12)
        self.full_tree.bind('<<TreeviewSelect>>',self.show_detail)
        detail_box=panel(page)
        detail_box.grid(row=3,column=0,sticky='ew',pady=(12,0))
        self.detail=text(detail_box,'Select a detection to see its evidence and MITRE context.',11,MUTED,bg=CARD,
                         justify='left',anchor='w',wraplength=1000)
        self.detail.pack(fill='x',padx=18,pady=16)

    def _make_sources(self,page):
        page.grid_columnconfigure(0,weight=1)
        text(page,'Data sources & live file watch',24,FG,True,bg=BG).grid(row=0,column=0,sticky='w',pady=(3,8))
        text(page,'Watches local files for changes — no packet capture, external connections or automatic blocking.',
             11,MUTED,bg=BG).grid(row=1,column=0,sticky='w',pady=(0,15))
        pane=panel(page)
        pane.grid(row=2,column=0,sticky='ew')
        pane.grid_columnconfigure(1,weight=1)
        for i,(title,var) in enumerate((('SSH AUTH LOG',self.ssh_file),('WEB ACCESS LOG',self.web_file))):
            text(pane,title,10,MUTED,True,bg=CARD).grid(row=i,column=0,sticky='w',padx=18,pady=16)
            tk.Entry(pane,textvariable=var,fg=FG,bg=CARD2,insertbackground=FG,relief='flat',font=('Menlo',10),
                     highlightthickness=1,highlightbackground=BORDER).grid(row=i,column=1,sticky='ew',pady=12,ipady=7)
            Pill(pane,'BROWSE',lambda v=var:self.browse(v)).grid(row=i,column=2,padx=14)
        options=panel(page)
        options.grid(row=3,column=0,sticky='ew',pady=13)
        for i,(title,var) in enumerate((('FAILED LOGIN THRESHOLD',self.threshold),('TIME WINDOW (MIN)',self.window),('SSH LOG YEAR',self.year))):
            cell=tk.Frame(options,bg=CARD)
            cell.pack(side='left',padx=18,pady=18)
            text(cell,title,9,MUTED,True,bg=CARD).pack(anchor='w')
            tk.Entry(cell,textvariable=var,bg=CARD2,fg=FG,insertbackground=FG,relief='flat',width=10,
                     font=('Helvetica',12),highlightthickness=1,highlightbackground=BORDER).pack(anchor='w',pady=(8,0),ipady=6)
        controls=tk.Frame(page,bg=BG)
        controls.grid(row=4,column=0,sticky='ew',pady=(3,15))
        Pill(controls,'▶  RUN SECURITY SCAN',self.scan,primary=True).pack(side='left',padx=(0,10))
        self.watch_btn=Pill(controls,'ENABLE FILE WATCH',self.toggle_watch)
        self.watch_btn.pack(side='left',padx=(0,10))
        Pill(controls,'LOAD DEMO DATA',self.load_demo).pack(side='left')
        geo_frame=panel(page)
        geo_frame.grid(row=5,column=0,sticky='ew')
        text(geo_frame,'GEOGRAPHIC SOURCE LOOKUPS  •  OPTIONAL',11,FG,True,bg=CARD).pack(anchor='w',padx=18,pady=(18,6))
        text(geo_frame,'Import a local GeoLite2-City .mmdb database to place public source IPs on the world map.\n'
             'Install optional dependency: python3 -m pip install geoip2. All lookups stay on your Mac.\n'
             'Private IPs and unknown locations are never guessed. Demo locations are entirely illustrative.',
             11,MUTED,bg=CARD,justify='left').pack(anchor='w',padx=18)
        Pill(geo_frame,'LOAD LOCAL .MMDB DATABASE',self.load_geo).pack(anchor='w',padx=18,pady=18)
        self.geo_name=text(geo_frame,'GeoIP location database: not configured',10,MUTED,bg=CARD)
        self.geo_name.pack(anchor='w',padx=18,pady=(0,16))

    def _make_about(self,page):
        text(page,'About SENTINEL',24,FG,True,bg=BG).pack(anchor='w',pady=(4,15))
        p=panel(page)
        p.pack(fill='x')
        content=(
            'SENTINEL is an offline defensive-security learning project. It parses SSH authentication\n'
            'and web access logs, then looks for suspicious activity using rules and time-window analysis.\n\n'
            'THE WORLD MAP\n'
            '• Demo mode uses explicitly invented example positions for reserved documentation IPs.\n'
            '• Real logs only appear geographically with a locally provided GeoIP database.\n'
            '• Arcs connect mapped sources to a *visual analysis node*. They are NOT observed network flows.\n'
            '• Approximate GeoIP locations do not identify an attacker or prove an incident.\n\n'
            'THE LIVE MONITOR\n'
            '• Watches selected local files for updates and reruns the existing detection engine.\n'
            '• Does not capture packets, connect to hosts, or perform real-time network surveillance.\n'
            '• Does not send log contents or IP addresses to third-party services.\n\n'
            'Supported: Python 3.10+, Tkinter; optional local geoip2 + GeoLite2-City .mmdb.\n'
            'Data source: user-supplied logs or generated synthetic examples.\n'
            'Map coastlines: Natural Earth-derived, simplified for offline rendering.\n'
            'Alerts are triage indicators, not verified security incidents.'
        )
        text(p,content,12,FG,bg=CARD,justify='left',anchor='nw').pack(anchor='w',padx=26,pady=26)

    def browse(self,var):
        p=filedialog.askopenfilename(title='Select a log file (local only)')
        if p:
            var.set(p)
            self.demo=False
            self.draw_map()

    def load_geo(self):
        p=filedialog.askopenfilename(title='Open a local GeoIP2 City MMDB database',filetypes=[('GeoIP database','*.mmdb'),('All files','*')])
        if p:
            try:self.geo.load(p)
            except Exception as exc:messagebox.showerror('Local geolocation unavailable',str(exc));return
            self.geo_name.config(text=f'GeoIP database: {Path(p).name}')
            self.draw_map()
            self._update_status()

    def load_demo(self):
        gen=APP_DIR/'generate_sample_logs.py'
        if not gen.is_file():
            messagebox.showerror('Demo unavailable','Missing generate_sample_logs.py.');return
        # Generate only into a new temporary directory; never overwrite the user's real logs.
        dest=Path(tempfile.mkdtemp(prefix='sentinel_demo_'))
        try:subprocess.run([sys.executable,str(gen)],cwd=dest,check=True,capture_output=True,timeout=15)
        except Exception as exc:messagebox.showerror('Demo failed',str(exc));return
        self.ssh_file.set(str(dest/'auth.log'))
        self.web_file.set(str(dest/'access.log'))
        self.year.set('2026')
        self.demo=True
        self.scan()

    def scan(self):
        ssh=self.ssh_file.get().strip()
        web=self.web_file.get().strip()
        if not ssh and not web:
            messagebox.showinfo('Choose data','Select a local SSH or web log, or load demo data.');return
        if self.busy:return
        try:
            threshold=int(self.threshold.get())
            window=int(self.window.get())
            year=int(self.year.get())
            if threshold<=0 or window<=0 or not 1970<=year<=2200:raise ValueError()
        except ValueError:
            messagebox.showerror('Invalid scan settings','Use a positive threshold and window; enter a valid year.');return
        self.busy=True
        self.header_state.config(text='●  ANALYSING LOGS',fg=AMBER)
        self.footer.config(text='Parsing and analysing local files...')
        threading.Thread(target=self._worker,args=(ssh,web,threshold,window,year),daemon=True).start()

    def _worker(self,ssh,web,threshold,window,year):
        try:
            s=engine.parse_ssh(ssh,year) if ssh else []
            w=engine.parse_web(web) if web else []
            alerts=(engine.analyse_ssh(s,threshold,timedelta(minutes=window))+
                    engine.analyse_web(w,threshold,timedelta(minutes=window)))
            alerts.sort(key=lambda a:(engine.SEVERITY_ORDER[a.severity],-a.count))
            self.messages.put(('result',(s,w,alerts)))
        except Exception as exc:
            self.messages.put(('error',str(exc)))

    def _poll(self):
        try:
            while True:
                k,contents=self.messages.get_nowait()
                self.busy=False
                if k=='error':
                    self.header_state.config(text='●  SCAN ERROR',fg=RED)
                    self.footer.config(text='Scan error — check the selected input files.')
                    messagebox.showerror('Scan failed',contents)
                else:
                    self.ssh_events,self.web_events,self.alerts=contents
                    self._update_status()
                    self._update_charts()
                    self.refresh_tables()
        except queue.Empty:pass
        self.root.after(150,self._poll)

    def _update_status(self):
        total=len(self.ssh_events)+len(self.web_events)
        counts=Counter(a.severity for a in self.alerts)
        flagged=len({a.source_ip for a in self.alerts})
        for key,num,sub in (
             ('events',str(total),'Parsed SSH + web records'),
             ('alerts',str(len(self.alerts)),'Detection findings'),
             ('critical',str(counts['CRITICAL']),'Requires investigation'),
             ('sources',str(flagged),'Distinct flagged IPs'),
             ('status','WATCHING' if self.live else 'READY','Local file watch' if self.live else 'Manual scans')):
            lbl,desc=self.kpi[key]
            lbl.config(text=num)
            desc.config(text=sub)
        self.system_lines['Geolocation'].config(text='LOCAL DB' if self.geo.reader else ('DEMO ONLY' if self.demo else 'OFF'),
                                                fg=GREEN if self.geo.reader else AMBER if self.demo else MUTED)
        self.system_lines['Local file watch'].config(text='ON' if self.live else 'OFF',fg=GREEN if self.live else MUTED)
        self.src_label.config(text=f'● SSH logs      {"READY" if self.ssh_file.get() else "WAITING"}\n'
                                  f'● Web logs      {"READY" if self.web_file.get() else "WAITING"}')
        self.header_state.config(text='●  ENGINE READY',fg=GREEN)
        self.footer.config(text=f'Parsed {total} log records • {len(self.alerts)} alerts • '
                                 +('Synthetic demo' if self.demo else 'Local files'))

    def _update_charts(self):
        self.draw_map();self.draw_donut();self.draw_source_bars()
        self.recent[1].delete(*self.recent[1].get_children())
        for a in self.alerts[:8]:
            self.recent[1].insert('', 'end', values=(a.severity,a.category,a.source_ip,a.count),tags=(a.severity,))

    def draw_map(self):
        c=self.map
        c.delete('all')
        w,h=c.winfo_width(),c.winfo_height()
        if w<50 or h<50:return
        margin=12
        mx,my=margin+8,14
        mw,mh=w-2*(margin+8),h-42
        # Geographic graticule and world coastline (bundled Natural Earth-derived outline).
        for lon in range(-150,180,30):
            x,_=project(lon,0,mx,my,mw,mh)
            c.create_line(x,my,x,my+mh,fill='#17283e',width=1)
        for lat in (-60,-30,0,30,60):
            _,y=project(0,lat,mx,my,mw,mh)
            c.create_line(mx,y,mx+mw,y,fill='#17283e',width=1)
        for seg in self.coasts:
            if len(seg)<2:continue
            flattened=[]
            for lon,lat in seg:
                x,y=project(lon,lat,mx,my,mw,mh)
                flattened += [x,y]
            if len(flattened)>=4:
                c.create_line(*flattened,fill='#34475d',width=1.05,smooth=False)
        places=visible_sources(self.alerts,self.demo,self.geo.lookup)
        if self.demo:
            self.geo_badge.config(text='●  SIMULATED POSITIONS',fg=AMBER)
            self.geo_footer.config(text='Example positions are fictional. Hover on source dots for details.')
        elif self.geo.reader:
            self.geo_badge.config(text='●  LOCAL GEOIP ESTIMATES',fg=GREEN)
            self.geo_footer.config(text=f'{len(places)} source(s) mapped using a local database; unknown locations omitted.')
        else:
            self.geo_badge.config(text='●  GEOLOCATION NOT CONFIGURED',fg=MUTED)
            self.geo_footer.config(text='Real IPs are not guessed. Load an optional local GeoIP database to plot them.')
        if not places:
            c.create_text(w/2,h/2,text='NO VERIFIED SOURCE LOCATIONS',fill=FG,font=('Helvetica',15,'bold'))
            c.create_text(w/2,h/2+27,text='Load demo data or a local GeoIP database',fill=MUTED,font=('Helvetica',11))
            return
        node=project(*DEMO_NODE,mx,my,mw,mh)
        # Analysis-node arcs are links between visual indicators, not actual network routes.
        nx,ny=node
        for idx,(ip,count,lon,lat,label) in enumerate(places):
            sx,sy=project(lon,lat,mx,my,mw,mh)
            dx=nx-sx
            dy=ny-sy
            # Quadratic Bezier, curved upwards; make shallow curves at short distances.
            cx=(nx+sx)/2
            cy=(ny+sy)/2-max(18,min(85,abs(dx)*0.16))
            points=[]
            for i in range(41):
                t=i/40
                px=(1-t)**2*sx+2*(1-t)*t*cx+t*t*nx
                py=(1-t)**2*sy+2*(1-t)*t*cy+t*t*ny
                points.extend((px,py))
            for thick,color in [(5,'#293343'),(1.7,RED if count>1 else ORANGE)]:
                c.create_line(*points,fill=color,width=thick,smooth=False)
            r=5+min(count,8)*0.5
            marker = f'marker_{idx}'
            c.create_oval(sx-r-5,sy-r-5,sx+r+5,sy+r+5,outline='#4c2537',width=2,tags=(marker,))
            c.create_oval(sx-r,sy-r,sx+r,sy+r,fill=RED,outline='#ffc5bd',width=1,tags=(marker,))
            info=f'{ip} • {count} alert(s) • {label}'+(' • FICTIONAL DEMO' if self.demo else ' • GEOIP ESTIMATE')
            c.tag_bind(marker,'<Enter>',lambda _e,v=info:self.geo_footer.config(text=v))
            c.tag_bind(marker,'<Leave>',lambda _e:self._reset_geo_footer())
        c.create_oval(nx-7,ny-7,nx+7,ny+7,fill=BLUE,outline='#9bd0ff',width=2)
        c.create_text(nx,ny+18,text='ANALYSIS NODE',fill=CYAN,font=('Helvetica',8,'bold'))
        c.create_text(w-15,h-9,text='HOVER A SOURCE DOT  •  NO PACKET CAPTURE',anchor='e',fill=MUTED,font=('Helvetica',8))

    def _reset_geo_footer(self):
        if self.demo:
            self.geo_footer.config(text='Example positions are fictional. Hover on source dots for details.')
        elif self.geo.reader:
            self.geo_footer.config(text='Local GeoIP estimates • unknown locations omitted • hover source dots')
        else:
            self.geo_footer.config(text='Load an optional local GeoIP database for public IP coordinates.')

    def draw_donut(self):
        c=self.donut
        c.delete('all')
        w,h=c.winfo_width(),c.winfo_height()
        if w<50 or h<50:return
        counts=Counter(a.severity for a in self.alerts)
        total=sum(counts.values())
        size=min(h-28,w*0.43,150)
        left=max(14,w*.08)
        top=(h-size)/2
        if total:
            ang=90
            for sev in ('CRITICAL','HIGH','MEDIUM','LOW'):
                count=counts[sev]
                if count:
                    ext=-360*count/total
                    c.create_arc(left,top,left+size,top+size,start=ang,extent=ext,
                                 style='arc',width=17,outline=SEVERITIES[sev])
                    ang+=ext
        else:
            c.create_arc(left,top,left+size,top+size,start=0,extent=359.9,style='arc',width=17,outline=BORDER)
        cx=left+size/2
        c.create_text(cx,top+size/2-10,text=str(total),font=('Helvetica',24,'bold'),fill=FG)
        c.create_text(cx,top+size/2+15,text='TOTAL ALERTS',font=('Helvetica',8,'bold'),fill=MUTED)
        x=left+size+23
        y=h/2-50
        for sev in ('CRITICAL','HIGH','MEDIUM','LOW'):
            c.create_oval(x,y,x+8,y+8,fill=SEVERITIES[sev],outline='')
            c.create_text(x+14,y+4,text=sev.title(),fill=MUTED,anchor='w',font=('Helvetica',9))
            c.create_text(w-16,y+4,text=str(counts[sev]),fill=FG,anchor='e',font=('Helvetica',10,'bold'))
            y+=29

    def draw_source_bars(self):
        c=self.source_canvas;c.delete('all')
        w,h=c.winfo_width(),c.winfo_height()
        if w<100 or h<70:return
        counts=Counter(a.source_ip for a in self.alerts)
        if not counts:
            c.create_text(w/2,h/2,text='NO ALERTS TO DISPLAY',fill=MUTED,font=('Helvetica',10))
            return
        top=counts.most_common(5)
        maxv=top[0][1]
        rh=max(31,(h-10)/len(top))
        for i,(ip,n) in enumerate(top):
            y=8+i*rh
            c.create_text(4,y,text=ip,anchor='nw',fill=FG,font=('Menlo',10))
            c.create_text(w-8,y,text=f'{n} alerts',anchor='ne',fill=MUTED,font=('Helvetica',9))
            c.create_rectangle(4,y+21,w-12,y+28,fill=CARD2,outline='')
            c.create_rectangle(4,y+21,4+(w-16)*n/maxv,y+28,fill=BLUE if i>0 else RED,outline='')

    def refresh_tables(self):
        if not hasattr(self,'full_tree'):return
        q=self.search.get().lower().strip()
        sel=self.severity.get()
        filtered=[a for a in self.alerts if (sel=='ALL' or a.severity==sel) and
                  (not q or q in ' '.join(str(v) for v in asdict(a).values()).lower())]
        self.filtered=filtered
        self.full_tree.delete(*self.full_tree.get_children())
        for i,a in enumerate(filtered):
            self.full_tree.insert('','end',iid=str(i),tags=(a.severity,),values=(a.severity,a.category,a.source_ip,a.count,a.first_seen,a.mitre))
        self.count_alerts.config(text=f'{len(filtered)} detections')

    def show_detail(self,event=None):
        s=self.full_tree.selection()
        if not s:return
        a=self.filtered[int(s[0])]
        self.detail.config(text=f'{a.severity}  /  {a.category}  |  {a.source_ip}  |  {a.count} events\n'
                                f'{a.description}\n{a.first_seen} → {a.last_seen}  •  MITRE ATT&CK {a.mitre}',fg=FG)

    def export(self,typ):
        if not self.alerts:
            messagebox.showinfo('Nothing to export','Load demo data or run a scan first.');return
        path=filedialog.asksaveasfilename(defaultextension='.'+typ,filetypes=[(typ.upper(),'*.'+typ)])
        if not path:return
        data=[asdict(a) for a in self.alerts]
        try:
            if typ=='json':Path(path).write_text(json.dumps(data,indent=2),encoding='utf-8')
            else:
                with open(path,'w',newline='',encoding='utf-8') as out:
                    wr=csv.DictWriter(out,fieldnames=data[0].keys())
                    wr.writeheader();wr.writerows(data)
            self.footer.config(text=f'Exported {len(data)} alerts to {Path(path).name}')
        except OSError as exc:messagebox.showerror('Export failed',str(exc))

    def toggle_watch(self):
        if not (self.ssh_file.get() or self.web_file.get()):
            messagebox.showinfo('No sources','Choose a log first, or load demo data.');return
        self.live=not self.live
        self.watch_btn.config(text='DISABLE FILE WATCH' if self.live else 'ENABLE FILE WATCH',
                              bg=GREEN if self.live else CARD2,fg=BG if self.live else FG)
        self.watch_state=self._file_state()
        self._update_status()

    def _file_state(self):
        state={}
        for path in (self.ssh_file.get().strip(),self.web_file.get().strip()):
            if path:
                try:
                    st=Path(path).stat()
                    state[path]=(st.st_mtime_ns,st.st_size)
                except OSError:state[path]=None
        return state

    def _check_files(self):
        if self.live and not self.busy:
            current=self._file_state()
            if current!=self.watch_state:
                self.watch_state=current
                self.scan()
        self.root.after(1500,self._check_files)

    def close(self):
        self.live=False
        self.geo.close()
        self.root.destroy()


def main():
    root=tk.Tk()
    Sentinel(root)
    root.mainloop()


if __name__=='__main__':
    main()