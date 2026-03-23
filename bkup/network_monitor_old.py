"""
Home Network Guardian - Family Network Monitor
Requires: pip install psutil scapy requests
Run as Administrator for full packet capture capabilities.
"""

import tkinter as tk
from tkinter import ttk, messagebox, font
import psutil
import threading
import time
import socket
import json
import collections
from datetime import datetime
import subprocess
import sys
import os

# ── Attempt optional imports ──────────────────────────────────────────────────
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Color Palette ─────────────────────────────────────────────────────────────
BG        = "#0d1117"
PANEL     = "#161b22"
BORDER    = "#30363d"
ACCENT    = "#58a6ff"
ACCENT2   = "#3fb950"
WARN      = "#d29922"
DANGER    = "#f85149"
TEXT      = "#e6edf3"
TEXT_DIM  = "#8b949e"
TEXT_DARK = "#484f58"

# ── Thresholds ────────────────────────────────────────────────────────────────
ALERT_CONN_COUNT   = 50    # connections per device before warning
ALERT_BYTES_MB_MIN = 50    # MB/min upload before warning
SUSPICIOUS_PORTS   = {
    4444, 1337, 6667, 31337, 12345, 9999, 8080, 3389,
    5900, 23, 135, 139, 445,
}
KNOWN_GOOD_PORTS   = {80, 443, 53, 123, 67, 68, 5353}

# ── Helpers ───────────────────────────────────────────────────────────────────
def format_bytes(b):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip

def severity_color(level):
    return {0: ACCENT2, 1: WARN, 2: DANGER}.get(level, TEXT_DIM)

# ── Alert Model ───────────────────────────────────────────────────────────────
class Alert:
    def __init__(self, level, title, detail, ip=""):
        self.ts     = datetime.now().strftime("%H:%M:%S")
        self.level  = level          # 0=info 1=warn 2=danger
        self.title  = title
        self.detail = detail
        self.ip     = ip
        self.icons  = ["ℹ", "⚠", "🔴"]

    def label(self):
        return f"{self.icons[self.level]}  [{self.ts}]  {self.title}"

# ── Core Monitor ──────────────────────────────────────────────────────────────
class NetworkMonitor:
    def __init__(self):
        self.running       = False
        self.alerts        = []
        self.connections   = {}      # ip → {count, ports, bytes_sent, first_seen}
        self.prev_counters = {}
        self.net_snapshot  = None
        self.lock          = threading.Lock()
        self.on_update     = None    # callback

    def start(self):
        self.running = True
        self.net_snapshot = psutil.net_io_counters(pernic=False)
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            self._poll()
            time.sleep(3)

    def _poll(self):
        new_conns = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            conns = []

        for c in conns:
            if not c.raddr:
                continue
            ip   = c.raddr.ip
            port = c.raddr.port
            if ip.startswith("127.") or ip == "::1":
                continue

            if ip not in new_conns:
                new_conns[ip] = {"count": 0, "ports": set(), "lports": set()}
            new_conns[ip]["count"]  += 1
            new_conns[ip]["ports"].add(port)
            if c.laddr:
                new_conns[ip]["lports"].add(c.laddr.port)

        # Network I/O delta
        cur = psutil.net_io_counters(pernic=False)
        prev = self.net_snapshot
        sent_delta = (cur.bytes_sent - prev.bytes_sent) if prev else 0
        recv_delta = (cur.bytes_recv - prev.bytes_recv) if prev else 0
        self.net_snapshot = cur

        # Per-process top talkers
        proc_data = []
        for proc in psutil.process_iter(["pid", "name", "connections"]):
            try:
                pconns = proc.connections(kind="inet")
                remote_ips = [c.raddr.ip for c in pconns if c.raddr]
                if remote_ips:
                    proc_data.append({
                        "pid":  proc.pid,
                        "name": proc.info["name"],
                        "conn_count": len(remote_ips),
                        "ips": remote_ips,
                    })
            except Exception:
                pass

        with self.lock:
            self.connections  = new_conns
            self.sent_delta   = sent_delta
            self.recv_delta   = recv_delta
            self.proc_data    = proc_data
            self._check_alerts(new_conns, sent_delta)

        if self.on_update:
            self.on_update()

    def _check_alerts(self, conns, sent_delta):
        # High connection count
        for ip, data in conns.items():
            if data["count"] >= ALERT_CONN_COUNT:
                self._add_alert(Alert(2, f"High connection count: {ip}",
                    f"{data['count']} simultaneous connections detected.", ip))

        # Suspicious ports
        for ip, data in conns.items():
            bad = data["ports"] & SUSPICIOUS_PORTS
            if bad:
                self._add_alert(Alert(2, f"Suspicious port(s) contacted: {ip}",
                    f"Ports: {', '.join(str(p) for p in bad)}", ip))

        # High upload
        mb_per_min = (sent_delta / 3) / (1024*1024) * 60
        if mb_per_min > ALERT_BYTES_MB_MIN:
            self._add_alert(Alert(1, "High upload rate detected",
                f"{mb_per_min:.1f} MB/min upload — possible data exfiltration."))

    def _add_alert(self, alert):
        # Deduplicate by title in last 30 seconds
        now = datetime.now()
        for a in self.alerts[-20:]:
            if a.title == alert.title:
                return
        self.alerts.insert(0, alert)
        self.alerts = self.alerts[:200]

    def snapshot(self):
        with self.lock:
            return (
                dict(self.connections),
                getattr(self, "sent_delta", 0),
                getattr(self, "recv_delta", 0),
                list(getattr(self, "proc_data", [])),
                list(self.alerts),
            )

# ── GUI ───────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Home Network Guardian")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(bg=BG)
        self.resizable(True, True)

        self.monitor = NetworkMonitor()
        self.monitor.on_update = self._schedule_refresh

        self._build_ui()
        self.monitor.start()
        self._refresh()

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=PANEL, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="🛡  Home Network Guardian", bg=PANEL, fg=TEXT,
                 font=("Consolas", 16, "bold")).pack(side="left", padx=20, pady=12)

        self.status_lbl = tk.Label(hdr, text="● MONITORING", bg=PANEL, fg=ACCENT2,
                                   font=("Consolas", 10, "bold"))
        self.status_lbl.pack(side="left", padx=10)

        self.clock_lbl = tk.Label(hdr, text="", bg=PANEL, fg=TEXT_DIM,
                                  font=("Consolas", 10))
        self.clock_lbl.pack(side="right", padx=20)

        # Stats bar
        stats = tk.Frame(self, bg=BG, pady=8)
        stats.pack(fill="x", padx=16)

        self.stat_frames = {}
        for key, label in [
            ("devices",  "Active Devices"),
            ("conns",    "Connections"),
            ("upload",   "Upload/s"),
            ("download", "Download/s"),
            ("alerts",   "Alerts"),
        ]:
            f = self._stat_card(stats, label, "—")
            f.pack(side="left", padx=6, pady=4)
            self.stat_frames[key] = f

        # Main panels
        body = tk.PanedWindow(self, orient="horizontal", bg=BG,
                              sashwidth=6, sashrelief="flat")
        body.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        left = tk.Frame(body, bg=BG)
        right = tk.Frame(body, bg=BG)
        body.add(left,  minsize=380)
        body.add(right, minsize=300)

        # Left: connection table + process list
        self._build_conn_panel(left)
        self._build_proc_panel(left)

        # Right: alerts
        self._build_alert_panel(right)

    def _stat_card(self, parent, label, value):
        f = tk.Frame(parent, bg=PANEL, padx=16, pady=8,
                     highlightthickness=1, highlightbackground=BORDER)
        tk.Label(f, text=label, bg=PANEL, fg=TEXT_DIM,
                 font=("Consolas", 8)).pack(anchor="w")
        val_lbl = tk.Label(f, text=value, bg=PANEL, fg=TEXT,
                           font=("Consolas", 14, "bold"))
        val_lbl.pack(anchor="w")
        f._val_lbl = val_lbl
        return f

    def _build_conn_panel(self, parent):
        tk.Label(parent, text="  ACTIVE CONNECTIONS", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 9, "bold"), anchor="w").pack(fill="x", pady=(4, 2))

        cols = ("IP Address", "Conns", "Ports (sample)", "Status")
        self.conn_tree = self._make_tree(parent, cols, height=12)
        self.conn_tree.pack(fill="both", expand=True, padx=2)

    def _build_proc_panel(self, parent):
        tk.Label(parent, text="  TOP PROCESSES BY CONNECTIONS", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 9, "bold"), anchor="w").pack(fill="x", pady=(8, 2))

        cols = ("Process", "PID", "Connections")
        self.proc_tree = self._make_tree(parent, cols, height=6)
        self.proc_tree.pack(fill="both", expand=True, padx=2)

    def _build_alert_panel(self, parent):
        hdr = tk.Frame(parent, bg=BG)
        hdr.pack(fill="x", pady=(4, 2))
        tk.Label(hdr, text="  ALERTS & ANOMALIES", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 9, "bold")).pack(side="left")
        tk.Button(hdr, text="Clear", bg=PANEL, fg=TEXT_DIM,
                  font=("Consolas", 8), relief="flat", bd=0, cursor="hand2",
                  command=self._clear_alerts).pack(side="right", padx=4)

        self.alert_frame = tk.Frame(parent, bg=PANEL,
                                    highlightthickness=1, highlightbackground=BORDER)
        self.alert_frame.pack(fill="both", expand=True, padx=2)

        self.alert_canvas = tk.Canvas(self.alert_frame, bg=PANEL,
                                      highlightthickness=0, bd=0)
        vsb = tk.Scrollbar(self.alert_frame, orient="vertical",
                           command=self.alert_canvas.yview)
        self.alert_canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.alert_canvas.pack(fill="both", expand=True)

        self.alert_inner = tk.Frame(self.alert_canvas, bg=PANEL)
        self.alert_canvas.create_window((0, 0), window=self.alert_inner, anchor="nw")
        self.alert_inner.bind("<Configure>",
            lambda e: self.alert_canvas.configure(
                scrollregion=self.alert_canvas.bbox("all")))

    def _make_tree(self, parent, cols, height=10):
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Guardian.Treeview",
            background=PANEL, foreground=TEXT,
            fieldbackground=PANEL, rowheight=24,
            borderwidth=0, font=("Consolas", 9))
        style.configure("Guardian.Treeview.Heading",
            background=BG, foreground=TEXT_DIM,
            relief="flat", font=("Consolas", 8, "bold"))
        style.map("Guardian.Treeview",
            background=[("selected", "#1f2937")],
            foreground=[("selected", ACCENT)])

        frame = tk.Frame(parent, bg=PANEL,
                         highlightthickness=1, highlightbackground=BORDER)
        tree = ttk.Treeview(frame, columns=cols, show="headings",
                            height=height, style="Guardian.Treeview")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)

        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=120, anchor="w")

        return frame.children.get("!treeview") or tree

    # ── Refresh ───────────────────────────────────────────────────────────────
    def _schedule_refresh(self):
        self.after(0, self._refresh)

    def _refresh(self):
        conns, sent, recv, procs, alerts = self.monitor.snapshot()

        # Clock
        self.clock_lbl.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))

        # Stats
        self.stat_frames["devices"]._val_lbl.config(text=str(len(conns)))
        total_conns = sum(d["count"] for d in conns.values())
        self.stat_frames["conns"]._val_lbl.config(text=str(total_conns))
        self.stat_frames["upload"]._val_lbl.config(
            text=format_bytes(sent / 3) + "/s")
        self.stat_frames["download"]._val_lbl.config(
            text=format_bytes(recv / 3) + "/s")
        n_warn = sum(1 for a in alerts if a.level >= 1)
        alert_color = DANGER if n_warn else ACCENT2
        self.stat_frames["alerts"]._val_lbl.config(
            text=str(n_warn), fg=alert_color)

        # Connection tree
        tree = self.conn_tree
        for item in tree.get_children():
            tree.delete(item)

        sorted_conns = sorted(conns.items(), key=lambda x: -x[1]["count"])
        for ip, data in sorted_conns[:80]:
            ports = data["ports"]
            bad   = ports & SUSPICIOUS_PORTS
            status = "⚠ SUSPICIOUS PORTS" if bad else (
                     "● HIGH CONN" if data["count"] >= 20 else "✓ Normal")
            tag = "danger" if bad else ("warn" if data["count"] >= 20 else "ok")
            sample_ports = ", ".join(str(p) for p in list(ports)[:5])
            if len(ports) > 5:
                sample_ports += f" +{len(ports)-5} more"
            tree.insert("", "end", values=(ip, data["count"], sample_ports, status),
                        tags=(tag,))

        tree.tag_configure("danger", foreground=DANGER)
        tree.tag_configure("warn",   foreground=WARN)
        tree.tag_configure("ok",     foreground=ACCENT2)

        # Process tree
        ptree = self.proc_tree
        for item in ptree.get_children():
            ptree.delete(item)
        for p in sorted(procs, key=lambda x: -x["conn_count"])[:20]:
            ptree.insert("", "end", values=(p["name"], p["pid"], p["conn_count"]))

        # Alerts
        for widget in self.alert_inner.winfo_children():
            widget.destroy()

        if not alerts:
            tk.Label(self.alert_inner, text="\n  ✓  No alerts detected.\n  Network looks clean.",
                     bg=PANEL, fg=ACCENT2, font=("Consolas", 10),
                     justify="left").pack(anchor="w", padx=12, pady=8)
        else:
            for alert in alerts[:50]:
                color = severity_color(alert.level)
                row = tk.Frame(self.alert_inner, bg=PANEL, pady=2)
                row.pack(fill="x", padx=4, pady=1)
                tk.Label(row, text=alert.label(), bg=PANEL, fg=color,
                         font=("Consolas", 9, "bold"), anchor="w",
                         justify="left").pack(fill="x", padx=8)
                tk.Label(row, text=f"   {alert.detail}", bg=PANEL, fg=TEXT_DIM,
                         font=("Consolas", 8), anchor="w",
                         justify="left").pack(fill="x", padx=8)
                tk.Frame(row, bg=BORDER, height=1).pack(fill="x", padx=8, pady=2)

    def _clear_alerts(self):
        with self.monitor.lock:
            self.monitor.alerts.clear()
        self._refresh()

    def on_close(self):
        self.monitor.stop()
        self.destroy()

# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Check for psutil
    try:
        import psutil
    except ImportError:
        print("Missing dependency. Run:  pip install psutil")
        sys.exit(1)

    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
