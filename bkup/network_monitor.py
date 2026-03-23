"""
Home Network Guardian - Family Network Monitor
Requires: pip install psutil
Run as Administrator for full visibility.
"""

import tkinter as tk
from tkinter import ttk
import threading
import time
import socket
from datetime import datetime
import sys
import traceback

# ── Optional imports with graceful fallback ───────────────────────────────────
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ── Color Palette ─────────────────────────────────────────────────────────────
BG       = "#0d1117"
PANEL    = "#161b22"
BORDER   = "#30363d"
ACCENT   = "#58a6ff"
ACCENT2  = "#3fb950"
WARN     = "#d29922"
DANGER   = "#f85149"
TEXT     = "#e6edf3"
TEXT_DIM = "#8b949e"

# ── Thresholds ────────────────────────────────────────────────────────────────
ALERT_CONN_COUNT   = 50
ALERT_MB_PER_MIN   = 50
SUSPICIOUS_PORTS   = {4444, 1337, 6667, 31337, 12345, 9999, 3389, 5900, 23}

# ── Helpers ───────────────────────────────────────────────────────────────────
def format_bytes(b):
    for unit in ("B", "KB", "MB", "GB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"

# ── Alert ─────────────────────────────────────────────────────────────────────
class Alert:
    ICONS = ["i", "!", "X"]
    def __init__(self, level, title, detail):
        self.ts     = datetime.now().strftime("%H:%M:%S")
        self.level  = level  # 0=info 1=warn 2=danger
        self.title  = title
        self.detail = detail

    def label(self):
        return f"[{self.ICONS[self.level]}]  [{self.ts}]  {self.title}"

LEVEL_COLOR = {0: ACCENT, 1: WARN, 2: DANGER}

# ── Monitor ───────────────────────────────────────────────────────────────────
class NetworkMonitor:
    def __init__(self, log_fn=None):
        self.running      = False
        self.lock         = threading.Lock()
        self.alerts       = []
        self.connections  = {}
        self.proc_data    = []
        self.sent_delta   = 0
        self.recv_delta   = 0
        self._prev_io     = None
        self._log         = log_fn or (lambda msg: None)
        self.on_update    = None

    def start(self):
        self.running = True
        try:
            self._prev_io = psutil.net_io_counters(pernic=False)
        except Exception as e:
            self._log(f"Initial net_io_counters failed: {e}")
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            try:
                self._poll()
            except Exception as e:
                self._log(f"Poll loop error: {e}\n{traceback.format_exc()}")
            time.sleep(3)

    def _poll(self):
        new_conns  = self._get_connections()
        sent, recv = self._get_io_delta()
        procs      = self._get_processes()
        new_alerts = self._check_alerts(new_conns, sent)

        with self.lock:
            self.connections = new_conns
            self.sent_delta  = sent
            self.recv_delta  = recv
            self.proc_data   = procs
            for a in new_alerts:
                self._add_alert(a)

        if self.on_update:
            self.on_update()

    def _get_connections(self):
        result = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied as e:
            self._log(f"net_connections AccessDenied: {e} — run as Administrator.")
            return result
        except Exception as e:
            self._log(f"net_connections error: {e}\n{traceback.format_exc()}")
            return result
        for c in conns:
            try:
                if not c.raddr:
                    continue
                ip   = c.raddr.ip
                port = c.raddr.port
                if ip.startswith("127.") or ip == "::1" or ip == "0.0.0.0":
                    continue
                if ip not in result:
                    result[ip] = {"count": 0, "ports": set()}
                result[ip]["count"] += 1
                result[ip]["ports"].add(port)
            except Exception as e:
                self._log(f"Connection parse error: {e}")
        return result

    

    def _get_io_delta(self):
        try:
            cur = psutil.net_io_counters(pernic=False)
            if self._prev_io is None:
                self._prev_io = cur
                return 0, 0
            sent = max(0, cur.bytes_sent - self._prev_io.bytes_sent)
            recv = max(0, cur.bytes_recv - self._prev_io.bytes_recv)
            self._prev_io = cur
            return sent, recv
        except Exception as e:
            self._log(f"net_io_counters error: {e}\n{traceback.format_exc()}")
            return 0, 0

    def _get_processes(self):
        result = []
        try:
            # "connections" is NOT a valid process_iter attr in psutil 5.9+
            # — must be fetched via proc.net_connections() or proc.connections()
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    # psutil 6.0 renamed connections() → net_connections()
                    if hasattr(proc, "net_connections"):
                        pconns = proc.net_connections(kind="inet")
                    else:
                        pconns = proc.connections(kind="inet")
                    remote = [c.raddr.ip for c in pconns if c.raddr]
                    if remote:
                        result.append({
                            "pid":        proc.pid,
                            "name":       proc.info.get("name", "?"),
                            "conn_count": len(remote),
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception as e:
                    self._log(f"Process error (pid {proc.pid}): {e}")
        except Exception as e:
            self._log(f"process_iter error: {e}\n{traceback.format_exc()}")
        return sorted(result, key=lambda x: -x["conn_count"])[:25]

    def _check_alerts(self, conns, sent_delta):
        new = []
        for ip, data in conns.items():
            if data["count"] >= ALERT_CONN_COUNT:
                new.append(Alert(2, f"High connections: {ip}",
                    f"{data['count']} simultaneous connections."))
            bad = data["ports"] & SUSPICIOUS_PORTS
            if bad:
                new.append(Alert(2, f"Suspicious port(s): {ip}",
                    f"Ports: {', '.join(str(p) for p in bad)}"))
        mb_min = (sent_delta / 3) / (1024 * 1024) * 60
        if mb_min > ALERT_MB_PER_MIN:
            new.append(Alert(1, "High upload rate",
                f"{mb_min:.1f} MB/min upload detected."))
        return new

    def _add_alert(self, alert):
        for a in self.alerts[-20:]:
            if a.title == alert.title:
                return
        self.alerts.insert(0, alert)
        self.alerts = self.alerts[:200]

    def snapshot(self):
        with self.lock:
            return (dict(self.connections),
                    self.sent_delta, self.recv_delta,
                    list(self.proc_data), list(self.alerts))


# ── Main App ──────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Home Network Guardian")
        self.geometry("1150x750")
        self.minsize(900, 600)
        self.configure(bg=BG)
        self.resizable(True, True)
        self.diag_log = []

        self._setup_styles()
        self._build_ui()

        # Log environment info
        self._log(f"Python {sys.version}")
        self._log(f"psutil installed: {HAS_PSUTIL}")
        if HAS_PSUTIL:
            self._log(f"psutil version: {psutil.__version__}")
        try:
            import platform
            self._log(f"OS: {platform.system()} {platform.release()}")
        except Exception:
            pass
        try:
            import ctypes
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            self._log(f"Running as Administrator: {admin}")
            if not admin:
                self._log("TIP: Right-click launch_monitor.bat -> 'Run as administrator' for full visibility.")
        except Exception:
            self._log("Could not determine admin status.")

        if not HAS_PSUTIL:
            self._show_psutil_error()
            return

        self.monitor = NetworkMonitor(log_fn=self._log)
        self.monitor.on_update = lambda: self.after(0, self._refresh)
        self.monitor.start()
        self._refresh()

    # ── Styles ────────────────────────────────────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use("default")
        for name in ("Guardian.Treeview",):
            s.configure(name,
                background=PANEL, foreground=TEXT,
                fieldbackground=PANEL, rowheight=24,
                borderwidth=0, font=("Consolas", 9))
            s.configure(f"{name}.Heading",
                background=BG, foreground=TEXT_DIM,
                relief="flat", font=("Consolas", 8, "bold"))
            s.map(name,
                background=[("selected", "#1f2937")],
                foreground=[("selected", ACCENT)])
        style = ttk.Style()
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=TEXT_DIM,
                        font=("Consolas", 9), padding=[12, 4])
        style.map("TNotebook.Tab",
                  background=[("selected", BG)],
                  foreground=[("selected", TEXT)])

    # ── Build UI ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=PANEL, height=54)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="Home Network Guardian", bg=PANEL, fg=TEXT,
                 font=("Consolas", 15, "bold")).pack(side="left", padx=20, pady=12)
        self.status_lbl = tk.Label(hdr, text="[*] MONITORING", bg=PANEL, fg=ACCENT2,
                                   font=("Consolas", 10, "bold"))
        self.status_lbl.pack(side="left", padx=8)
        self.clock_lbl = tk.Label(hdr, text="", bg=PANEL, fg=TEXT_DIM,
                                  font=("Consolas", 10))
        self.clock_lbl.pack(side="right", padx=20)

        # Stats bar
        sbar = tk.Frame(self, bg=BG)
        sbar.pack(fill="x", padx=12, pady=6)
        self._stats = {}
        for key, label in [("devices", "Devices"), ("conns", "Connections"),
                           ("up", "Upload/s"), ("dn", "Download/s"), ("alerts", "Alerts")]:
            card = tk.Frame(sbar, bg=PANEL, padx=14, pady=6,
                            highlightthickness=1, highlightbackground=BORDER)
            card.pack(side="left", padx=5)
            tk.Label(card, text=label, bg=PANEL, fg=TEXT_DIM,
                     font=("Consolas", 8)).pack(anchor="w")
            v = tk.Label(card, text="--", bg=PANEL, fg=TEXT,
                         font=("Consolas", 13, "bold"))
            v.pack(anchor="w")
            self._stats[key] = v

        # Tabs
        nb_frame = tk.Frame(self, bg=BG)
        nb_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.nb = ttk.Notebook(nb_frame)
        self.nb.pack(fill="both", expand=True)

        dash = tk.Frame(self.nb, bg=BG)
        self.nb.add(dash, text="  Dashboard  ")
        self._build_dashboard(dash)

        diag = tk.Frame(self.nb, bg=BG)
        self.nb.add(diag, text="  Diagnostics  ")
        self._build_diag_tab(diag)

    def _build_dashboard(self, parent):
        paned = tk.PanedWindow(parent, orient="horizontal", bg=BG,
                               sashwidth=6, sashrelief="flat")
        paned.pack(fill="both", expand=True)
        left  = tk.Frame(paned, bg=BG)
        right = tk.Frame(paned, bg=BG)
        paned.add(left,  minsize=400)
        paned.add(right, minsize=280)

        # Connection table
        self._section_label(left, "ACTIVE EXTERNAL CONNECTIONS")
        conn_frame = tk.Frame(left, bg=PANEL, highlightthickness=1,
                              highlightbackground=BORDER)
        conn_frame.pack(fill="both", expand=True, padx=2, pady=(0, 4))
        cols = ("Remote IP", "Conns", "Sample Ports", "Status")
        self.conn_tree = ttk.Treeview(conn_frame, columns=cols,
                                      show="headings", height=14,
                                      style="Guardian.Treeview")
        vsb1 = ttk.Scrollbar(conn_frame, orient="vertical",
                              command=self.conn_tree.yview)
        self.conn_tree.configure(yscrollcommand=vsb1.set)
        vsb1.pack(side="right", fill="y")
        self.conn_tree.pack(fill="both", expand=True)
        for col, w in zip(cols, [145, 55, 200, 145]):
            self.conn_tree.heading(col, text=col)
            self.conn_tree.column(col, width=w, anchor="w")
        self.conn_tree.tag_configure("danger", foreground=DANGER)
        self.conn_tree.tag_configure("warn",   foreground=WARN)
        self.conn_tree.tag_configure("ok",     foreground=ACCENT2)

        # Process table
        self._section_label(left, "TOP PROCESSES BY CONNECTIONS")
        proc_frame = tk.Frame(left, bg=PANEL, highlightthickness=1,
                              highlightbackground=BORDER)
        proc_frame.pack(fill="x", padx=2)
        pcols = ("Process", "PID", "Remote Conns")
        self.proc_tree = ttk.Treeview(proc_frame, columns=pcols,
                                      show="headings", height=7,
                                      style="Guardian.Treeview")
        vsb2 = ttk.Scrollbar(proc_frame, orient="vertical",
                              command=self.proc_tree.yview)
        self.proc_tree.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side="right", fill="y")
        self.proc_tree.pack(fill="both", expand=True)
        for col, w in zip(pcols, [180, 70, 100]):
            self.proc_tree.heading(col, text=col)
            self.proc_tree.column(col, width=w, anchor="w")

        # Alerts panel
        ahdr = tk.Frame(right, bg=BG)
        ahdr.pack(fill="x", pady=(0, 2))
        self._section_label_inline(ahdr, "ALERTS & ANOMALIES")
        tk.Button(ahdr, text="Clear", bg=PANEL, fg=TEXT_DIM, relief="flat",
                  font=("Consolas", 8), cursor="hand2",
                  command=self._clear_alerts).pack(side="right", padx=4)

        af = tk.Frame(right, bg=PANEL, highlightthickness=1,
                      highlightbackground=BORDER)
        af.pack(fill="both", expand=True, padx=2)
        self.alert_canvas = tk.Canvas(af, bg=PANEL, highlightthickness=0)
        vsb3 = tk.Scrollbar(af, orient="vertical",
                            command=self.alert_canvas.yview)
        self.alert_canvas.configure(yscrollcommand=vsb3.set)
        vsb3.pack(side="right", fill="y")
        self.alert_canvas.pack(fill="both", expand=True)
        self.alert_inner = tk.Frame(self.alert_canvas, bg=PANEL)
        self._alert_win = self.alert_canvas.create_window(
            (0, 0), window=self.alert_inner, anchor="nw")
        self.alert_inner.bind("<Configure>",
            lambda e: self.alert_canvas.configure(
                scrollregion=self.alert_canvas.bbox("all")))
        self.alert_canvas.bind("<Configure>",
            lambda e: self.alert_canvas.itemconfig(
                self._alert_win, width=e.width))

    def _build_diag_tab(self, parent):
        tk.Label(parent,
                 text="  Environment info and error log. If the monitor is not working, check here.",
                 bg=BG, fg=TEXT_DIM, font=("Consolas", 9),
                 anchor="w").pack(fill="x", padx=8, pady=(6, 2))
        frame = tk.Frame(parent, bg=PANEL, highlightthickness=1,
                         highlightbackground=BORDER)
        frame.pack(fill="both", expand=True, padx=8, pady=4)
        self.diag_text = tk.Text(frame, bg=PANEL, fg=TEXT_DIM,
                                 font=("Consolas", 9), wrap="word",
                                 state="disabled", relief="flat")
        vsb = tk.Scrollbar(frame, command=self.diag_text.yview)
        self.diag_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.diag_text.pack(fill="both", expand=True, padx=4, pady=4)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _section_label(self, parent, text):
        tk.Label(parent, text=f"  {text}", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8, "bold"), anchor="w").pack(
                 fill="x", pady=(6, 1))

    def _section_label_inline(self, parent, text):
        tk.Label(parent, text=f"  {text}", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8, "bold"), anchor="w").pack(
                 side="left", pady=(0, 2))

    def _log(self, msg):
        ts   = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"
        self.diag_log.append(line)
        if hasattr(self, "diag_text"):
            self.diag_text.configure(state="normal")
            self.diag_text.insert("end", line)
            self.diag_text.see("end")
            self.diag_text.configure(state="disabled")

    def _show_psutil_error(self):
        self.status_lbl.config(text="[!] ERROR", fg=DANGER)
        for w in self.alert_inner.winfo_children():
            w.destroy()
        msg = ("psutil is not installed.\n\n"
               "Open Command Prompt and run:\n\n"
               "    pip install psutil\n\n"
               "Then restart this program.")
        tk.Label(self.alert_inner, text=msg, bg=PANEL, fg=DANGER,
                 font=("Consolas", 11), justify="left").pack(
                 anchor="w", padx=12, pady=12)

    # ── Refresh ───────────────────────────────────────────────────────────────
    def _refresh(self):
        if not HAS_PSUTIL:
            return
        try:
            conns, sent, recv, procs, alerts = self.monitor.snapshot()
            self.clock_lbl.config(
                text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))

            # Stats
            total = sum(d["count"] for d in conns.values())
            n_warn = sum(1 for a in alerts if a.level >= 1)
            self._stats["devices"].config(text=str(len(conns)))
            self._stats["conns"].config(text=str(total))
            self._stats["up"].config(text=format_bytes(sent / 3) + "/s")
            self._stats["dn"].config(text=format_bytes(recv / 3) + "/s")
            self._stats["alerts"].config(text=str(n_warn),
                                         fg=DANGER if n_warn else ACCENT2)

            # Connection tree
            for item in self.conn_tree.get_children():
                self.conn_tree.delete(item)
            for ip, data in sorted(conns.items(),
                                   key=lambda x: -x[1]["count"])[:100]:
                bad  = data["ports"] & SUSPICIOUS_PORTS
                hi   = data["count"] >= 20
                tag  = "danger" if bad else ("warn" if hi else "ok")
                st   = ("SUSPICIOUS PORTS" if bad else
                        ("HIGH CONN COUNT" if hi else "Normal"))
                pts  = list(data["ports"])
                samp = ", ".join(str(p) for p in pts[:5])
                if len(pts) > 5:
                    samp += f" +{len(pts)-5}"
                self.conn_tree.insert("", "end",
                    values=(ip, data["count"], samp, st), tags=(tag,))

            # Process tree
            for item in self.proc_tree.get_children():
                self.proc_tree.delete(item)
            for p in procs:
                self.proc_tree.insert("", "end",
                    values=(p["name"], p["pid"], p["conn_count"]))

            # Alerts
            for w in self.alert_inner.winfo_children():
                w.destroy()
            if not alerts:
                tk.Label(self.alert_inner,
                         text="\n  No alerts detected.\n  Network looks clean.",
                         bg=PANEL, fg=ACCENT2, font=("Consolas", 10),
                         justify="left").pack(anchor="w", padx=12, pady=8)
            else:
                for a in alerts[:60]:
                    color = LEVEL_COLOR.get(a.level, TEXT_DIM)
                    row = tk.Frame(self.alert_inner, bg=PANEL)
                    row.pack(fill="x", padx=4, pady=1)
                    tk.Label(row, text=a.label(), bg=PANEL, fg=color,
                             font=("Consolas", 9, "bold"),
                             anchor="w").pack(fill="x", padx=8)
                    tk.Label(row, text=f"   {a.detail}", bg=PANEL, fg=TEXT_DIM,
                             font=("Consolas", 8), anchor="w").pack(
                             fill="x", padx=8)
                    tk.Frame(row, bg=BORDER, height=1).pack(
                             fill="x", padx=8, pady=2)

        except Exception as e:
            self._log(f"_refresh error: {e}\n{traceback.format_exc()}")

    def _clear_alerts(self):
        with self.monitor.lock:
            self.monitor.alerts.clear()
        self._refresh()

    def on_close(self):
        if hasattr(self, "monitor"):
            self.monitor.stop()
        self.destroy()


# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
