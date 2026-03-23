"""
Home Network Guardian - Family Network Monitor
Requires: pip install psutil
Run as Administrator for full visibility.

Connection direction explained:
  OUTBOUND  = your PC opened a connection to a remote address (most normal traffic)
  INBOUND   = a remote address connected into your PC (servers, p2p, remote desktop)
  LISTENING = your PC is waiting for incoming connections on a port (local servers)
"""

import tkinter as tk
from tkinter import ttk
import threading
import time
import socket
import ipaddress
from datetime import datetime
import sys
import traceback

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ── Colors ────────────────────────────────────────────────────────────────────
BG       = "#0d1117"
PANEL    = "#161b22"
BORDER   = "#30363d"
ACCENT   = "#58a6ff"
ACCENT2  = "#3fb950"
WARN     = "#d29922"
DANGER   = "#f85149"
TEXT     = "#e6edf3"
TEXT_DIM = "#8b949e"
LAN_COL  = "#79c0ff"   # light blue for LAN addresses
WAN_COL  = "#e6edf3"   # normal for WAN

# ── Constants ─────────────────────────────────────────────────────────────────
ALERT_CONN_COUNT  = 50
ALERT_MB_PER_MIN  = 50
SUSPICIOUS_PORTS  = {4444, 1337, 6667, 31337, 12345, 9999, 3389, 5900, 23}

# RFC-1918 private ranges + link-local
_PRIVATE = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]

def is_lan(ip_str):
    """Return True if the IP is a private/LAN address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE)
    except ValueError:
        return False

def format_bytes(b):
    for unit in ("B", "KB", "MB", "GB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"

# ── Connection record ─────────────────────────────────────────────────────────
class Connection:
    """One active connection or listening socket."""
    def __init__(self, laddr, raddr, status, pid, pname):
        self.laddr  = laddr    # (ip, port) or None
        self.raddr  = raddr    # (ip, port) or None
        self.status = status   # ESTABLISHED, LISTEN, TIME_WAIT, etc.
        self.pid    = pid
        self.pname  = pname

        lip  = laddr[0] if laddr else ""
        rip  = raddr[0] if raddr else ""

        # Scope
        self.lan_local  = is_lan(lip)  if lip  else True
        self.lan_remote = is_lan(rip)  if rip  else False

        # Direction
        if status == "LISTEN":
            self.direction = "LISTEN"
        elif raddr:
            # Heuristic: if the remote port is a well-known service port (< 1024)
            # or the local port is ephemeral (> 1024) → outbound.
            # If the local port is a well-known port and remote is ephemeral → inbound.
            lport = laddr[1] if laddr else 0
            rport = raddr[1] if raddr else 0
            if rport < 1024 or lport > 1024:
                self.direction = "OUTBOUND"
            else:
                self.direction = "INBOUND"
        else:
            self.direction = "UNKNOWN"

        # Suspicious?
        rport = raddr[1] if raddr else 0
        self.suspicious = rport in SUSPICIOUS_PORTS

    @property
    def remote_ip(self):
        return self.raddr[0] if self.raddr else ""

    @property
    def remote_port(self):
        return self.raddr[1] if self.raddr else 0

    @property
    def local_ip(self):
        return self.laddr[0] if self.laddr else ""

    @property
    def local_port(self):
        return self.laddr[1] if self.laddr else 0

    def scope_label(self):
        if self.direction == "LISTEN":
            return "LISTENING"
        if self.lan_remote:
            return "LAN"
        return "WAN"

    def endpoint_str(self):
        """Human-readable  local_ip:port  →  remote_ip:port"""
        l = f"{self.local_ip}:{self.local_port}" if self.laddr else "?"
        r = f"{self.remote_ip}:{self.remote_port}" if self.raddr else "?"
        if self.direction == "LISTEN":
            return f"{l}  (listening)"
        arrow = "→" if self.direction == "OUTBOUND" else "←"
        return f"{l}  {arrow}  {r}"

# ── Alert ─────────────────────────────────────────────────────────────────────
class Alert:
    ICONS = ["i", "!", "X"]
    def __init__(self, level, title, detail):
        self.ts     = datetime.now().strftime("%H:%M:%S")
        self.level  = level
        self.title  = title
        self.detail = detail

    def label(self):
        return f"[{self.ICONS[self.level]}]  [{self.ts}]  {self.title}"

LEVEL_COLOR = {0: ACCENT, 1: WARN, 2: DANGER}

# ── Monitor ───────────────────────────────────────────────────────────────────
class NetworkMonitor:
    def __init__(self, log_fn=None):
        self.running     = False
        self.lock        = threading.Lock()
        self.alerts      = []
        self.conns       = []    # list of Connection objects
        self.proc_data   = []
        self.sent_delta  = 0
        self.recv_delta  = 0
        self._prev_io    = None
        self._log        = log_fn or (lambda m: None)
        self.on_update   = None

    def start(self):
        self.running = True
        try:
            self._prev_io = psutil.net_io_counters(pernic=False)
        except Exception as e:
            self._log(f"Initial net_io_counters failed: {e}")
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            try:
                self._poll()
            except Exception as e:
                self._log(f"Poll error: {e}\n{traceback.format_exc()}")
            time.sleep(3)

    def _poll(self):
        # Build pid→name map once per poll (cheaper than per-connection lookup)
        pid_names = {}
        try:
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    pid_names[p.pid] = p.info.get("name", "?")
                except Exception:
                    pass
        except Exception as e:
            self._log(f"process_iter error: {e}")

        new_conns = self._get_connections(pid_names)
        sent, recv = self._get_io_delta()
        procs = self._get_processes(pid_names)
        new_alerts = self._check_alerts(new_conns, sent)

        with self.lock:
            self.conns      = new_conns
            self.sent_delta = sent
            self.recv_delta = recv
            self.proc_data  = procs
            for a in new_alerts:
                self._add_alert(a)

        if self.on_update:
            self.on_update()

    def _get_connections(self, pid_names):
        result = []
        try:
            raw = psutil.net_connections(kind="inet")
        except psutil.AccessDenied as e:
            self._log(f"net_connections AccessDenied: {e}")
            return result
        except Exception as e:
            self._log(f"net_connections error: {e}\n{traceback.format_exc()}")
            return result

        for c in raw:
            try:
                laddr = (c.laddr.ip, c.laddr.port) if c.laddr else None
                raddr = (c.raddr.ip, c.raddr.port) if c.raddr else None
                # Skip pure loopback
                if laddr and laddr[0].startswith("127."):
                    continue
                pid   = c.pid or 0
                pname = pid_names.get(pid, "?")
                conn  = Connection(laddr, raddr, c.status or "?", pid, pname)
                result.append(conn)
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
            self._log(f"net_io_counters error: {e}")
            return 0, 0

    def _get_processes(self, pid_names):
        # Count remote connections per process
        counts = {}
        for c in self.conns:
            if c.raddr and c.direction != "LISTEN":
                counts[c.pid] = counts.get(c.pid, 0) + 1
        result = [{"pid": pid, "name": pid_names.get(pid, "?"), "conn_count": n}
                  for pid, n in counts.items()]
        return sorted(result, key=lambda x: -x["conn_count"])[:25]

    def _check_alerts(self, conns, sent_delta):
        new = []
        # Count per remote IP
        ip_counts = {}
        for c in conns:
            if c.remote_ip:
                ip_counts[c.remote_ip] = ip_counts.get(c.remote_ip, 0) + 1

        for ip, count in ip_counts.items():
            if count >= ALERT_CONN_COUNT:
                new.append(Alert(2, f"High connections to {ip}",
                    f"{count} simultaneous connections."))

        for c in conns:
            if c.suspicious:
                new.append(Alert(2, f"Suspicious port {c.remote_port} — {c.remote_ip}",
                    f"Process: {c.pname}  |  {c.endpoint_str()}"))

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
            return (list(self.conns), self.sent_delta, self.recv_delta,
                    list(self.proc_data), list(self.alerts))

# ── App ───────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Home Network Guardian")
        self.geometry("1300x780")
        self.minsize(1000, 600)
        self.configure(bg=BG)
        self.resizable(True, True)
        self.diag_log = []
        self._filter_var    = tk.StringVar(value="ALL")
        self._sort_col      = "remote_ip"
        self._sort_rev      = False

        self._setup_styles()
        self._build_ui()

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
            s.configure(name, background=PANEL, foreground=TEXT,
                        fieldbackground=PANEL, rowheight=22,
                        borderwidth=0, font=("Consolas", 9))
            s.configure(f"{name}.Heading", background=BG, foreground=TEXT_DIM,
                        relief="flat", font=("Consolas", 8, "bold"))
            s.map(name,
                  background=[("selected", "#1f2937")],
                  foreground=[("selected", ACCENT)])
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=PANEL, foreground=TEXT_DIM,
                    font=("Consolas", 9), padding=[12, 4])
        s.map("TNotebook.Tab",
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
        for key, label in [("total","Total Conns"), ("outbound","Outbound"),
                           ("inbound","Inbound"), ("lan","LAN"),
                           ("up","Upload/s"), ("dn","Download/s"), ("alerts","Alerts")]:
            card = tk.Frame(sbar, bg=PANEL, padx=12, pady=6,
                            highlightthickness=1, highlightbackground=BORDER)
            card.pack(side="left", padx=4)
            tk.Label(card, text=label, bg=PANEL, fg=TEXT_DIM,
                     font=("Consolas", 8)).pack(anchor="w")
            v = tk.Label(card, text="--", bg=PANEL, fg=TEXT,
                         font=("Consolas", 12, "bold"))
            v.pack(anchor="w")
            self._stats[key] = v

        # Tabs
        nb_frame = tk.Frame(self, bg=BG)
        nb_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.nb = ttk.Notebook(nb_frame)
        self.nb.pack(fill="both", expand=True)

        dash = tk.Frame(self.nb, bg=BG)
        self.nb.add(dash, text="  Connections  ")
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
        paned.add(left,  minsize=700)
        paned.add(right, minsize=260)

        # ── Filter bar ────────────────────────────────────────────────────────
        fbar = tk.Frame(left, bg=BG)
        fbar.pack(fill="x", pady=(4, 2), padx=2)
        tk.Label(fbar, text="  Show:", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8)).pack(side="left")
        for label, val in [("All", "ALL"), ("Outbound", "OUTBOUND"),
                           ("Inbound", "INBOUND"), ("LAN", "LAN"),
                           ("WAN only", "WAN"), ("Suspicious", "SUSPICIOUS")]:
            rb = tk.Radiobutton(fbar, text=label, variable=self._filter_var,
                                value=val, command=self._refresh,
                                bg=BG, fg=TEXT_DIM, selectcolor=PANEL,
                                activebackground=BG, activeforeground=TEXT,
                                font=("Consolas", 8), relief="flat",
                                highlightthickness=0)
            rb.pack(side="left", padx=6)

        # ── Connection table ──────────────────────────────────────────────────
        self._section_label(left, "ACTIVE CONNECTIONS  (click a column header to sort)")

        # Columns: Direction | Scope | Local Endpoint | Remote Endpoint | Process | State
        cols = ("Dir", "Scope", "Local IP : Port", "Remote IP : Port", "Process", "State")
        widths = [70, 65, 175, 175, 140, 100]

        conn_frame = tk.Frame(left, bg=PANEL, highlightthickness=1,
                              highlightbackground=BORDER)
        conn_frame.pack(fill="both", expand=True, padx=2, pady=(0, 4))

        self.conn_tree = ttk.Treeview(conn_frame, columns=cols,
                                      show="headings", height=18,
                                      style="Guardian.Treeview")
        vsb1 = ttk.Scrollbar(conn_frame, orient="vertical",
                              command=self.conn_tree.yview)
        hsb1 = ttk.Scrollbar(conn_frame, orient="horizontal",
                              command=self.conn_tree.xview)
        self.conn_tree.configure(yscrollcommand=vsb1.set, xscrollcommand=hsb1.set)
        hsb1.pack(side="bottom", fill="x")
        vsb1.pack(side="right",  fill="y")
        self.conn_tree.pack(fill="both", expand=True)

        for col, w in zip(cols, widths):
            self.conn_tree.heading(col, text=col,
                command=lambda c=col: self._sort_by(c))
            self.conn_tree.column(col, width=w, anchor="w", minwidth=50)

        # Row tags
        self.conn_tree.tag_configure("danger",   foreground=DANGER)
        self.conn_tree.tag_configure("warn",     foreground=WARN)
        self.conn_tree.tag_configure("outbound", foreground=WAN_COL)
        self.conn_tree.tag_configure("inbound",  foreground=ACCENT)
        self.conn_tree.tag_configure("lan",      foreground=LAN_COL)
        self.conn_tree.tag_configure("listen",   foreground=TEXT_DIM)

        # ── Process table ─────────────────────────────────────────────────────
        self._section_label(left, "TOP PROCESSES")
        proc_frame = tk.Frame(left, bg=PANEL, highlightthickness=1,
                              highlightbackground=BORDER)
        proc_frame.pack(fill="x", padx=2)
        pcols = ("Process", "PID", "Remote Conns")
        self.proc_tree = ttk.Treeview(proc_frame, columns=pcols,
                                      show="headings", height=5,
                                      style="Guardian.Treeview")
        vsb2 = ttk.Scrollbar(proc_frame, orient="vertical",
                              command=self.proc_tree.yview)
        self.proc_tree.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side="right", fill="y")
        self.proc_tree.pack(fill="both", expand=True)
        for col, w in zip(pcols, [200, 70, 110]):
            self.proc_tree.heading(col, text=col)
            self.proc_tree.column(col, width=w, anchor="w")

        # ── Alerts panel ──────────────────────────────────────────────────────
        ahdr = tk.Frame(right, bg=BG)
        ahdr.pack(fill="x", pady=(4, 2))
        self._section_label_inline(ahdr, "ALERTS")
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

        # ── Legend ────────────────────────────────────────────────────────────
        leg = tk.Frame(right, bg=BG)
        leg.pack(fill="x", padx=4, pady=(8, 0))
        tk.Label(leg, text="Legend:", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8, "bold")).pack(anchor="w", padx=4)
        for color, text in [
            (WAN_COL,  "OUTBOUND  — your PC → internet"),
            (ACCENT,   "INBOUND   — internet → your PC"),
            (LAN_COL,  "LAN       — local network device"),
            (TEXT_DIM, "LISTEN    — waiting for connections"),
            (DANGER,   "SUSPICIOUS — known bad port"),
        ]:
            tk.Label(leg, text=f"  {text}", bg=BG, fg=color,
                     font=("Consolas", 8), anchor="w").pack(fill="x", padx=4)

    def _build_diag_tab(self, parent):
        tk.Label(parent,
                 text="  Environment and error log.",
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

    def _sort_by(self, col):
        key_map = {
            "Dir":              lambda c: c.direction,
            "Scope":            lambda c: c.scope_label(),
            "Local IP : Port":  lambda c: (c.local_ip, c.local_port),
            "Remote IP : Port": lambda c: (c.remote_ip, c.remote_port),
            "Process":          lambda c: c.pname,
            "State":            lambda c: c.status,
        }
        self._sort_key = key_map.get(col, lambda c: c.remote_ip)
        self._sort_rev = not self._sort_rev if self._sort_col == col else False
        self._sort_col = col
        self._refresh()

    # ── Refresh ───────────────────────────────────────────────────────────────
    def _refresh(self):
        if not HAS_PSUTIL:
            return
        try:
            conns, sent, recv, procs, alerts = self.monitor.snapshot()
            self.clock_lbl.config(
                text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))

            # Filter
            fval = self._filter_var.get()
            def passes(c):
                if fval == "ALL":        return True
                if fval == "OUTBOUND":   return c.direction == "OUTBOUND"
                if fval == "INBOUND":    return c.direction == "INBOUND"
                if fval == "LAN":        return c.lan_remote or c.scope_label() == "LAN"
                if fval == "WAN":        return not c.lan_remote and c.raddr is not None
                if fval == "SUSPICIOUS": return c.suspicious
                return True
            visible = [c for c in conns if passes(c)]

            # Sort
            sort_fn = getattr(self, "_sort_key",
                              lambda c: (c.remote_ip, c.remote_port))
            try:
                visible.sort(key=sort_fn, reverse=self._sort_rev)
            except Exception:
                pass

            # Stats
            out_n  = sum(1 for c in conns if c.direction == "OUTBOUND")
            in_n   = sum(1 for c in conns if c.direction == "INBOUND")
            lan_n  = sum(1 for c in conns if c.lan_remote)
            n_warn = sum(1 for a in alerts if a.level >= 1)
            self._stats["total"].config(text=str(len(conns)))
            self._stats["outbound"].config(text=str(out_n), fg=WAN_COL)
            self._stats["inbound"].config(text=str(in_n),   fg=ACCENT)
            self._stats["lan"].config(text=str(lan_n),      fg=LAN_COL)
            self._stats["up"].config(text=format_bytes(sent / 3) + "/s")
            self._stats["dn"].config(text=format_bytes(recv / 3) + "/s")
            self._stats["alerts"].config(text=str(n_warn),
                                         fg=DANGER if n_warn else ACCENT2)

            # Connection tree
            for item in self.conn_tree.get_children():
                self.conn_tree.delete(item)

            for c in visible[:300]:
                # Pick tag (danger wins)
                if c.suspicious:
                    tag = "danger"
                elif c.direction == "INBOUND":
                    tag = "inbound"
                elif c.direction == "LISTEN":
                    tag = "listen"
                elif c.lan_remote:
                    tag = "lan"
                else:
                    tag = "outbound"

                lep = f"{c.local_ip}:{c.local_port}"   if c.laddr else "—"
                rep = f"{c.remote_ip}:{c.remote_port}" if c.raddr else "—"

                self.conn_tree.insert("", "end", tags=(tag,), values=(
                    c.direction,
                    c.scope_label(),
                    lep,
                    rep,
                    c.pname or "?",
                    c.status,
                ))

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
                         text="\n  No alerts.\n  Network looks clean.",
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
