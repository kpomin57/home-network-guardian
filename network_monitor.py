"""
Home Network Guardian - Family Network Monitor
Requires: pip install psutil
Run as Administrator for full visibility.

Tabs:
  Connections  — live view of this PC's network activity
  LAN Scanner  — discover and monitor all devices on your local network
  Diagnostics  — error log and environment info
"""

import tkinter as tk
from tkinter import ttk
import threading
import time
import socket
import ipaddress
import subprocess
import platform
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
LAN_COL  = "#79c0ff"
WAN_COL  = "#e6edf3"

# ── Thresholds ────────────────────────────────────────────────────────────────
ALERT_CONN_COUNT = 50
ALERT_MB_PER_MIN = 50
SUSPICIOUS_PORTS = {4444, 1337, 6667, 31337, 12345, 9999, 3389, 5900, 23}

# Common ports to probe during LAN scan (fast fingerprint)
PROBE_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 548, 554, 631, 993, 995, 1883,
    3306, 3389, 5000, 5900, 8080, 8443, 8888, 9100,
]

# ── Helpers ───────────────────────────────────────────────────────────────────
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def is_lan(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in n for n in _PRIVATE_NETS)
    except ValueError:
        return False

def format_bytes(b):
    for unit in ("B", "KB", "MB", "GB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"

def get_local_ips():
    """Return list of (ip, netmask) for non-loopback interfaces."""
    addrs = []
    try:
        for iface, snics in psutil.net_if_addrs().items():
            for snic in snics:
                if snic.family == socket.AF_INET:
                    ip = snic.address
                    if not ip.startswith("127."):
                        addrs.append((ip, snic.netmask or "255.255.255.0"))
    except Exception:
        pass
    return addrs

def cidr_hosts(ip, netmask):
    """Yield all host IPs in the subnet (up to /16 = 65534 hosts, capped at /24)."""
    try:
        net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        # Safety cap: only scan /24 or smaller
        if net.prefixlen < 24:
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return [str(h) for h in net.hosts()]
    except Exception:
        return []

def ping(ip, timeout=0.5):
    """Return True if host responds to ping."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
    timeout_val   = "500" if platform.system().lower() == "windows" else "1"
    try:
        result = subprocess.run(
            ["ping", param, "1", timeout_param, timeout_val, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return result.returncode == 0
    except Exception:
        return False

def resolve_hostname(ip, timeout=1.0):
    """Reverse DNS lookup with timeout."""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)

def probe_ports(ip, ports, timeout=0.3):
    """Return list of open ports from the probe list."""
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports

PORT_LABELS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 548: "AFP", 554: "RTSP", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1883: "MQTT", 3306: "MySQL",
    3389: "RDP", 5000: "UPnP", 5900: "VNC", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "HTTP-dev", 9100: "Print",
}

RISKY_PORTS = {23, 135, 139, 445, 3389, 5900}   # flag these if open

def describe_ports(open_ports):
    if not open_ports:
        return "none"
    return ", ".join(PORT_LABELS.get(p, str(p)) for p in sorted(open_ports))

def guess_device_type(open_ports, hostname):
    p = set(open_ports)
    h = hostname.lower()
    if 9100 in p:                          return "Printer"
    if 554 in p or 8554 in p:             return "IP Camera"
    if 1883 in p:                          return "IoT Device"
    if 5900 in p:                          return "VNC Host"
    if 3389 in p:                          return "Windows PC (RDP)"
    if 22 in p and 80 not in p:           return "Linux/Mac"
    if 445 in p or 139 in p:             return "Windows PC"
    if 548 in p:                           return "Mac (AFP)"
    if 80 in p or 443 in p:              return "Web Server / Router"
    if "iphone" in h or "ipad" in h:     return "Apple Device"
    if "android" in h:                    return "Android Device"
    if "router" in h or "gateway" in h:  return "Router"
    return "Unknown"


# ── LAN Device record ─────────────────────────────────────────────────────────
class LanDevice:
    def __init__(self, ip):
        self.ip          = ip
        self.hostname    = ""
        self.open_ports  = []
        self.device_type = "?"
        self.first_seen  = datetime.now().strftime("%H:%M:%S")
        self.last_seen   = self.first_seen
        self.status      = "UP"     # UP / DOWN
        self.is_new      = True     # flag for first appearance
        self.risky       = False

    def update(self, hostname, open_ports):
        self.hostname    = hostname
        self.open_ports  = open_ports
        self.device_type = guess_device_type(open_ports, hostname)
        self.last_seen   = datetime.now().strftime("%H:%M:%S")
        self.status      = "UP"
        self.risky       = bool(set(open_ports) & RISKY_PORTS)

    def port_summary(self):
        return describe_ports(self.open_ports)


# ── LAN Scanner ───────────────────────────────────────────────────────────────
class LanScanner:
    """
    Periodically scans the local subnet.
    - Ping-sweeps to find live hosts
    - Port-probes each live host
    - Reverse-DNS lookup for hostname
    - Tracks new/disappeared devices
    """
    def __init__(self, log_fn=None, on_update=None):
        self.lock       = threading.Lock()
        self.devices    = {}        # ip → LanDevice
        self.alerts     = []
        self.running    = False
        self.scanning   = False
        self.scan_progress = ""
        self._log       = log_fn or (lambda m: None)
        self.on_update  = on_update
        self._known_ips = set()     # IPs seen at least once

    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            try:
                self._full_scan()
            except Exception as e:
                self._log(f"LAN scan error: {e}\n{traceback.format_exc()}")
            # Wait 2 minutes between full scans
            for _ in range(120):
                if not self.running:
                    return
                time.sleep(1)

    def _full_scan(self):
        local_addrs = get_local_ips()
        if not local_addrs:
            self._log("LAN Scanner: no local IP addresses found.")
            return

        all_hosts = []
        for ip, mask in local_addrs:
            hosts = cidr_hosts(ip, mask)
            self._log(f"LAN Scanner: scanning {len(hosts)} hosts on {ip}/{mask}")
            all_hosts.extend(hosts)

        # Remove duplicates preserving order
        seen = set()
        unique_hosts = [h for h in all_hosts if not (h in seen or seen.add(h))]

        with self.lock:
            self.scanning = True
            self.scan_progress = f"0 / {len(unique_hosts)}"

        # Mark all existing devices as potentially DOWN
        with self.lock:
            for dev in self.devices.values():
                dev.status = "DOWN"

        found = 0
        # Use a thread pool for faster scanning
        results = {}
        lock = threading.Lock()

        def scan_one(ip):
            if not ping(ip):
                return
            hostname   = resolve_hostname(ip)
            open_ports = probe_ports(ip, PROBE_PORTS)
            with lock:
                results[ip] = (hostname, open_ports)

        threads = []
        for ip in unique_hosts:
            if not self.running:
                break
            t = threading.Thread(target=scan_one, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
            # Throttle: max 30 concurrent threads
            if len([t for t in threads if t.is_alive()]) >= 30:
                time.sleep(0.1)

        # Wait for all to finish
        for t in threads:
            t.join(timeout=5)

        # Update device records
        with self.lock:
            for ip, (hostname, open_ports) in results.items():
                is_new_device = ip not in self._known_ips
                if ip not in self.devices:
                    self.devices[ip] = LanDevice(ip)
                dev = self.devices[ip]
                dev.update(hostname, open_ports)
                dev.is_new = is_new_device

                if is_new_device:
                    self._known_ips.add(ip)
                    self.alerts.insert(0, {
                        "ts":     datetime.now().strftime("%H:%M:%S"),
                        "level":  1,
                        "title":  f"New device: {ip}",
                        "detail": f"Hostname: {hostname or 'unknown'}  |  "
                                  f"Type: {dev.device_type}  |  "
                                  f"Open ports: {dev.port_summary()}",
                    })

                if dev.risky:
                    self.alerts.insert(0, {
                        "ts":     datetime.now().strftime("%H:%M:%S"),
                        "level":  2,
                        "title":  f"Risky ports open: {ip}",
                        "detail": f"Open: {dev.port_summary()}  — "
                                  f"RDP/VNC/Telnet/SMB can be exploited.",
                    })

            self.alerts = self.alerts[:200]
            self.scanning      = False
            self.scan_progress = f"{len(results)} devices found"

        if self.on_update:
            self.on_update()

    def snapshot(self):
        with self.lock:
            return (dict(self.devices), self.scanning,
                    self.scan_progress, list(self.alerts))


# ── Connection record ─────────────────────────────────────────────────────────
class Connection:
    def __init__(self, laddr, raddr, status, pid, pname):
        self.laddr  = laddr
        self.raddr  = raddr
        self.status = status
        self.pid    = pid
        self.pname  = pname

        lip = laddr[0] if laddr else ""
        rip = raddr[0] if raddr else ""
        self.lan_local  = is_lan(lip) if lip else True
        self.lan_remote = is_lan(rip) if rip else False

        if status == "LISTEN":
            self.direction = "LISTEN"
        elif raddr:
            lport = laddr[1] if laddr else 0
            rport = raddr[1] if raddr else 0
            self.direction = "OUTBOUND" if (rport < 1024 or lport > 1024) else "INBOUND"
        else:
            self.direction = "UNKNOWN"

        rport = raddr[1] if raddr else 0
        self.suspicious = rport in SUSPICIOUS_PORTS

    @property
    def remote_ip(self):   return self.raddr[0] if self.raddr else ""
    @property
    def remote_port(self): return self.raddr[1] if self.raddr else 0
    @property
    def local_ip(self):    return self.laddr[0] if self.laddr else ""
    @property
    def local_port(self):  return self.laddr[1] if self.laddr else 0

    def scope_label(self):
        if self.direction == "LISTEN": return "LISTENING"
        return "LAN" if self.lan_remote else "WAN"


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


# ── Network Monitor (this-PC connections) ─────────────────────────────────────
class NetworkMonitor:
    def __init__(self, log_fn=None):
        self.running     = False
        self.lock        = threading.Lock()
        self.alerts      = []
        self.conns       = []
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
        pid_names = {}
        try:
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    pid_names[p.pid] = p.info.get("name", "?")
                except Exception:
                    pass
        except Exception as e:
            self._log(f"process_iter error: {e}")

        new_conns  = self._get_connections(pid_names)
        sent, recv = self._get_io_delta()
        procs      = self._get_processes(pid_names, new_conns)
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
                if laddr and laddr[0].startswith("127."):
                    continue
                pid   = c.pid or 0
                conn  = Connection(laddr, raddr, c.status or "?",
                                   pid, pid_names.get(pid, "?"))
                result.append(conn)
            except Exception as e:
                self._log(f"Connection parse error: {e}")
        return result

    def _get_io_delta(self):
        try:
            cur  = psutil.net_io_counters(pernic=False)
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

    def _get_processes(self, pid_names, conns):
        counts = {}
        for c in conns:
            if c.raddr and c.direction != "LISTEN":
                counts[c.pid] = counts.get(c.pid, 0) + 1
        result = [{"pid": pid, "name": pid_names.get(pid, "?"), "conn_count": n}
                  for pid, n in counts.items()]
        return sorted(result, key=lambda x: -x["conn_count"])[:25]

    def _check_alerts(self, conns, sent_delta):
        new = []
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
                new.append(Alert(2, f"Suspicious port {c.remote_port}: {c.remote_ip}",
                                 f"Process: {c.pname}"))
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
        self.geometry("1300x800")
        self.minsize(1000, 600)
        self.configure(bg=BG)
        self.resizable(True, True)
        self.diag_log    = []
        self._filter_var = tk.StringVar(value="ALL")
        self._sort_col   = "remote_ip"
        self._sort_rev   = False
        self._sort_key   = lambda c: (c.remote_ip, c.remote_port)

        self._setup_styles()
        self._build_ui()

        self._log(f"Python {sys.version}")
        self._log(f"psutil installed: {HAS_PSUTIL}")
        if HAS_PSUTIL:
            self._log(f"psutil version: {psutil.__version__}")
        try:
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
            return

        self.monitor = NetworkMonitor(log_fn=self._log)
        self.monitor.on_update = lambda: self.after(0, self._refresh_connections)
        self.monitor.start()

        self.lan_scanner = LanScanner(
            log_fn=self._log,
            on_update=lambda: self.after(0, self._refresh_lan))
        self.lan_scanner.start()

        self._refresh_connections()

    # ── Styles ────────────────────────────────────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use("default")
        s.configure("Guardian.Treeview",
                    background=PANEL, foreground=TEXT,
                    fieldbackground=PANEL, rowheight=22,
                    borderwidth=0, font=("Consolas", 9))
        s.configure("Guardian.Treeview.Heading",
                    background=BG, foreground=TEXT_DIM,
                    relief="flat", font=("Consolas", 8, "bold"))
        s.map("Guardian.Treeview",
              background=[("selected", "#1f2937")],
              foreground=[("selected", ACCENT)])
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=PANEL, foreground=TEXT_DIM,
                    font=("Consolas", 9), padding=[12, 4])
        s.map("TNotebook.Tab",
              background=[("selected", BG)],
              foreground=[("selected", TEXT)])

    # ── Top-level UI ──────────────────────────────────────────────────────────
    def _build_ui(self):
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

        sbar = tk.Frame(self, bg=BG)
        sbar.pack(fill="x", padx=12, pady=6)
        self._stats = {}
        for key, label in [("total","Total Conns"), ("outbound","Outbound"),
                           ("inbound","Inbound"), ("lan_conns","LAN Conns"),
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

        nb_frame = tk.Frame(self, bg=BG)
        nb_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.nb = ttk.Notebook(nb_frame)
        self.nb.pack(fill="both", expand=True)

        dash = tk.Frame(self.nb, bg=BG)
        self.nb.add(dash, text="  Connections  ")
        self._build_connections_tab(dash)

        lan = tk.Frame(self.nb, bg=BG)
        self.nb.add(lan, text="  LAN Scanner  ")
        self._build_lan_tab(lan)

        diag = tk.Frame(self.nb, bg=BG)
        self.nb.add(diag, text="  Diagnostics  ")
        self._build_diag_tab(diag)

    # ── Connections tab ───────────────────────────────────────────────────────
    def _build_connections_tab(self, parent):
        paned = tk.PanedWindow(parent, orient="horizontal", bg=BG,
                               sashwidth=6, sashrelief="flat")
        paned.pack(fill="both", expand=True)
        left  = tk.Frame(paned, bg=BG)
        right = tk.Frame(paned, bg=BG)
        paned.add(left,  minsize=700)
        paned.add(right, minsize=260)

        fbar = tk.Frame(left, bg=BG)
        fbar.pack(fill="x", pady=(4, 2), padx=2)
        tk.Label(fbar, text="  Show:", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8)).pack(side="left")
        for label, val in [("All","ALL"), ("Outbound","OUTBOUND"),
                           ("Inbound","INBOUND"), ("LAN","LAN"),
                           ("WAN only","WAN"), ("Suspicious","SUSPICIOUS")]:
            tk.Radiobutton(fbar, text=label, variable=self._filter_var,
                           value=val, command=self._refresh_connections,
                           bg=BG, fg=TEXT_DIM, selectcolor=PANEL,
                           activebackground=BG, activeforeground=TEXT,
                           font=("Consolas", 8), relief="flat",
                           highlightthickness=0).pack(side="left", padx=6)

        self._section_label(left, "ACTIVE CONNECTIONS  (click column header to sort)")

        cols   = ("Dir", "Scope", "Local IP : Port", "Remote IP : Port", "Process", "State")
        widths = [70, 65, 175, 175, 150, 100]
        cf = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        cf.pack(fill="both", expand=True, padx=2, pady=(0, 4))
        self.conn_tree = ttk.Treeview(cf, columns=cols, show="headings",
                                      height=18, style="Guardian.Treeview")
        vsb = ttk.Scrollbar(cf, orient="vertical", command=self.conn_tree.yview)
        hsb = ttk.Scrollbar(cf, orient="horizontal", command=self.conn_tree.xview)
        self.conn_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        vsb.pack(side="right",  fill="y")
        self.conn_tree.pack(fill="both", expand=True)
        for col, w in zip(cols, widths):
            self.conn_tree.heading(col, text=col,
                                   command=lambda c=col: self._sort_by(c))
            self.conn_tree.column(col, width=w, anchor="w", minwidth=50)
        self.conn_tree.tag_configure("danger",   foreground=DANGER)
        self.conn_tree.tag_configure("inbound",  foreground=ACCENT)
        self.conn_tree.tag_configure("lan",      foreground=LAN_COL)
        self.conn_tree.tag_configure("outbound", foreground=WAN_COL)
        self.conn_tree.tag_configure("listen",   foreground=TEXT_DIM)

        self._section_label(left, "TOP PROCESSES")
        pf = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        pf.pack(fill="x", padx=2)
        pcols = ("Process", "PID", "Remote Conns")
        self.proc_tree = ttk.Treeview(pf, columns=pcols, show="headings",
                                      height=5, style="Guardian.Treeview")
        vsb2 = ttk.Scrollbar(pf, orient="vertical", command=self.proc_tree.yview)
        self.proc_tree.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side="right", fill="y")
        self.proc_tree.pack(fill="both", expand=True)
        for col, w in zip(pcols, [200, 70, 110]):
            self.proc_tree.heading(col, text=col)
            self.proc_tree.column(col, width=w, anchor="w")

        # Alerts + legend on right
        ahdr = tk.Frame(right, bg=BG)
        ahdr.pack(fill="x", pady=(4, 2))
        self._section_label_inline(ahdr, "ALERTS")
        tk.Button(ahdr, text="Clear", bg=PANEL, fg=TEXT_DIM, relief="flat",
                  font=("Consolas", 8), cursor="hand2",
                  command=self._clear_conn_alerts).pack(side="right", padx=4)
        af = tk.Frame(right, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        af.pack(fill="both", expand=True, padx=2)
        self.alert_canvas = tk.Canvas(af, bg=PANEL, highlightthickness=0)
        vsb3 = tk.Scrollbar(af, orient="vertical", command=self.alert_canvas.yview)
        self.alert_canvas.configure(yscrollcommand=vsb3.set)
        vsb3.pack(side="right", fill="y")
        self.alert_canvas.pack(fill="both", expand=True)
        self.alert_inner = tk.Frame(self.alert_canvas, bg=PANEL)
        aw = self.alert_canvas.create_window((0,0), window=self.alert_inner, anchor="nw")
        self.alert_inner.bind("<Configure>",
            lambda e: self.alert_canvas.configure(
                scrollregion=self.alert_canvas.bbox("all")))
        self.alert_canvas.bind("<Configure>",
            lambda e: self.alert_canvas.itemconfig(aw, width=e.width))

        leg = tk.Frame(right, bg=BG)
        leg.pack(fill="x", padx=4, pady=(8, 0))
        tk.Label(leg, text="Legend:", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8, "bold")).pack(anchor="w", padx=4)
        for color, desc in [
            (WAN_COL,  "OUTBOUND  — your PC → internet"),
            (ACCENT,   "INBOUND   — internet → your PC"),
            (LAN_COL,  "LAN       — local network device"),
            (TEXT_DIM, "LISTEN    — waiting for connections"),
            (DANGER,   "SUSPICIOUS — known bad port"),
        ]:
            tk.Label(leg, text=f"  {desc}", bg=BG, fg=color,
                     font=("Consolas", 8), anchor="w").pack(fill="x", padx=4)

    # ── LAN Scanner tab ───────────────────────────────────────────────────────
    def _build_lan_tab(self, parent):
        paned = tk.PanedWindow(parent, orient="horizontal", bg=BG,
                               sashwidth=6, sashrelief="flat")
        paned.pack(fill="both", expand=True)
        left  = tk.Frame(paned, bg=BG)
        right = tk.Frame(paned, bg=BG)
        paned.add(left,  minsize=720)
        paned.add(right, minsize=260)

        # Status / scan bar
        scanbar = tk.Frame(left, bg=BG)
        scanbar.pack(fill="x", padx=2, pady=(4, 2))
        self.lan_status_lbl = tk.Label(
            scanbar, text="  Scanning your local network...",
            bg=BG, fg=TEXT_DIM, font=("Consolas", 9), anchor="w")
        self.lan_status_lbl.pack(side="left")
        tk.Button(scanbar, text="Scan Now", bg=PANEL, fg=ACCENT,
                  font=("Consolas", 8), relief="flat", cursor="hand2",
                  command=self._manual_lan_scan).pack(side="right", padx=6)

        self._section_label(left, "DISCOVERED DEVICES")

        lan_cols   = ("IP Address", "Hostname", "Device Type",
                      "Open Services", "Risk", "Last Seen")
        lan_widths = [120, 180, 140, 220, 60, 80]
        lf = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        lf.pack(fill="both", expand=True, padx=2, pady=(0, 4))
        self.lan_tree = ttk.Treeview(lf, columns=lan_cols, show="headings",
                                     height=22, style="Guardian.Treeview")
        vsbL = ttk.Scrollbar(lf, orient="vertical", command=self.lan_tree.yview)
        hsbL = ttk.Scrollbar(lf, orient="horizontal", command=self.lan_tree.xview)
        self.lan_tree.configure(yscrollcommand=vsbL.set, xscrollcommand=hsbL.set)
        hsbL.pack(side="bottom", fill="x")
        vsbL.pack(side="right",  fill="y")
        self.lan_tree.pack(fill="both", expand=True)
        for col, w in zip(lan_cols, lan_widths):
            self.lan_tree.heading(col, text=col)
            self.lan_tree.column(col, width=w, anchor="w", minwidth=50)
        self.lan_tree.tag_configure("risky",  foreground=DANGER)
        self.lan_tree.tag_configure("new",    foreground=WARN)
        self.lan_tree.tag_configure("normal", foreground=ACCENT2)
        self.lan_tree.tag_configure("down",   foreground=TEXT_DARK if "TEXT_DARK" in dir() else TEXT_DIM)

        # LAN alerts on right
        ahdr2 = tk.Frame(right, bg=BG)
        ahdr2.pack(fill="x", pady=(4, 2))
        self._section_label_inline(ahdr2, "LAN ALERTS")
        tk.Button(ahdr2, text="Clear", bg=PANEL, fg=TEXT_DIM, relief="flat",
                  font=("Consolas", 8), cursor="hand2",
                  command=self._clear_lan_alerts).pack(side="right", padx=4)
        af2 = tk.Frame(right, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        af2.pack(fill="both", expand=True, padx=2)
        self.lan_alert_canvas = tk.Canvas(af2, bg=PANEL, highlightthickness=0)
        vsb4 = tk.Scrollbar(af2, orient="vertical", command=self.lan_alert_canvas.yview)
        self.lan_alert_canvas.configure(yscrollcommand=vsb4.set)
        vsb4.pack(side="right", fill="y")
        self.lan_alert_canvas.pack(fill="both", expand=True)
        self.lan_alert_inner = tk.Frame(self.lan_alert_canvas, bg=PANEL)
        law = self.lan_alert_canvas.create_window(
            (0,0), window=self.lan_alert_inner, anchor="nw")
        self.lan_alert_inner.bind("<Configure>",
            lambda e: self.lan_alert_canvas.configure(
                scrollregion=self.lan_alert_canvas.bbox("all")))
        self.lan_alert_canvas.bind("<Configure>",
            lambda e: self.lan_alert_canvas.itemconfig(law, width=e.width))

        # Notes
        notes = tk.Frame(right, bg=BG)
        notes.pack(fill="x", padx=4, pady=(8, 0))
        tk.Label(notes, text="How it works:", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8, "bold")).pack(anchor="w", padx=4)
        for line in [
            "Pings every device on your subnet",
            "Checks common service ports",
            "Reverse-DNS for hostnames",
            "Alerts on new/unknown devices",
            "Flags risky open ports (RDP,",
            "  VNC, Telnet, SMB)",
            "",
            "Full scan runs every 2 min.",
            "First scan may take ~30s.",
        ]:
            tk.Label(notes, text=f"  {line}", bg=BG, fg=TEXT_DIM,
                     font=("Consolas", 8), anchor="w").pack(fill="x", padx=4)

    # ── Diagnostics tab ───────────────────────────────────────────────────────
    def _build_diag_tab(self, parent):
        tk.Label(parent, text="  Environment and error log.",
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
        self._refresh_connections()

    def _manual_lan_scan(self):
        self.lan_status_lbl.config(text="  Manual scan triggered...", fg=WARN)
        threading.Thread(target=self.lan_scanner._full_scan, daemon=True).start()

    # ── Refresh: Connections ──────────────────────────────────────────────────
    def _refresh_connections(self):
        if not HAS_PSUTIL:
            return
        try:
            conns, sent, recv, procs, alerts = self.monitor.snapshot()
            self.clock_lbl.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))

            fval = self._filter_var.get()
            def passes(c):
                if fval == "ALL":        return True
                if fval == "OUTBOUND":   return c.direction == "OUTBOUND"
                if fval == "INBOUND":    return c.direction == "INBOUND"
                if fval == "LAN":        return c.lan_remote
                if fval == "WAN":        return not c.lan_remote and c.raddr is not None
                if fval == "SUSPICIOUS": return c.suspicious
                return True
            visible = [c for c in conns if passes(c)]
            try:
                visible.sort(key=self._sort_key, reverse=self._sort_rev)
            except Exception:
                pass

            out_n  = sum(1 for c in conns if c.direction == "OUTBOUND")
            in_n   = sum(1 for c in conns if c.direction == "INBOUND")
            lan_n  = sum(1 for c in conns if c.lan_remote)
            n_warn = sum(1 for a in alerts if a.level >= 1)
            self._stats["total"].config(text=str(len(conns)))
            self._stats["outbound"].config(text=str(out_n),  fg=WAN_COL)
            self._stats["inbound"].config(text=str(in_n),    fg=ACCENT)
            self._stats["lan_conns"].config(text=str(lan_n), fg=LAN_COL)
            self._stats["up"].config(text=format_bytes(sent/3)+"/s")
            self._stats["dn"].config(text=format_bytes(recv/3)+"/s")
            self._stats["alerts"].config(text=str(n_warn),
                                         fg=DANGER if n_warn else ACCENT2)

            for item in self.conn_tree.get_children():
                self.conn_tree.delete(item)
            for c in visible[:300]:
                tag = ("danger"   if c.suspicious   else
                       "inbound"  if c.direction == "INBOUND" else
                       "listen"   if c.direction == "LISTEN"  else
                       "lan"      if c.lan_remote              else
                       "outbound")
                lep = f"{c.local_ip}:{c.local_port}"   if c.laddr else "—"
                rep = f"{c.remote_ip}:{c.remote_port}" if c.raddr else "—"
                self.conn_tree.insert("", "end", tags=(tag,),
                    values=(c.direction, c.scope_label(), lep, rep, c.pname, c.status))

            for item in self.proc_tree.get_children():
                self.proc_tree.delete(item)
            for p in procs:
                self.proc_tree.insert("", "end",
                    values=(p["name"], p["pid"], p["conn_count"]))

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
                             font=("Consolas", 8), anchor="w").pack(fill="x", padx=8)
                    tk.Frame(row, bg=BORDER, height=1).pack(fill="x", padx=8, pady=2)

        except Exception as e:
            self._log(f"_refresh_connections error: {e}\n{traceback.format_exc()}")

    # ── Refresh: LAN ──────────────────────────────────────────────────────────
    def _refresh_lan(self):
        if not HAS_PSUTIL:
            return
        try:
            devices, scanning, progress, alerts = self.lan_scanner.snapshot()

            if scanning:
                self.lan_status_lbl.config(
                    text=f"  Scanning... {progress}", fg=WARN)
            else:
                up = sum(1 for d in devices.values() if d.status == "UP")
                self.lan_status_lbl.config(
                    text=f"  {up} devices online  |  {progress}  |  "
                         f"Next scan in ~2 min", fg=ACCENT2)

            for item in self.lan_tree.get_children():
                self.lan_tree.delete(item)

            for ip, dev in sorted(devices.items(),
                                  key=lambda x: [int(p) for p in x[0].split(".")]):
                if dev.status == "DOWN":
                    tag = "down"
                elif dev.risky:
                    tag = "risky"
                elif dev.is_new:
                    tag = "new"
                else:
                    tag = "normal"

                risk_str = "RISKY" if dev.risky else ("NEW" if dev.is_new else "OK")
                self.lan_tree.insert("", "end", tags=(tag,), values=(
                    dev.ip,
                    dev.hostname or "(unknown)",
                    dev.device_type,
                    dev.port_summary(),
                    risk_str,
                    dev.last_seen,
                ))

            for w in self.lan_alert_inner.winfo_children():
                w.destroy()
            if not alerts:
                tk.Label(self.lan_alert_inner,
                         text="\n  No LAN alerts yet.\n  Scan in progress...",
                         bg=PANEL, fg=TEXT_DIM, font=("Consolas", 10),
                         justify="left").pack(anchor="w", padx=12, pady=8)
            else:
                for a in alerts[:60]:
                    color = LEVEL_COLOR.get(a["level"], TEXT_DIM)
                    row = tk.Frame(self.lan_alert_inner, bg=PANEL)
                    row.pack(fill="x", padx=4, pady=1)
                    icon = ["i","!","X"][a["level"]]
                    tk.Label(row,
                             text=f"[{icon}]  [{a['ts']}]  {a['title']}",
                             bg=PANEL, fg=color,
                             font=("Consolas", 9, "bold"),
                             anchor="w").pack(fill="x", padx=8)
                    tk.Label(row, text=f"   {a['detail']}",
                             bg=PANEL, fg=TEXT_DIM,
                             font=("Consolas", 8), anchor="w").pack(fill="x", padx=8)
                    tk.Frame(row, bg=BORDER, height=1).pack(fill="x", padx=8, pady=2)

        except Exception as e:
            self._log(f"_refresh_lan error: {e}\n{traceback.format_exc()}")

    def _clear_conn_alerts(self):
        with self.monitor.lock:
            self.monitor.alerts.clear()
        self._refresh_connections()

    def _clear_lan_alerts(self):
        with self.lan_scanner.lock:
            self.lan_scanner.alerts.clear()
        self._refresh_lan()

    def on_close(self):
        if hasattr(self, "monitor"):
            self.monitor.stop()
        if hasattr(self, "lan_scanner"):
            self.lan_scanner.stop()
        self.destroy()


# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
