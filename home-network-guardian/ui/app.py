"""
Main GUI application for the Home Network Guardian.

App extends tk.Tk and wires together the NetworkMonitor, LanScanner,
and PacketCapture backends with a four-tab Tkinter interface:
  - Connections     — live view of this PC's network activity
  - LAN Scanner     — discovered devices on the local network
  - Packet Capture  — live packet capture on a selected interface
  - Diagnostics     — error log and environment info
"""

import platform
import sys
import threading
import traceback
import webbrowser
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk, filedialog, messagebox
from typing import Callable, Optional

from core.capture import HAS_SCAPY, PacketCapture
from core.logger import setup_logging, get_logger
from core.monitor import NetworkMonitor
from core.persistence import PersistenceManager
from core.scanner import LanScanner
from core.utils import HAS_PSUTIL, format_bytes

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

# Data directory sits alongside the package root
DATA_DIR = Path(__file__).parent.parent / "data"

# ── Color palette ─────────────────────────────────────────────────────────────
BG        = "#0d1117"
PANEL     = "#161b22"
PANEL_ALT = "#131920"      # alternating row background
BORDER    = "#30363d"
ACCENT    = "#58a6ff"
ACCENT2   = "#3fb950"
WARN      = "#d29922"
DANGER    = "#f85149"
TEXT      = "#e6edf3"
TEXT_DIM  = "#8b949e"
LAN_COL   = "#79c0ff"
WAN_COL   = "#e6edf3"
SEL_BG    = "#1f2937"

LEVEL_COLOR: dict = {0: ACCENT, 1: WARN, 2: DANGER}

# Status indicator characters for the header pulse
_STATUS_CHARS = ("●", "○")


class App(tk.Tk):
    """Main GUI application window for the Home Network Guardian."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Home Network Guardian")
        self.geometry("1380x840")
        self.minsize(1100, 640)
        self.configure(bg=BG)
        self.resizable(True, True)

        # Set up file + console logging before anything else
        self._logger = setup_logging(DATA_DIR)

        self.diag_log: list = []
        self._filter_var = tk.StringVar(value="ALL")
        self._sort_col = "remote_ip"
        self._sort_rev = False
        self._sort_key = lambda c: (c.remote_ip, c.remote_port)
        self._status_tick = 0
        self._lan_was_scanning = False   # track scan-complete transitions

        # Packet capture state
        self._cap_displayed: int = 0
        self._cap_poll_id: Optional[str] = None
        self._cap_iface_var = tk.StringVar()
        self._cap_filter_var = tk.StringVar()
        self._cap_iface_map: dict = {}   # display → scapy name

        self._setup_styles()
        self._build_ui()

        self._log(f"Python {sys.version}")
        self._log(f"psutil installed: {HAS_PSUTIL}")
        if HAS_PSUTIL:
            self._log(f"psutil version: {psutil.__version__}")
        self._log(f"scapy installed: {HAS_SCAPY}")
        try:
            self._log(f"OS: {platform.system()} {platform.release()}")
        except Exception:
            pass
        try:
            import ctypes
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            self._log(f"Running as Administrator: {admin}")
            if not admin:
                self._log("  ↳ Packet capture and full connection data may require Admin.")
        except Exception:
            self._log("Could not determine admin status.")

        if not HAS_PSUTIL:
            self._tick()
            return

        # Persistence
        self._persistence = PersistenceManager(DATA_DIR)

        self.monitor = NetworkMonitor(log_fn=self._log)
        self.monitor.on_update = lambda: self.after(0, self._refresh_connections)
        self.monitor.start()

        self.lan_scanner = LanScanner(
            log_fn=self._log,
            on_update=lambda: self.after(0, self._refresh_lan),
        )

        # Restore persisted devices so returning hosts aren't flagged as new
        saved_devices, known_ips = self._persistence.load_devices()
        if saved_devices:
            with self.lan_scanner.lock:
                self.lan_scanner.devices = saved_devices
                self.lan_scanner._known_ips = known_ips
            self._log(f"Restored {len(saved_devices)} persisted device(s).")

        saved_lan_alerts = self._persistence.load_lan_alerts()
        if saved_lan_alerts:
            with self.lan_scanner.lock:
                self.lan_scanner.alerts = saved_lan_alerts
            self._log(f"Restored {len(saved_lan_alerts)} persisted LAN alert(s).")

        self.lan_scanner.start()
        self.capture = PacketCapture(log_fn=self._log)

        self._refresh_connections()
        self._refresh_lan()
        self._tick()

    # ── Styles ────────────────────────────────────────────────────────────────

    def _setup_styles(self) -> None:
        """Configure ttk styles for the dark theme."""
        s = ttk.Style(self)
        s.theme_use("default")

        s.configure("Guardian.Treeview",
                    background=PANEL, foreground=TEXT,
                    fieldbackground=PANEL, rowheight=24,
                    borderwidth=0, font=("Consolas", 9))
        s.configure("Guardian.Treeview.Heading",
                    background=BG, foreground=ACCENT,
                    relief="flat", font=("Consolas", 8, "bold"))
        s.map("Guardian.Treeview",
              background=[("selected", SEL_BG)],
              foreground=[("selected", ACCENT)])

        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab",
                    background=PANEL, foreground=TEXT_DIM,
                    font=("Consolas", 9), padding=[16, 6])
        s.map("TNotebook.Tab",
              background=[("selected", BG)],
              foreground=[("selected", TEXT)],
              font=[("selected", ("Consolas", 10, "bold"))])

        s.configure("Vertical.TScrollbar",
                    background=BORDER, troughcolor=PANEL,
                    borderwidth=0, arrowsize=12, relief="flat")
        s.configure("Horizontal.TScrollbar",
                    background=BORDER, troughcolor=PANEL,
                    borderwidth=0, arrowsize=12, relief="flat")

        s.configure("TCombobox",
                    fieldbackground=PANEL, background=PANEL,
                    foreground=TEXT, selectbackground=SEL_BG,
                    selectforeground=TEXT)
        s.map("TCombobox",
              fieldbackground=[("readonly", PANEL)],
              background=[("readonly", PANEL)],
              foreground=[("readonly", TEXT)])

    # ── Clock tick ────────────────────────────────────────────────────────────

    def _tick(self) -> None:
        """Update the header clock and pulse the status indicator every second."""
        self.clock_lbl.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self._status_tick = (self._status_tick + 1) % 2
        self.status_lbl.config(text=f" {_STATUS_CHARS[self._status_tick]}  MONITORING ")
        self.after(1000, self._tick)

    # ── Top-level UI ──────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Build the main window layout: header, stats bar, and notebook."""
        # Header
        hdr = tk.Frame(self, bg=PANEL, height=54)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        # Accent stripe
        tk.Frame(hdr, bg=ACCENT, width=3).pack(side="left", fill="y")
        tk.Label(hdr, text="  Home Network Guardian", bg=PANEL, fg=TEXT,
                 font=("Consolas", 15, "bold")).pack(side="left", padx=(12, 0), pady=12)
        self.status_lbl = tk.Label(hdr, text=f" {_STATUS_CHARS[0]}  MONITORING ",
                                   bg=PANEL, fg=ACCENT2,
                                   font=("Consolas", 10, "bold"))
        self.status_lbl.pack(side="left", padx=10)
        tk.Label(hdr, text="|", bg=PANEL, fg=BORDER,
                 font=("Consolas", 14)).pack(side="right", padx=4)
        self.clock_lbl = tk.Label(hdr, text="", bg=PANEL, fg=TEXT_DIM,
                                  font=("Consolas", 10))
        self.clock_lbl.pack(side="right", padx=8)

        # Stats bar
        sbar = tk.Frame(self, bg=BG)
        sbar.pack(fill="x", padx=12, pady=(8, 4))
        self._stats: dict = {}
        stat_defs = [
            ("total",    "Total Conns", TEXT),
            ("outbound", "Outbound",    WAN_COL),
            ("inbound",  "Inbound",     ACCENT),
            ("lan_conns","LAN Conns",   LAN_COL),
            ("up",       "Upload/s",    ACCENT2),
            ("dn",       "Download/s",  ACCENT2),
            ("alerts",   "Alerts",      ACCENT2),
        ]
        for key, label, val_color in stat_defs:
            card = tk.Frame(sbar, bg=PANEL, padx=14, pady=8,
                            highlightthickness=1, highlightbackground=BORDER)
            card.pack(side="left", padx=4)
            # Accent top border
            tk.Frame(card, bg=ACCENT, height=2).pack(fill="x", pady=(0, 4))
            tk.Label(card, text=label, bg=PANEL, fg=TEXT_DIM,
                     font=("Consolas", 8)).pack(anchor="w")
            v = tk.Label(card, text="--", bg=PANEL, fg=val_color,
                         font=("Consolas", 13, "bold"))
            v.pack(anchor="w")
            self._stats[key] = v

        # Notebook
        nb_frame = tk.Frame(self, bg=BG)
        nb_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.nb = ttk.Notebook(nb_frame)
        self.nb.pack(fill="both", expand=True)
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab_change)

        dash = tk.Frame(self.nb, bg=BG)
        self.nb.add(dash, text="  Connections  ")
        self._build_connections_tab(dash)

        lan = tk.Frame(self.nb, bg=BG)
        self.nb.add(lan, text="  LAN Scanner  ")
        self._build_lan_tab(lan)

        cap = tk.Frame(self.nb, bg=BG)
        self.nb.add(cap, text="  Packet Capture  ")
        self._build_capture_tab(cap)

        diag = tk.Frame(self.nb, bg=BG)
        self.nb.add(diag, text="  Diagnostics  ")
        self._build_diag_tab(diag)

    # ── Connections tab ───────────────────────────────────────────────────────

    def _build_connections_tab(self, parent: tk.Frame) -> None:
        """Build the Connections tab with table, process list, and alerts."""
        paned = tk.PanedWindow(parent, orient="horizontal", bg=BG,
                               sashwidth=6, sashrelief="flat")
        paned.pack(fill="both", expand=True)
        left  = tk.Frame(paned, bg=BG)
        right = tk.Frame(paned, bg=BG)
        paned.add(left,  minsize=700)
        paned.add(right, minsize=260)

        fbar = tk.Frame(left, bg=BG)
        fbar.pack(fill="x", pady=(6, 2), padx=2)
        tk.Label(fbar, text="  Show:", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8)).pack(side="left")
        for label, val in [
            ("All",        "ALL"),
            ("Outbound",   "OUTBOUND"),
            ("Inbound",    "INBOUND"),
            ("LAN",        "LAN"),
            ("WAN only",   "WAN"),
            ("Suspicious", "SUSPICIOUS"),
        ]:
            tk.Radiobutton(fbar, text=label, variable=self._filter_var,
                           value=val, command=self._refresh_connections,
                           bg=BG, fg=TEXT_DIM, selectcolor=PANEL,
                           activebackground=BG, activeforeground=TEXT,
                           font=("Consolas", 8), relief="flat",
                           highlightthickness=0).pack(side="left", padx=6)

        self._section_label(left, "ACTIVE CONNECTIONS  (click column header to sort)")

        cols   = ("Dir", "Scope", "Local IP : Port", "Remote IP : Port", "Process", "State")
        widths = [70, 65, 175, 175, 155, 100]
        cf = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        cf.pack(fill="both", expand=True, padx=2, pady=(0, 4))
        self.conn_tree = ttk.Treeview(cf, columns=cols, show="headings",
                                      height=18, style="Guardian.Treeview")
        vsb = ttk.Scrollbar(cf, orient="vertical", command=self.conn_tree.yview)
        hsb = ttk.Scrollbar(cf, orient="horizontal", command=self.conn_tree.xview)
        self.conn_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        vsb.pack(side="right", fill="y")
        self.conn_tree.pack(fill="both", expand=True)
        for col, w in zip(cols, widths):
            self.conn_tree.heading(col, text=col,
                                   command=lambda c=col: self._sort_by(c))
            self.conn_tree.column(col, width=w, anchor="w", minwidth=50)
        self.conn_tree.tag_configure("danger",    foreground=DANGER)
        self.conn_tree.tag_configure("inbound",   foreground=ACCENT)
        self.conn_tree.tag_configure("lan",       foreground=LAN_COL)
        self.conn_tree.tag_configure("outbound",  foreground=WAN_COL)
        self.conn_tree.tag_configure("listen",    foreground=TEXT_DIM)
        self.conn_tree.tag_configure("row_even",  background=PANEL)
        self.conn_tree.tag_configure("row_odd",   background=PANEL_ALT)
        self.conn_tree.bind("<Button-3>", self._show_conn_menu)

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
        for col, w in zip(pcols, [210, 70, 110]):
            self.proc_tree.heading(col, text=col)
            self.proc_tree.column(col, width=w, anchor="w")
        self.proc_tree.tag_configure("row_even", background=PANEL)
        self.proc_tree.tag_configure("row_odd",  background=PANEL_ALT)

        # Alerts panel
        ahdr = tk.Frame(right, bg=BG)
        ahdr.pack(fill="x", pady=(6, 2))
        self._section_label_inline(ahdr, "ALERTS")
        self._make_button(ahdr, "Clear", self._clear_conn_alerts).pack(
            side="right", padx=4)
        af = tk.Frame(right, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        af.pack(fill="both", expand=True, padx=2)
        self.alert_canvas = tk.Canvas(af, bg=PANEL, highlightthickness=0)
        vsb3 = ttk.Scrollbar(af, orient="vertical", command=self.alert_canvas.yview)
        self.alert_canvas.configure(yscrollcommand=vsb3.set)
        vsb3.pack(side="right", fill="y")
        self.alert_canvas.pack(fill="both", expand=True)
        self.alert_inner = tk.Frame(self.alert_canvas, bg=PANEL)
        aw = self.alert_canvas.create_window((0, 0), window=self.alert_inner, anchor="nw")
        self.alert_inner.bind("<Configure>",
            lambda e: self.alert_canvas.configure(
                scrollregion=self.alert_canvas.bbox("all")))
        self.alert_canvas.bind("<Configure>",
            lambda e: self.alert_canvas.itemconfig(aw, width=e.width))

        # Legend
        leg = tk.Frame(right, bg=BG)
        leg.pack(fill="x", padx=4, pady=(10, 0))
        tk.Label(leg, text="  Legend:", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8, "bold")).pack(anchor="w", padx=4)
        tk.Frame(leg, bg=BORDER, height=1).pack(fill="x", padx=4, pady=(2, 4))
        for color, desc in [
            (WAN_COL,  "OUTBOUND  — your PC → internet"),
            (ACCENT,   "INBOUND   — internet → your PC"),
            (LAN_COL,  "LAN       — local network"),
            (TEXT_DIM, "LISTEN    — awaiting connections"),
            (DANGER,   "SUSPICIOUS — known bad port"),
        ]:
            tk.Label(leg, text=f"  {desc}", bg=BG, fg=color,
                     font=("Consolas", 8), anchor="w").pack(fill="x", padx=4)

    # ── LAN Scanner tab ───────────────────────────────────────────────────────

    def _build_lan_tab(self, parent: tk.Frame) -> None:
        """Build the LAN Scanner tab with device table and alerts."""
        paned = tk.PanedWindow(parent, orient="horizontal", bg=BG,
                               sashwidth=6, sashrelief="flat")
        paned.pack(fill="both", expand=True)
        left  = tk.Frame(paned, bg=BG)
        right = tk.Frame(paned, bg=BG)
        paned.add(left,  minsize=720)
        paned.add(right, minsize=260)

        scanbar = tk.Frame(left, bg=BG)
        scanbar.pack(fill="x", padx=2, pady=(6, 2))
        self.lan_status_lbl = tk.Label(
            scanbar, text="  Scanning your local network...",
            bg=BG, fg=TEXT_DIM, font=("Consolas", 9), anchor="w")
        self.lan_status_lbl.pack(side="left")
        self._make_button(scanbar, "Scan Now", self._manual_lan_scan,
                          style="primary").pack(side="right", padx=6)

        self._section_label(left, "DISCOVERED DEVICES")

        lan_cols   = ("IP Address", "Hostname", "Device Type",
                      "Open Services", "Risk", "Last Seen")
        lan_widths = [120, 185, 145, 225, 62, 82]
        lf = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        lf.pack(fill="both", expand=True, padx=2, pady=(0, 4))
        self.lan_tree = ttk.Treeview(lf, columns=lan_cols, show="headings",
                                     height=22, style="Guardian.Treeview")
        vsbL = ttk.Scrollbar(lf, orient="vertical", command=self.lan_tree.yview)
        hsbL = ttk.Scrollbar(lf, orient="horizontal", command=self.lan_tree.xview)
        self.lan_tree.configure(yscrollcommand=vsbL.set, xscrollcommand=hsbL.set)
        hsbL.pack(side="bottom", fill="x")
        vsbL.pack(side="right", fill="y")
        self.lan_tree.pack(fill="both", expand=True)
        for col, w in zip(lan_cols, lan_widths):
            self.lan_tree.heading(col, text=col)
            self.lan_tree.column(col, width=w, anchor="w", minwidth=50)
        self.lan_tree.tag_configure("risky",    foreground=DANGER)
        self.lan_tree.tag_configure("new",      foreground=WARN)
        self.lan_tree.tag_configure("normal",   foreground=ACCENT2)
        self.lan_tree.tag_configure("down",     foreground=TEXT_DIM)
        self.lan_tree.tag_configure("row_even", background=PANEL)
        self.lan_tree.tag_configure("row_odd",  background=PANEL_ALT)
        self.lan_tree.bind("<Button-3>", self._show_lan_menu)

        # LAN alerts
        ahdr2 = tk.Frame(right, bg=BG)
        ahdr2.pack(fill="x", pady=(6, 2))
        self._section_label_inline(ahdr2, "LAN ALERTS")
        self._make_button(ahdr2, "Clear", self._clear_lan_alerts).pack(
            side="right", padx=4)
        af2 = tk.Frame(right, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        af2.pack(fill="both", expand=True, padx=2)
        self.lan_alert_canvas = tk.Canvas(af2, bg=PANEL, highlightthickness=0)
        vsb4 = ttk.Scrollbar(af2, orient="vertical",
                              command=self.lan_alert_canvas.yview)
        self.lan_alert_canvas.configure(yscrollcommand=vsb4.set)
        vsb4.pack(side="right", fill="y")
        self.lan_alert_canvas.pack(fill="both", expand=True)
        self.lan_alert_inner = tk.Frame(self.lan_alert_canvas, bg=PANEL)
        law = self.lan_alert_canvas.create_window(
            (0, 0), window=self.lan_alert_inner, anchor="nw")
        self.lan_alert_inner.bind("<Configure>",
            lambda e: self.lan_alert_canvas.configure(
                scrollregion=self.lan_alert_canvas.bbox("all")))
        self.lan_alert_canvas.bind("<Configure>",
            lambda e: self.lan_alert_canvas.itemconfig(law, width=e.width))

        notes = tk.Frame(right, bg=BG)
        notes.pack(fill="x", padx=4, pady=(10, 0))
        tk.Label(notes, text="  How it works:", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8, "bold")).pack(anchor="w", padx=4)
        tk.Frame(notes, bg=BORDER, height=1).pack(fill="x", padx=4, pady=(2, 4))
        for line in [
            "Pings every device on your subnet",
            "Checks common service ports",
            "Reverse-DNS for hostnames",
            "Alerts on new/unknown devices",
            "Flags risky open ports",
            "  (RDP, VNC, Telnet, SMB)",
            "",
            "Full scan runs every 2 min.",
            "First scan may take ~30s.",
        ]:
            tk.Label(notes, text=f"  {line}", bg=BG, fg=TEXT_DIM,
                     font=("Consolas", 8), anchor="w").pack(fill="x", padx=4)

    # ── Packet Capture tab ────────────────────────────────────────────────────

    def _build_capture_tab(self, parent: tk.Frame) -> None:
        """Build the Packet Capture tab with interface selector and live table."""
        if not HAS_SCAPY:
            msg = tk.Frame(parent, bg=BG)
            msg.pack(expand=True)
            tk.Label(msg, text="⚠  scapy is not installed.",
                     bg=BG, fg=WARN, font=("Consolas", 13, "bold")).pack(pady=(40, 8))
            tk.Label(msg,
                     text="Install it with:   pip install scapy\n\n"
                          "Windows also requires Npcap:  https://npcap.com/",
                     bg=BG, fg=TEXT_DIM, font=("Consolas", 10),
                     justify="center").pack()
            return

        # Control bar
        ctrl = tk.Frame(parent, bg=BG)
        ctrl.pack(fill="x", padx=8, pady=(8, 4))

        tk.Label(ctrl, text="Interface:", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 9)).pack(side="left", padx=(0, 4))
        self._cap_combo = ttk.Combobox(ctrl, textvariable=self._cap_iface_var,
                                       state="readonly", width=38,
                                       font=("Consolas", 9))
        self._cap_combo.pack(side="left", padx=(0, 12))

        tk.Label(ctrl, text="BPF Filter:", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 9)).pack(side="left", padx=(0, 4))
        self._cap_filter_entry = tk.Entry(ctrl, textvariable=self._cap_filter_var,
                                width=26, bg=PANEL, fg=TEXT_DIM,
                                insertbackground=TEXT, relief="flat",
                                highlightthickness=1,
                                highlightbackground=BORDER,
                                highlightcolor=ACCENT,
                                font=("Consolas", 9))
        self._cap_filter_entry.pack(side="left", padx=(0, 12), ipady=3)
        # Placeholder behaviour
        self._cap_filter_placeholder = "e.g. tcp port 80"
        self._cap_filter_entry.insert(0, self._cap_filter_placeholder)
        self._cap_filter_entry.bind("<FocusIn>",
            lambda e: self._cap_entry_focus_in(
                self._cap_filter_entry, self._cap_filter_placeholder))
        self._cap_filter_entry.bind("<FocusOut>",
            lambda e: self._cap_entry_focus_out(
                self._cap_filter_entry, self._cap_filter_placeholder))

        self._cap_start_btn = self._make_button(ctrl, "▶  Start", self._cap_start,
                                               style="primary")
        self._cap_start_btn.pack(side="left", padx=3)
        self._cap_stop_btn = self._make_button(ctrl, "■  Stop", self._cap_stop)
        self._cap_stop_btn.pack(side="left", padx=3)
        self._cap_stop_btn.config(state="disabled")

        self._make_button(ctrl, "Clear", self._cap_clear).pack(side="left", padx=3)
        self._make_button(ctrl, "Save .pcap", self._cap_save).pack(side="left", padx=3)

        self._cap_count_lbl = tk.Label(ctrl, text="0 packets", bg=BG, fg=TEXT_DIM,
                                       font=("Consolas", 9))
        self._cap_count_lbl.pack(side="right", padx=8)

        # Status bar
        self._cap_status_lbl = tk.Label(parent, text="  Select an interface and press Start.",
                                        bg=BG, fg=TEXT_DIM, font=("Consolas", 9),
                                        anchor="w")
        self._cap_status_lbl.pack(fill="x", padx=8, pady=(0, 2))

        self._section_label(parent, "CAPTURED PACKETS")

        # Packet table
        cap_cols   = ("Time", "Source", "Destination", "Protocol", "Len", "Summary")
        cap_widths = [95, 155, 155, 72, 55, 400]
        tf = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        tf.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.cap_tree = ttk.Treeview(tf, columns=cap_cols, show="headings",
                                     height=22, style="Guardian.Treeview")
        vtcb = ttk.Scrollbar(tf, orient="vertical", command=self.cap_tree.yview)
        htcb = ttk.Scrollbar(tf, orient="horizontal", command=self.cap_tree.xview)
        self.cap_tree.configure(yscrollcommand=vtcb.set, xscrollcommand=htcb.set)
        htcb.pack(side="bottom", fill="x")
        vtcb.pack(side="right", fill="y")
        self.cap_tree.pack(fill="both", expand=True)
        for col, w in zip(cap_cols, cap_widths):
            self.cap_tree.heading(col, text=col)
            self.cap_tree.column(col, width=w, anchor="w", minwidth=40)
        self.cap_tree.column("Summary", stretch=True)
        self.cap_tree.tag_configure("tcp",      foreground=ACCENT)
        self.cap_tree.tag_configure("udp",      foreground=ACCENT2)
        self.cap_tree.tag_configure("icmp",     foreground=WARN)
        self.cap_tree.tag_configure("arp",      foreground=LAN_COL)
        self.cap_tree.tag_configure("other",    foreground=TEXT_DIM)
        self.cap_tree.tag_configure("row_even", background=PANEL)
        self.cap_tree.tag_configure("row_odd",  background=PANEL_ALT)
        self.cap_tree.bind("<Button-3>", self._show_cap_menu)

    # ── Diagnostics tab ───────────────────────────────────────────────────────

    def _build_diag_tab(self, parent: tk.Frame) -> None:
        """Build the Diagnostics tab with a scrollable log text widget."""
        tk.Label(parent, text="  Environment and error log.",
                 bg=BG, fg=TEXT_DIM, font=("Consolas", 9),
                 anchor="w").pack(fill="x", padx=8, pady=(6, 2))
        frame = tk.Frame(parent, bg=PANEL, highlightthickness=1,
                         highlightbackground=BORDER)
        frame.pack(fill="both", expand=True, padx=8, pady=4)
        self.diag_text = tk.Text(frame, bg=PANEL, fg=TEXT_DIM,
                                 font=("Consolas", 9), wrap="word",
                                 state="disabled", relief="flat",
                                 insertbackground=TEXT)
        vsb = ttk.Scrollbar(frame, command=self.diag_text.yview)
        self.diag_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.diag_text.pack(fill="both", expand=True, padx=4, pady=4)

    # ── UI helpers ────────────────────────────────────────────────────────────

    def _section_label(self, parent: tk.Widget, text: str) -> None:
        """Render a full-width section header with a separator rule."""
        tk.Label(parent, text=f"  {text}", bg=BG, fg=ACCENT,
                 font=("Consolas", 8, "bold"), anchor="w").pack(
                 fill="x", pady=(6, 0))
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=2, pady=(1, 2))

    def _section_label_inline(self, parent: tk.Widget, text: str) -> None:
        """Render an inline (left-packed) section header label."""
        tk.Label(parent, text=f"  {text}", bg=BG, fg=ACCENT,
                 font=("Consolas", 8, "bold"), anchor="w").pack(
                 side="left", pady=(0, 2))

    def _make_button(self, parent: tk.Widget, text: str,
                     command: Callable, style: str = "secondary") -> tk.Button:
        """Create a consistently styled flat button.

        Args:
            parent: Parent widget.
            text: Button label.
            command: Callback for button click.
            style: "primary" (ACCENT fg) or "secondary" (TEXT_DIM fg).

        Returns:
            The configured tk.Button widget (not yet packed).
        """
        fg = ACCENT if style == "primary" else TEXT_DIM
        btn = tk.Button(parent, text=text, bg=PANEL, fg=fg,
                        relief="flat", font=("Consolas", 8),
                        cursor="hand2", activebackground=SEL_BG,
                        activeforeground=TEXT, padx=10, pady=3,
                        command=command,
                        highlightthickness=1,
                        highlightbackground=BORDER)
        btn.bind("<Enter>", lambda e: btn.config(fg=TEXT)
                 if str(btn.cget("state")) != "disabled" else None)
        btn.bind("<Leave>", lambda e: btn.config(fg=fg)
                 if str(btn.cget("state")) != "disabled" else None)
        return btn

    def _log(self, msg: str) -> None:
        """Append a timestamped message to the diagnostics log and file logger."""
        ts   = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"
        self.diag_log.append(line)
        if hasattr(self, "diag_text"):
            self.diag_text.configure(state="normal")
            self.diag_text.insert("end", line)
            self.diag_text.see("end")
            self.diag_text.configure(state="disabled")
        # Forward to the rotating file logger
        if hasattr(self, "_logger"):
            self._logger.info(msg)

    def _sort_by(self, col: str) -> None:
        """Toggle sort order when a column header is clicked."""
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

    def _on_tab_change(self, _event=None) -> None:
        """Populate interface list when the Packet Capture tab is selected."""
        if not HAS_SCAPY:
            return
        try:
            selected = self.nb.tab(self.nb.select(), "text").strip()
            if selected == "Packet Capture" and not self._cap_iface_var.get():
                self._cap_refresh_ifaces()
        except Exception:
            pass

    # ── Refresh: Connections ──────────────────────────────────────────────────

    def _refresh_connections(self) -> None:
        """Update the Connections tab from the latest monitor snapshot."""
        if not HAS_PSUTIL:
            return
        try:
            conns, sent, recv, procs, alerts = self.monitor.snapshot()

            fval = self._filter_var.get()

            def passes(c) -> bool:
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
            self._stats["outbound"].config(text=str(out_n))
            self._stats["inbound"].config(text=str(in_n))
            self._stats["lan_conns"].config(text=str(lan_n))
            self._stats["up"].config(text=format_bytes(sent / 3) + "/s")
            self._stats["dn"].config(text=format_bytes(recv / 3) + "/s")
            self._stats["alerts"].config(text=str(n_warn),
                                         fg=DANGER if n_warn else ACCENT2)

            for item in self.conn_tree.get_children():
                self.conn_tree.delete(item)
            for i, c in enumerate(visible[:300]):
                sem_tag = ("danger"   if c.suspicious          else
                           "inbound"  if c.direction == "INBOUND" else
                           "listen"   if c.direction == "LISTEN"  else
                           "lan"      if c.lan_remote              else
                           "outbound")
                row_tag = "row_even" if i % 2 == 0 else "row_odd"
                lep = f"{c.local_ip}:{c.local_port}"   if c.laddr else "—"
                rep = f"{c.remote_ip}:{c.remote_port}" if c.raddr else "—"
                self.conn_tree.insert("", "end", tags=(sem_tag, row_tag),
                    values=(c.direction, c.scope_label(), lep, rep, c.pname, c.status))

            for item in self.proc_tree.get_children():
                self.proc_tree.delete(item)
            for i, p in enumerate(procs):
                row_tag = "row_even" if i % 2 == 0 else "row_odd"
                self.proc_tree.insert("", "end", tags=(row_tag,),
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

    def _refresh_lan(self) -> None:
        """Update the LAN Scanner tab from the latest scanner snapshot."""
        if not HAS_PSUTIL:
            return
        try:
            devices, scanning, progress, alerts = self.lan_scanner.snapshot()

            # Persist state whenever a scan finishes (scanning → not scanning)
            if self._lan_was_scanning and not scanning:
                self._persistence.save_devices(devices)
                self._persistence.save_lan_alerts(alerts)
            self._lan_was_scanning = scanning

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

            for i, (ip, dev) in enumerate(sorted(
                    devices.items(),
                    key=lambda x: [int(p) for p in x[0].split(".")])):
                if dev.status == "DOWN":
                    sem_tag = "down"
                elif dev.risky:
                    sem_tag = "risky"
                elif dev.is_new:
                    sem_tag = "new"
                else:
                    sem_tag = "normal"
                row_tag = "row_even" if i % 2 == 0 else "row_odd"
                risk_str = "RISKY" if dev.risky else ("NEW" if dev.is_new else "OK")
                self.lan_tree.insert("", "end", tags=(sem_tag, row_tag), values=(
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
                    icon = ["i", "!", "X"][a["level"]]
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

    # ── Context menus ────────────────────────────────────────────────────────

    def _popup_menu(self) -> tk.Menu:
        """Return a new styled popup menu."""
        return tk.Menu(self, tearoff=0,
                       bg=PANEL, fg=TEXT,
                       activebackground=SEL_BG, activeforeground=ACCENT,
                       relief="flat", bd=1)

    def _show_conn_menu(self, event: tk.Event) -> None:
        """Show right-click context menu for the Connections table."""
        item = self.conn_tree.identify_row(event.y)
        if not item:
            return
        self.conn_tree.selection_set(item)
        values = self.conn_tree.item(item, "values")
        if not values:
            return

        # values: (Dir, Scope, "Local IP:Port", "Remote IP:Port", Process, State)
        rep = str(values[3])   # "Remote IP : Port"
        lep = str(values[2])   # "Local IP : Port"
        process = str(values[4])

        remote_ip = rep.rsplit(":", 1)[0] if rep != "—" else ""

        menu = self._popup_menu()

        if remote_ip:
            menu.add_command(
                label=f"  Copy Remote IP          {remote_ip}",
                command=lambda: self._copy(remote_ip))
            menu.add_command(
                label=f"  Copy Remote IP:Port     {rep}",
                command=lambda: self._copy(rep))
            menu.add_separator()
            menu.add_command(
                label=f"  IP Info / Whois →",
                command=lambda: self._whois(remote_ip))
            menu.add_command(
                label=f"  Capture traffic for this host",
                command=lambda: self._start_capture_for(remote_ip))

        if process and process != "?":
            menu.add_separator()
            menu.add_command(
                label=f"  Copy process name       {process}",
                command=lambda: self._copy(process))

        if lep != "—":
            menu.add_separator()
            menu.add_command(
                label=f"  Copy Local IP:Port      {lep}",
                command=lambda: self._copy(lep))

        menu.tk_popup(event.x_root, event.y_root)

    def _show_lan_menu(self, event: tk.Event) -> None:
        """Show right-click context menu for the LAN Scanner table."""
        item = self.lan_tree.identify_row(event.y)
        if not item:
            return
        self.lan_tree.selection_set(item)
        values = self.lan_tree.item(item, "values")
        if not values:
            return

        # values: (IP, Hostname, Device Type, Open Services, Risk, Last Seen)
        ip       = str(values[0])
        hostname = str(values[1])
        services = str(values[3])   # e.g. "HTTP, HTTPS"

        menu = self._popup_menu()
        menu.add_command(
            label=f"  Copy IP                 {ip}",
            command=lambda: self._copy(ip))
        if hostname and hostname != "(unknown)":
            menu.add_command(
                label=f"  Copy hostname           {hostname}",
                command=lambda: self._copy(hostname))
        menu.add_separator()
        menu.add_command(
            label="  IP Info / Whois →",
            command=lambda: self._whois(ip))
        menu.add_command(
            label="  Capture traffic for this host",
            command=lambda: self._start_capture_for(ip))
        # Open in browser if HTTP/HTTPS is available
        if "HTTPS" in services or "HTTP-alt" in services:
            url = f"https://{ip}"
            menu.add_command(
                label=f"  Open in browser (HTTPS) →",
                command=lambda: webbrowser.open(url))
        elif "HTTP" in services:
            url = f"http://{ip}"
            menu.add_command(
                label=f"  Open in browser (HTTP) →",
                command=lambda: webbrowser.open(url))

        menu.tk_popup(event.x_root, event.y_root)

    def _show_cap_menu(self, event: tk.Event) -> None:
        """Show right-click context menu for the Packet Capture table."""
        item = self.cap_tree.identify_row(event.y)
        if not item:
            return
        self.cap_tree.selection_set(item)
        values = self.cap_tree.item(item, "values")
        if not values:
            return

        # values: (Time, Source, Destination, Protocol, Len, Summary)
        src  = str(values[1]).rsplit(":", 1)[0]   # strip port if present
        dst  = str(values[2]).rsplit(":", 1)[0]
        summary = str(values[5])

        menu = self._popup_menu()
        if src:
            menu.add_command(
                label=f"  Copy source             {src}",
                command=lambda: self._copy(src))
            menu.add_command(
                label="  IP Info / Whois (src) →",
                command=lambda: self._whois(src))
            menu.add_command(
                label="  Capture traffic for source",
                command=lambda: self._start_capture_for(src))
        if dst and dst != src:
            menu.add_separator()
            menu.add_command(
                label=f"  Copy destination        {dst}",
                command=lambda: self._copy(dst))
            menu.add_command(
                label="  IP Info / Whois (dst) →",
                command=lambda: self._whois(dst))
        menu.add_separator()
        menu.add_command(
            label="  Copy summary line",
            command=lambda: self._copy(summary))

        menu.tk_popup(event.x_root, event.y_root)

    # ── Context menu helpers ──────────────────────────────────────────────────

    def _copy(self, text: str) -> None:
        """Copy ``text`` to the system clipboard."""
        self.clipboard_clear()
        self.clipboard_append(text)

    def _whois(self, ip: str) -> None:
        """Open a browser tab with IP info for ``ip``."""
        webbrowser.open(f"https://ipinfo.io/{ip}")

    def _start_capture_for(self, ip: str) -> None:
        """Switch to Packet Capture tab and pre-fill BPF filter for ``ip``."""
        # Select the Packet Capture tab (index 2)
        self.nb.select(2)
        bpf = f"host {ip}"
        self._cap_filter_var.set(bpf)
        if hasattr(self, "_cap_filter_entry"):
            self._cap_filter_entry.config(fg=TEXT)
        if not self._cap_iface_var.get():
            self._cap_refresh_ifaces()
        if hasattr(self, "_cap_status_lbl"):
            self._cap_status_lbl.config(
                text=f"  Ready — filter set to '{bpf}'. Press ▶ Start.",
                fg=TEXT_DIM)

    # ── Packet Capture actions ────────────────────────────────────────────────

    def _cap_refresh_ifaces(self) -> None:
        """Populate the interface combobox from PacketCapture.get_interfaces()."""
        ifaces = self.capture.get_interfaces()
        self._cap_iface_map = {i["display"]: i["name"] for i in ifaces}
        values = list(self._cap_iface_map.keys())
        self._cap_combo["values"] = values
        if values and not self._cap_iface_var.get():
            self._cap_iface_var.set(values[0])

    def _cap_entry_focus_in(self, entry: tk.Entry, placeholder: str) -> None:
        """Clear the BPF filter placeholder text on focus."""
        if entry.get() == placeholder:
            entry.delete(0, "end")
            entry.config(fg=TEXT)

    def _cap_entry_focus_out(self, entry: tk.Entry, placeholder: str) -> None:
        """Restore the BPF filter placeholder text when empty."""
        if not entry.get().strip():
            entry.insert(0, placeholder)
            entry.config(fg=TEXT_DIM)

    def _cap_start(self) -> None:
        """Start a packet capture on the selected interface."""
        display = self._cap_iface_var.get()
        if not display:
            self._cap_refresh_ifaces()
            display = self._cap_iface_var.get()
        if not display:
            self._cap_status_lbl.config(
                text="  No interface selected.", fg=WARN)
            return

        scapy_iface = self._cap_iface_map.get(display, display)
        raw_filter = self._cap_filter_var.get().strip()
        placeholder = "e.g. tcp port 80"
        bpf = "" if raw_filter == placeholder else raw_filter

        self._cap_displayed = 0
        err = self.capture.start(scapy_iface, bpf)
        if err:
            self._cap_status_lbl.config(text=f"  Error: {err}", fg=DANGER)
            return

        self._cap_start_btn.config(state="disabled")
        self._cap_stop_btn.config(state="normal")
        filter_note = f"  filter: {bpf}" if bpf else ""
        self._cap_status_lbl.config(
            text=f"  Capturing on {display}{filter_note}", fg=ACCENT2)
        self._cap_poll_id = self.after(500, self._cap_poll)

    def _cap_stop(self) -> None:
        """Stop the active packet capture."""
        if self._cap_poll_id:
            self.after_cancel(self._cap_poll_id)
            self._cap_poll_id = None
        self.capture.stop()
        self._cap_start_btn.config(state="normal")
        self._cap_stop_btn.config(state="disabled")
        count = len(self.cap_tree.get_children())
        self._cap_status_lbl.config(
            text=f"  Stopped. {count} packets displayed.", fg=TEXT_DIM)

    def _cap_clear(self) -> None:
        """Discard all captured packets from memory and the table."""
        self.capture.clear()
        for item in self.cap_tree.get_children():
            self.cap_tree.delete(item)
        self._cap_displayed = 0
        self._cap_count_lbl.config(text="0 packets")
        self._cap_status_lbl.config(
            text="  Cleared.", fg=TEXT_DIM)

    def _cap_save(self) -> None:
        """Open a save dialog and write captured packets to a .pcap file."""
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            title="Save Capture As",
        )
        if not path:
            return
        count = self.capture.save_pcap(path)
        if count >= 0:
            self._cap_status_lbl.config(
                text=f"  Saved {count} packets to {path}", fg=ACCENT2)
        else:
            self._cap_status_lbl.config(
                text="  Error saving file — check diagnostics.", fg=DANGER)

    def _cap_poll(self) -> None:
        """Poll captured packets every 500 ms and update the table."""
        try:
            packets = self.capture.snapshot()
            new_pkts = packets[self._cap_displayed: self._cap_displayed + 200]

            if new_pkts:
                # Remove oldest rows if over display cap
                children = self.cap_tree.get_children()
                overflow = (len(children) + len(new_pkts)) - 2000
                if overflow > 0:
                    self.cap_tree.delete(*children[:overflow])

                for pkt in new_pkts:
                    i = self._cap_displayed
                    proto_tag = pkt.protocol.lower() if pkt.protocol.lower() in (
                        "tcp", "udp", "icmp", "arp") else "other"
                    row_tag = "row_even" if i % 2 == 0 else "row_odd"
                    self.cap_tree.insert("", "end", tags=(proto_tag, row_tag),
                        values=(pkt.timestamp, pkt.src, pkt.dst,
                                pkt.protocol, pkt.length, pkt.summary))
                    self._cap_displayed += 1

                # Auto-scroll to bottom
                self.cap_tree.yview_moveto(1.0)

            self._cap_count_lbl.config(text=f"{len(packets)} packets")
        except Exception as e:
            self._log(f"_cap_poll error: {e}\n{traceback.format_exc()}")

        if self.capture.running:
            self._cap_poll_id = self.after(500, self._cap_poll)

    # ── LAN / Connection actions ──────────────────────────────────────────────

    def _manual_lan_scan(self) -> None:
        """Trigger an immediate LAN scan in a background thread."""
        self.lan_status_lbl.config(text="  Manual scan triggered...", fg=WARN)
        threading.Thread(target=self.lan_scanner._full_scan, daemon=True).start()

    def _clear_conn_alerts(self) -> None:
        """Clear all connection monitor alerts."""
        with self.monitor.lock:
            self.monitor.alerts.clear()
        self._refresh_connections()

    def _clear_lan_alerts(self) -> None:
        """Clear all LAN scanner alerts."""
        with self.lan_scanner.lock:
            self.lan_scanner.alerts.clear()
        self._refresh_lan()

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def on_close(self) -> None:
        """Persist state, stop all background threads, and destroy the window."""
        if hasattr(self, "lan_scanner") and hasattr(self, "_persistence"):
            devices, _, _, alerts = self.lan_scanner.snapshot()
            self._persistence.save_devices(devices)
            self._persistence.save_lan_alerts(alerts)
        if hasattr(self, "monitor"):
            self.monitor.stop()
        if hasattr(self, "lan_scanner"):
            self.lan_scanner.stop()
        if hasattr(self, "capture"):
            self.capture.stop()
        self.destroy()
