"""
Main GUI application for the Home Network Guardian.

App extends tk.Tk and wires together the NetworkMonitor and LanScanner
background threads with a three-tab Tkinter interface:
  - Connections  — live view of this PC's network activity
  - LAN Scanner  — discovered devices on the local network
  - Diagnostics  — error log and environment info
"""

import platform
import sys
import threading
import traceback
import tkinter as tk
from datetime import datetime
from tkinter import ttk
from typing import Optional

from core.alerts import LEVEL_COLOR_KEYS
from core.monitor import NetworkMonitor
from core.scanner import LanScanner
from core.utils import HAS_PSUTIL, format_bytes

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

# ── Color palette ─────────────────────────────────────────────────────────────
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

# Map alert level integer → actual color string
LEVEL_COLOR: dict = {0: ACCENT, 1: WARN, 2: DANGER}


class App(tk.Tk):
    """Main GUI application window for the Home Network Guardian.

    Launches NetworkMonitor and LanScanner background threads and
    presents their data in a three-tab Tkinter notebook.
    """

    def __init__(self) -> None:
        """Initialise the window, styles, UI, and background threads."""
        super().__init__()
        self.title("Home Network Guardian")
        self.geometry("1300x800")
        self.minsize(1000, 600)
        self.configure(bg=BG)
        self.resizable(True, True)

        self.diag_log: list = []
        self._filter_var = tk.StringVar(value="ALL")
        self._sort_col = "remote_ip"
        self._sort_rev = False
        self._sort_key = lambda c: (c.remote_ip, c.remote_port)

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
            on_update=lambda: self.after(0, self._refresh_lan),
        )
        self.lan_scanner.start()

        self._refresh_connections()

    # ── Styles ────────────────────────────────────────────────────────────────

    def _setup_styles(self) -> None:
        """Configure ttk styles for the dark theme."""
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

    def _build_ui(self) -> None:
        """Build the main window layout: header, stats bar, and notebook."""
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
        self._stats: dict = {}
        for key, label in [
            ("total",    "Total Conns"),
            ("outbound", "Outbound"),
            ("inbound",  "Inbound"),
            ("lan_conns","LAN Conns"),
            ("up",       "Upload/s"),
            ("dn",       "Download/s"),
            ("alerts",   "Alerts"),
        ]:
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

    def _build_connections_tab(self, parent: tk.Frame) -> None:
        """Build the Connections tab with table, process list, and alerts.

        Args:
            parent: The tab frame to populate.
        """
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
        aw = self.alert_canvas.create_window((0, 0), window=self.alert_inner, anchor="nw")
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

    def _build_lan_tab(self, parent: tk.Frame) -> None:
        """Build the LAN Scanner tab with device table and alerts.

        Args:
            parent: The tab frame to populate.
        """
        paned = tk.PanedWindow(parent, orient="horizontal", bg=BG,
                               sashwidth=6, sashrelief="flat")
        paned.pack(fill="both", expand=True)
        left  = tk.Frame(paned, bg=BG)
        right = tk.Frame(paned, bg=BG)
        paned.add(left,  minsize=720)
        paned.add(right, minsize=260)

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
        self.lan_tree.tag_configure("down",   foreground=TEXT_DIM)

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
            (0, 0), window=self.lan_alert_inner, anchor="nw")
        self.lan_alert_inner.bind("<Configure>",
            lambda e: self.lan_alert_canvas.configure(
                scrollregion=self.lan_alert_canvas.bbox("all")))
        self.lan_alert_canvas.bind("<Configure>",
            lambda e: self.lan_alert_canvas.itemconfig(law, width=e.width))

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

    def _build_diag_tab(self, parent: tk.Frame) -> None:
        """Build the Diagnostics tab with a scrollable log text widget.

        Args:
            parent: The tab frame to populate.
        """
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

    # ── UI helpers ────────────────────────────────────────────────────────────

    def _section_label(self, parent: tk.Widget, text: str) -> None:
        """Render a full-width section header label.

        Args:
            parent: Parent widget.
            text: Header text.
        """
        tk.Label(parent, text=f"  {text}", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8, "bold"), anchor="w").pack(
                 fill="x", pady=(6, 1))

    def _section_label_inline(self, parent: tk.Widget, text: str) -> None:
        """Render an inline (left-packed) section header label.

        Args:
            parent: Parent widget.
            text: Header text.
        """
        tk.Label(parent, text=f"  {text}", bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8, "bold"), anchor="w").pack(
                 side="left", pady=(0, 2))

    def _log(self, msg: str) -> None:
        """Append a timestamped message to the diagnostics log.

        Args:
            msg: Message text to log.
        """
        ts   = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"
        self.diag_log.append(line)
        if hasattr(self, "diag_text"):
            self.diag_text.configure(state="normal")
            self.diag_text.insert("end", line)
            self.diag_text.see("end")
            self.diag_text.configure(state="disabled")

    def _sort_by(self, col: str) -> None:
        """Toggle sort order by column header click.

        Args:
            col: Column name string.
        """
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

    def _manual_lan_scan(self) -> None:
        """Trigger an immediate LAN scan in a background thread."""
        self.lan_status_lbl.config(text="  Manual scan triggered...", fg=WARN)
        threading.Thread(target=self.lan_scanner._full_scan, daemon=True).start()

    # ── Refresh: Connections ──────────────────────────────────────────────────

    def _refresh_connections(self) -> None:
        """Update the Connections tab from the latest monitor snapshot."""
        if not HAS_PSUTIL:
            return
        try:
            conns, sent, recv, procs, alerts = self.monitor.snapshot()
            self.clock_lbl.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))

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
            self._stats["outbound"].config(text=str(out_n),  fg=WAN_COL)
            self._stats["inbound"].config(text=str(in_n),    fg=ACCENT)
            self._stats["lan_conns"].config(text=str(lan_n), fg=LAN_COL)
            self._stats["up"].config(text=format_bytes(sent / 3) + "/s")
            self._stats["dn"].config(text=format_bytes(recv / 3) + "/s")
            self._stats["alerts"].config(text=str(n_warn),
                                         fg=DANGER if n_warn else ACCENT2)

            for item in self.conn_tree.get_children():
                self.conn_tree.delete(item)
            for c in visible[:300]:
                tag = ("danger"   if c.suspicious          else
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

    def _refresh_lan(self) -> None:
        """Update the LAN Scanner tab from the latest scanner snapshot."""
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

    # ── Actions ───────────────────────────────────────────────────────────────

    def _clear_conn_alerts(self) -> None:
        """Clear all connection monitor alerts and refresh the panel."""
        with self.monitor.lock:
            self.monitor.alerts.clear()
        self._refresh_connections()

    def _clear_lan_alerts(self) -> None:
        """Clear all LAN scanner alerts and refresh the panel."""
        with self.lan_scanner.lock:
            self.lan_scanner.alerts.clear()
        self._refresh_lan()

    def on_close(self) -> None:
        """Stop background threads and destroy the window."""
        if hasattr(self, "monitor"):
            self.monitor.stop()
        if hasattr(self, "lan_scanner"):
            self.lan_scanner.stop()
        self.destroy()
