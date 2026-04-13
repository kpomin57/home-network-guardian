"""
Network monitor for the Home Network Guardian.

NetworkMonitor runs as a background thread, polling psutil for active
connections, I/O counters, and per-process statistics every 3 seconds.
"""

import threading
import time
import traceback
from typing import Callable, List, Optional, Tuple

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

from core.alerts import Alert
from core.models import Connection
from core.utils import ALERT_CONN_COUNT, ALERT_MB_PER_MIN, SUSPICIOUS_PORTS


class NetworkMonitor:
    """Background monitor for this PC's active network connections and I/O.

    Polls psutil every 3 seconds to collect connections, calculate
    sent/received byte deltas, rank top processes, and generate alerts.

    Attributes:
        running: True while the background thread is active.
        lock: Threading lock protecting shared state.
        alerts: List of Alert objects (newest first, max 200).
        conns: List of Connection objects from the last poll.
        proc_data: Top 25 processes by remote connection count.
        sent_delta: Bytes sent in the last 3-second window.
        recv_delta: Bytes received in the last 3-second window.
        on_update: Optional callback invoked after each successful poll.
    """

    def __init__(self, log_fn: Optional[Callable[[str], None]] = None) -> None:
        """Initialise the monitor.

        Args:
            log_fn: Optional callable that accepts a log message string.
        """
        self.running: bool = False
        self.lock: threading.Lock = threading.Lock()
        self.alerts: List[Alert] = []
        self.conns: List[Connection] = []
        self.proc_data: List[dict] = []
        self.sent_delta: int = 0
        self.recv_delta: int = 0
        self._prev_io = None
        self._log: Callable[[str], None] = log_fn or (lambda m: None)
        self.on_update: Optional[Callable[[], None]] = None

    def start(self) -> None:
        """Start the background polling thread."""
        self.running = True
        try:
            self._prev_io = psutil.net_io_counters(pernic=False)
        except Exception as e:
            self._log(f"Initial net_io_counters failed: {e}")
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self) -> None:
        """Signal the background thread to stop."""
        self.running = False

    def _loop(self) -> None:
        """Main polling loop; runs until stop() is called."""
        while self.running:
            try:
                self._poll()
            except Exception as e:
                self._log(f"Poll error: {e}\n{traceback.format_exc()}")
            time.sleep(3)

    def _poll(self) -> None:
        """Perform one poll cycle: collect connections, I/O, and alerts."""
        pid_names: dict = {}
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
        procs = self._get_processes(pid_names, new_conns)
        new_alerts = self._check_alerts(new_conns, sent)

        with self.lock:
            self.conns = new_conns
            self.sent_delta = sent
            self.recv_delta = recv
            self.proc_data = procs
            for a in new_alerts:
                self._add_alert(a)

        if self.on_update:
            self.on_update()

    def _get_connections(self, pid_names: dict) -> List[Connection]:
        """Fetch all inet connections, filtering out localhost.

        Args:
            pid_names: Mapping of PID → process name.

        Returns:
            List of Connection objects.
        """
        result: List[Connection] = []
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
                pid = c.pid or 0
                conn = Connection(
                    laddr, raddr, c.status or "?",
                    pid, pid_names.get(pid, "?"),
                )
                result.append(conn)
            except Exception as e:
                self._log(f"Connection parse error: {e}")
        return result

    def _get_io_delta(self) -> Tuple[int, int]:
        """Calculate bytes sent/received since the last call.

        Returns:
            (sent_bytes, recv_bytes) tuple.
        """
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

    def _get_processes(self, pid_names: dict, conns: List[Connection]) -> List[dict]:
        """Build the top 25 processes sorted by remote connection count.

        Args:
            pid_names: Mapping of PID → process name.
            conns: Current list of connections.

        Returns:
            List of dicts with keys "pid", "name", "conn_count".
        """
        counts: dict = {}
        for c in conns:
            if c.raddr and c.direction != "LISTEN":
                counts[c.pid] = counts.get(c.pid, 0) + 1
        result = [
            {"pid": pid, "name": pid_names.get(pid, "?"), "conn_count": n}
            for pid, n in counts.items()
        ]
        return sorted(result, key=lambda x: -x["conn_count"])[:25]

    def _check_alerts(self, conns: List[Connection], sent_delta: int) -> List[Alert]:
        """Generate alerts for suspicious activity in the current snapshot.

        Args:
            conns: Current list of connections.
            sent_delta: Bytes sent in the last 3-second window.

        Returns:
            List of new Alert objects.
        """
        new: List[Alert] = []

        ip_counts: dict = {}
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

    def _add_alert(self, alert: Alert) -> None:
        """Add an alert, deduplicating against the last 20 entries.

        Args:
            alert: The Alert to append.
        """
        for a in self.alerts[-20:]:
            if a.title == alert.title:
                return
        self.alerts.insert(0, alert)
        self.alerts = self.alerts[:200]

    def snapshot(self) -> Tuple[List[Connection], int, int, List[dict], List[Alert]]:
        """Return a thread-safe snapshot of the current monitor state.

        Returns:
            (conns, sent_delta, recv_delta, proc_data, alerts) tuple.
        """
        with self.lock:
            return (
                list(self.conns),
                self.sent_delta,
                self.recv_delta,
                list(self.proc_data),
                list(self.alerts),
            )
