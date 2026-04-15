"""
LAN scanner for the Home Network Guardian.

LanScanner runs as a background thread, performing a full subnet
ping-sweep and port-probe every 2 minutes to discover and monitor
devices on the local network.
"""

import threading
import time
import traceback
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from core.models import LanDevice
from core.utils import (
    PROBE_PORTS,
    RISKY_PORTS,
    SUSPICIOUS_PORT_INFO,
    cidr_hosts,
    get_local_ips,
    ping,
    probe_ports,
    resolve_hostname,
)


class LanScanner:
    """Periodically scans the local subnet for active devices.

    Performs ping-sweeps, port-probes, and reverse-DNS lookups.
    Tracks new and disappeared devices, and raises alerts for
    newly discovered or high-risk hosts.

    Attributes:
        lock: Threading lock protecting shared state.
        devices: Mapping of IP string → LanDevice.
        alerts: List of alert dicts (newest first, max 200).
        running: True while the background thread is active.
        scanning: True during an active scan.
        scan_progress: Human-readable progress string for the UI.
        on_update: Optional callback invoked after each completed scan.
    """

    def __init__(
        self,
        log_fn: Optional[Callable[[str], None]] = None,
        on_update: Optional[Callable[[], None]] = None,
    ) -> None:
        """Initialise the LAN scanner.

        Args:
            log_fn: Optional callable that accepts a log message string.
            on_update: Optional callback invoked after each scan completes.
        """
        self.lock: threading.Lock = threading.Lock()
        self.devices: Dict[str, LanDevice] = {}
        self.alerts: List[dict] = []
        self.running: bool = False
        self.scanning: bool = False
        self.scan_progress: str = ""
        self._log: Callable[[str], None] = log_fn or (lambda m: None)
        self.on_update: Optional[Callable[[], None]] = on_update
        self._known_ips: set = set()

    def start(self) -> None:
        """Start the background scanning thread."""
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self) -> None:
        """Signal the background thread to stop."""
        self.running = False

    def _loop(self) -> None:
        """Main scan loop; performs a full scan then waits 2 minutes."""
        while self.running:
            try:
                self._full_scan()
            except Exception as e:
                self._log(f"LAN scan error: {e}\n{traceback.format_exc()}")
            for _ in range(120):
                if not self.running:
                    return
                time.sleep(1)

    def _full_scan(self) -> None:
        """Perform one complete subnet discovery cycle.

        Enumerates local interfaces, ping-sweeps each subnet,
        port-probes live hosts, updates device records, and
        inserts alerts for new or risky devices.
        """
        local_addrs = get_local_ips()
        if not local_addrs:
            self._log("LAN Scanner: no local IP addresses found.")
            return

        all_hosts: List[str] = []
        for ip, mask in local_addrs:
            hosts = cidr_hosts(ip, mask)
            self._log(f"LAN Scanner: scanning {len(hosts)} hosts on {ip}/{mask}")
            all_hosts.extend(hosts)

        seen: set = set()
        unique_hosts = [h for h in all_hosts if not (h in seen or seen.add(h))]

        with self.lock:
            self.scanning = True
            self.scan_progress = f"0 / {len(unique_hosts)}"

        with self.lock:
            for dev in self.devices.values():
                dev.status = "DOWN"

        results: Dict[str, Tuple[str, List[int]]] = {}
        results_lock = threading.Lock()

        def scan_one(ip: str) -> None:
            if not ping(ip):
                return
            hostname = resolve_hostname(ip)
            open_ports = probe_ports(ip, PROBE_PORTS)
            with results_lock:
                results[ip] = (hostname, open_ports)

        threads: List[threading.Thread] = []
        for ip in unique_hosts:
            if not self.running:
                break
            t = threading.Thread(target=scan_one, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
            if len([t for t in threads if t.is_alive()]) >= 30:
                time.sleep(0.1)

        for t in threads:
            t.join(timeout=5)

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
                        "detail": (
                            f"Hostname: {hostname or 'unknown'}  |  "
                            f"Type: {dev.device_type}  |  "
                            f"Open ports: {dev.port_summary()}"
                        ),
                    })

                if dev.risky:
                    risky_open = sorted(
                        p for p in dev.open_ports if p in RISKY_PORTS
                    )
                    lines = []
                    for port in risky_open:
                        info = SUSPICIOUS_PORT_INFO.get(port)
                        if info:
                            lines.append(
                                f"• {port} ({info['name']}): {info['why']}"
                            )
                        else:
                            lines.append(f"• {port}: risky port — no standard service.")
                    self.alerts.insert(0, {
                        "ts":     datetime.now().strftime("%H:%M:%S"),
                        "level":  2,
                        "title":  f"Risky ports open on {ip}"
                                  + (f" ({dev.hostname})" if dev.hostname else ""),
                        "detail": "\n".join(lines),
                    })

            self.alerts = self.alerts[:200]
            self.scanning = False
            self.scan_progress = f"{len(results)} devices found"

        if self.on_update:
            self.on_update()

    def snapshot(self) -> Tuple[Dict[str, LanDevice], bool, str, List[dict]]:
        """Return a thread-safe snapshot of the current scanner state.

        Returns:
            (devices, scanning, scan_progress, alerts) tuple.
        """
        with self.lock:
            return (
                dict(self.devices),
                self.scanning,
                self.scan_progress,
                list(self.alerts),
            )
