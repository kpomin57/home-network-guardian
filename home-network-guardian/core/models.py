"""
Data models for the Home Network Guardian.

Defines LanDevice (a discovered host on the local network) and
Connection (a single active network connection from this PC).
"""

from datetime import datetime
from typing import Optional, Tuple

from core.utils import (
    RISKY_PORTS,
    SUSPICIOUS_PORTS,
    describe_ports,
    guess_device_type,
    is_lan,
)


class LanDevice:
    """Represents a device discovered on the local network.

    Attributes:
        ip: IP address of the device.
        hostname: Reverse-DNS hostname (may be empty).
        open_ports: List of detected open port numbers.
        device_type: Inferred device category string.
        first_seen: Timestamp string (HH:MM:SS) of first discovery.
        last_seen: Timestamp string (HH:MM:SS) of most recent scan.
        status: "UP" or "DOWN".
        is_new: True on the first scan that found this device.
        risky: True if any risky ports are open.
    """

    def __init__(self, ip: str) -> None:
        """Initialise a new LanDevice with the given IP address.

        Args:
            ip: IPv4 address string for this device.
        """
        self.ip: str = ip
        self.hostname: str = ""
        self.open_ports: list = []
        self.device_type: str = "?"
        self.first_seen: str = datetime.now().strftime("%H:%M:%S")
        self.last_seen: str = self.first_seen
        self.status: str = "UP"
        self.is_new: bool = True
        self.risky: bool = False

    def update(self, hostname: str, open_ports: list) -> None:
        """Refresh device info after a scan.

        Args:
            hostname: Reverse-DNS name (may be empty string).
            open_ports: List of port numbers found open.
        """
        self.hostname = hostname
        self.open_ports = open_ports
        self.device_type = guess_device_type(open_ports, hostname)
        self.last_seen = datetime.now().strftime("%H:%M:%S")
        self.status = "UP"
        self.risky = bool(set(open_ports) & RISKY_PORTS)

    def port_summary(self) -> str:
        """Return a human-readable list of open services.

        Returns:
            Comma-separated service names, or "none".
        """
        return describe_ports(self.open_ports)


class Connection:
    """Represents a single active network connection on this PC.

    Attributes:
        laddr: (ip, port) local address tuple, or None.
        raddr: (ip, port) remote address tuple, or None.
        status: Connection state string (e.g., "ESTABLISHED", "LISTEN").
        pid: Process ID owning the connection.
        pname: Process name owning the connection.
        lan_local: True if the local address is in a private range.
        lan_remote: True if the remote address is in a private range.
        direction: "LISTEN", "OUTBOUND", or "INBOUND".
        suspicious: True if the remote port is in SUSPICIOUS_PORTS.
    """

    def __init__(
        self,
        laddr: Optional[Tuple[str, int]],
        raddr: Optional[Tuple[str, int]],
        status: str,
        pid: int,
        pname: str,
    ) -> None:
        """Initialise a Connection from raw socket data.

        Args:
            laddr: Local (ip, port) tuple, or None.
            raddr: Remote (ip, port) tuple, or None.
            status: Connection state string.
            pid: Owning process ID.
            pname: Owning process name.
        """
        self.laddr = laddr
        self.raddr = raddr
        self.status = status
        self.pid = pid
        self.pname = pname

        lip = laddr[0] if laddr else ""
        rip = raddr[0] if raddr else ""
        self.lan_local: bool = is_lan(lip) if lip else True
        self.lan_remote: bool = is_lan(rip) if rip else False

        if status == "LISTEN":
            self.direction = "LISTEN"
        elif raddr:
            lport = laddr[1] if laddr else 0
            rport = raddr[1] if raddr else 0
            self.direction = "OUTBOUND" if (rport < 1024 or lport > 1024) else "INBOUND"
        else:
            self.direction = "UNKNOWN"

        rport = raddr[1] if raddr else 0
        self.suspicious: bool = rport in SUSPICIOUS_PORTS

    @property
    def remote_ip(self) -> str:
        """Remote IP address string, or empty string if unavailable."""
        return self.raddr[0] if self.raddr else ""

    @property
    def remote_port(self) -> int:
        """Remote port number, or 0 if unavailable."""
        return self.raddr[1] if self.raddr else 0

    @property
    def local_ip(self) -> str:
        """Local IP address string, or empty string if unavailable."""
        return self.laddr[0] if self.laddr else ""

    @property
    def local_port(self) -> int:
        """Local port number, or 0 if unavailable."""
        return self.laddr[1] if self.laddr else 0

    def scope_label(self) -> str:
        """Return a display label for the connection scope.

        Returns:
            "LISTENING", "LAN", or "WAN".
        """
        if self.direction == "LISTEN":
            return "LISTENING"
        return "LAN" if self.lan_remote else "WAN"
