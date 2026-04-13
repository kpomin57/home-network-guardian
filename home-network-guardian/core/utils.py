"""
Utility functions and constants for the Home Network Guardian.

Provides network helpers (ping, port probing, DNS lookup, LAN detection)
and shared threshold constants used across core modules.
"""

import socket
import ipaddress
import subprocess
import platform
from typing import List, Tuple

try:
    import psutil
    HAS_PSUTIL: bool = True
except ImportError:
    HAS_PSUTIL: bool = False

# ── Alert thresholds ──────────────────────────────────────────────────────────
ALERT_CONN_COUNT: int = 50
ALERT_MB_PER_MIN: int = 50

# Ports considered suspicious on outbound connections
SUSPICIOUS_PORTS: set = {4444, 1337, 6667, 31337, 12345, 9999, 3389, 5900, 23}

# Common ports to probe during LAN scan (fast fingerprint)
PROBE_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 548, 554, 631, 993, 995, 1883,
    3306, 3389, 5000, 5900, 8080, 8443, 8888, 9100,
]

# Ports that indicate elevated risk when open on a LAN device
RISKY_PORTS: set = {23, 135, 139, 445, 3389, 5900}

# Private network ranges used for LAN detection
_PRIVATE_NETS: List[ipaddress.IPv4Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]

# Port number → service name mapping
PORT_LABELS: dict = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 548: "AFP", 554: "RTSP", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1883: "MQTT", 3306: "MySQL",
    3389: "RDP", 5000: "UPnP", 5900: "VNC", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "HTTP-dev", 9100: "Print",
}


def is_lan(ip_str: str) -> bool:
    """Return True if the IP address belongs to a private/LAN range.

    Args:
        ip_str: IPv4 address string to check.

    Returns:
        True if the address is in a private range, False otherwise.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in n for n in _PRIVATE_NETS)
    except ValueError:
        return False


def format_bytes(b: float) -> str:
    """Convert a byte count to a human-readable string.

    Args:
        b: Number of bytes.

    Returns:
        Formatted string such as "1.4 MB" or "512.0 B".
    """
    for unit in ("B", "KB", "MB", "GB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def get_local_ips() -> List[Tuple[str, str]]:
    """Return (ip, netmask) pairs for all non-loopback IPv4 interfaces.

    Returns:
        List of (ip_address, netmask) tuples.
    """
    addrs: List[Tuple[str, str]] = []
    try:
        for _iface, snics in psutil.net_if_addrs().items():
            for snic in snics:
                if snic.family == socket.AF_INET:
                    ip = snic.address
                    if not ip.startswith("127."):
                        addrs.append((ip, snic.netmask or "255.255.255.0"))
    except Exception:
        pass
    return addrs


def cidr_hosts(ip: str, netmask: str) -> List[str]:
    """Return all host IPs in the subnet, capped at /24 for safety.

    Args:
        ip: Any IP address within the target subnet.
        netmask: Subnet mask string (e.g., "255.255.255.0").

    Returns:
        List of host IP address strings.
    """
    try:
        net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        if net.prefixlen < 24:
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return [str(h) for h in net.hosts()]
    except Exception:
        return []


def ping(ip: str, timeout: float = 0.5) -> bool:
    """Return True if the host responds to a single ICMP ping.

    Args:
        ip: Target IP address string.
        timeout: Unused parameter kept for API compatibility.

    Returns:
        True if ping succeeds, False otherwise.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
    timeout_val = "500" if platform.system().lower() == "windows" else "1"
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


def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    """Perform a reverse DNS lookup; return empty string on failure.

    Args:
        ip: Target IP address string.
        timeout: Socket timeout in seconds.

    Returns:
        Resolved hostname string, or "" if lookup fails.
    """
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)


def probe_ports(ip: str, ports: List[int], timeout: float = 0.3) -> List[int]:
    """Return the subset of ports that are open on the target host.

    Args:
        ip: Target IP address string.
        ports: List of port numbers to probe.
        timeout: TCP connect timeout in seconds.

    Returns:
        List of open port numbers.
    """
    open_ports: List[int] = []
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


def describe_ports(open_ports: List[int]) -> str:
    """Format a list of port numbers as human-readable service names.

    Args:
        open_ports: List of open port numbers.

    Returns:
        Comma-separated service names, or "none" if the list is empty.
    """
    if not open_ports:
        return "none"
    return ", ".join(PORT_LABELS.get(p, str(p)) for p in sorted(open_ports))


def guess_device_type(open_ports: List[int], hostname: str) -> str:
    """Infer a device type from its open ports and hostname.

    Args:
        open_ports: List of detected open port numbers.
        hostname: Reverse-DNS hostname (may be empty).

    Returns:
        Human-readable device type string.
    """
    p = set(open_ports)
    h = hostname.lower()
    if 9100 in p:
        return "Printer"
    if 554 in p or 8554 in p:
        return "IP Camera"
    if 1883 in p:
        return "IoT Device"
    if 5900 in p:
        return "VNC Host"
    if 3389 in p:
        return "Windows PC (RDP)"
    if 22 in p and 80 not in p:
        return "Linux/Mac"
    if 445 in p or 139 in p:
        return "Windows PC"
    if 548 in p:
        return "Mac (AFP)"
    if 80 in p or 443 in p:
        return "Web Server / Router"
    if "iphone" in h or "ipad" in h:
        return "Apple Device"
    if "android" in h:
        return "Android Device"
    if "router" in h or "gateway" in h:
        return "Router"
    return "Unknown"
