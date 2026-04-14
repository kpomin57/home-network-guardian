"""
Packet capture backend for the Home Network Guardian.

Uses Scapy's AsyncSniffer to capture packets on a selected interface.
Falls back gracefully when scapy is not installed.

Windows note: requires Npcap (https://npcap.com/) and Administrator privileges.
"""

import threading
from collections import deque
from datetime import datetime
from typing import Callable, Dict, List, Optional

try:
    from scapy.all import (  # type: ignore
        AsyncSniffer,
        get_if_list,
        get_if_addr,
        wrpcap,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        ARP,
    )
    HAS_SCAPY: bool = True
except ImportError:
    HAS_SCAPY: bool = False

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

# Maximum packets kept in memory
MAX_PACKETS = 5000

# TCP flag bit → label mapping
_TCP_FLAGS: Dict[str, str] = {
    "F": "FIN", "S": "SYN", "R": "RST",
    "P": "PSH", "A": "ACK", "U": "URG",
    "E": "ECE", "C": "CWR",
}


class CapturedPacket:
    """A single captured network packet, parsed for display.

    Attributes:
        timestamp: Capture time formatted as HH:MM:SS.mmm.
        src: Source IP address (or MAC if no IP layer).
        dst: Destination IP address (or MAC if no IP layer).
        protocol: Protocol string ("TCP", "UDP", "ICMP", "ARP", "Other").
        length: Raw packet length in bytes.
        summary: One-line human-readable description.
    """

    def __init__(
        self,
        timestamp: str,
        src: str,
        dst: str,
        protocol: str,
        length: int,
        summary: str,
    ) -> None:
        self.timestamp = timestamp
        self.src = src
        self.dst = dst
        self.protocol = protocol
        self.length = length
        self.summary = summary

    @classmethod
    def from_scapy(cls, pkt) -> "CapturedPacket":
        """Construct a CapturedPacket from a raw Scapy packet object.

        Args:
            pkt: Raw Scapy packet.

        Returns:
            A new CapturedPacket instance.
        """
        ts = datetime.now().strftime("%H:%M:%S.") + f"{datetime.now().microsecond // 1000:03d}"

        # Determine IP layer
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
        elif pkt.haslayer(ARP):
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst
        else:
            src = getattr(getattr(pkt, "src", None), "__str__", lambda: str(getattr(pkt, "src", "?")))()
            dst = getattr(getattr(pkt, "dst", None), "__str__", lambda: str(getattr(pkt, "dst", "?")))()

        # Determine protocol and build summary
        if pkt.haslayer(TCP):
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = _decode_tcp_flags(pkt[TCP].flags)
            flag_str = f" [{flags}]" if flags else ""
            summary = f"TCP {src}:{sport} → {dst}:{dport}{flag_str}"
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            summary = f"UDP {src}:{sport} → {dst}:{dport}"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            icmp_type = pkt[ICMP].type
            summary = f"ICMP {src} → {dst} type={icmp_type}"
        elif pkt.haslayer(ARP):
            proto = "ARP"
            op = "who-has" if pkt[ARP].op == 1 else "is-at"
            summary = f"ARP {op} {dst} tell {src}"
        else:
            proto = "Other"
            summary = pkt.summary()[:80]

        length = len(pkt)
        return cls(ts, src, dst, proto, length, summary)


def _decode_tcp_flags(flags) -> str:
    """Convert Scapy TCP flags to a readable string like 'SYN, ACK'.

    Args:
        flags: Scapy TCP flags field.

    Returns:
        Comma-separated flag names, or empty string.
    """
    try:
        flag_str = str(flags)
        active = [_TCP_FLAGS[f] for f in flag_str if f in _TCP_FLAGS]
        return ", ".join(active)
    except Exception:
        return ""


class PacketCapture:
    """Manages live packet capture on a selected network interface.

    Uses Scapy's AsyncSniffer in a background thread. Thread-safe
    access to captured packets via snapshot().

    Attributes:
        running: True while a capture is active.
    """

    def __init__(self, log_fn: Optional[Callable[[str], None]] = None) -> None:
        """Initialise the capture engine.

        Args:
            log_fn: Optional callable for log messages.
        """
        self._log: Callable[[str], None] = log_fn or (lambda m: None)
        self._lock: threading.Lock = threading.Lock()
        self._packets: deque = deque(maxlen=MAX_PACKETS)
        self._raw_packets: deque = deque(maxlen=MAX_PACKETS)
        self._sniffer = None
        self.running: bool = False
        # Maps display name → scapy interface name
        self._iface_map: Dict[str, str] = {}

    def get_interfaces(self) -> List[Dict[str, str]]:
        """Return available network interfaces with display metadata.

        Resolves the IP of each Scapy interface and cross-references
        with psutil for a human-friendly display name.

        Returns:
            List of dicts with keys: "name" (Scapy iface), "ip", "display".
        """
        if not HAS_SCAPY:
            return []

        # Build IP → psutil name map
        ip_to_psutil: Dict[str, str] = {}
        if psutil:
            try:
                for iface_name, snics in psutil.net_if_addrs().items():
                    import socket
                    for snic in snics:
                        if snic.family == socket.AF_INET and not snic.address.startswith("127."):
                            ip_to_psutil[snic.address] = iface_name
            except Exception:
                pass

        result: List[Dict[str, str]] = []
        self._iface_map = {}

        try:
            for scapy_name in get_if_list():
                try:
                    ip = get_if_addr(scapy_name)
                except Exception:
                    ip = ""

                if not ip or ip == "0.0.0.0":
                    continue

                friendly = ip_to_psutil.get(ip, scapy_name)
                display = f"{friendly}  ({ip})"
                self._iface_map[display] = scapy_name

                result.append({
                    "name":    scapy_name,
                    "ip":      ip,
                    "display": display,
                })
        except Exception as e:
            self._log(f"get_interfaces error: {e}")

        return result

    def start(self, iface: str, bpf_filter: str = "") -> Optional[str]:
        """Start capturing packets on the given interface.

        Args:
            iface: Scapy interface name.
            bpf_filter: Optional BPF filter string (e.g., "tcp port 80").

        Returns:
            None on success, or an error message string on failure.
        """
        if not HAS_SCAPY:
            return "scapy is not installed."
        if self.running:
            return "Capture already running."

        try:
            kwargs = {"iface": iface, "prn": self._on_packet, "store": False}
            if bpf_filter.strip():
                kwargs["filter"] = bpf_filter.strip()

            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            self.running = True
            self._log(f"Packet capture started on {iface}"
                      + (f" filter='{bpf_filter}'" if bpf_filter.strip() else ""))
            return None
        except PermissionError:
            return "Permission denied — run as Administrator."
        except Exception as e:
            self._log(f"Capture start error: {e}")
            return str(e)

    def stop(self) -> None:
        """Stop the active capture."""
        if not self.running:
            return
        try:
            if self._sniffer:
                self._sniffer.stop()
                self._sniffer = None
        except Exception as e:
            self._log(f"Capture stop error: {e}")
        finally:
            self.running = False
            self._log("Packet capture stopped.")

    def clear(self) -> None:
        """Discard all captured packets from memory."""
        with self._lock:
            self._packets.clear()
            self._raw_packets.clear()

    def snapshot(self) -> List[CapturedPacket]:
        """Return a thread-safe copy of all captured packets.

        Returns:
            List of CapturedPacket objects, oldest first.
        """
        with self._lock:
            return list(self._packets)

    def save_pcap(self, filepath: str) -> int:
        """Write captured packets to a .pcap file.

        Args:
            filepath: Destination file path.

        Returns:
            Number of packets written, or -1 on error.
        """
        if not HAS_SCAPY:
            return -1
        try:
            with self._lock:
                raw = list(self._raw_packets)
            wrpcap(filepath, raw)
            self._log(f"Saved {len(raw)} packets to {filepath}")
            return len(raw)
        except Exception as e:
            self._log(f"save_pcap error: {e}")
            return -1

    def _on_packet(self, pkt) -> None:
        """Callback invoked by AsyncSniffer for each captured packet.

        Args:
            pkt: Raw Scapy packet.
        """
        try:
            parsed = CapturedPacket.from_scapy(pkt)
            with self._lock:
                self._packets.append(parsed)
                self._raw_packets.append(pkt)
        except Exception as e:
            self._log(f"Packet parse error: {e}")
