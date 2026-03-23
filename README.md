# 🛡 Home Network Guardian

A lightweight Windows network monitoring tool built with Python. Monitor your home network for suspicious activity, discover all devices on your LAN, and get alerted to unusual traffic patterns.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Connection Monitor** — Live view of all inbound/outbound connections on this PC, with process names, local/remote endpoints, direction, and state
- **LAN Scanner** — Discovers all devices on your local network via ping sweep and port probing. Identifies device types, open services, and flags new or risky devices
- **Alerts** — Automatic warnings for suspicious ports, high connection counts, high upload rates, new unknown devices, and risky open ports (RDP, VNC, Telnet, SMB)
- **Filtering & Sorting** — Filter connections by direction (inbound/outbound), scope (LAN/WAN), or suspicious status
- **Diagnostics tab** — Built-in error log showing environment info and any runtime errors

## Screenshots

*(Add screenshots here after first run)*

## Requirements

- Windows 10 or 11
- Python 3.9 or later (tested on 3.14)
- [psutil](https://pypi.org/project/psutil/)

## Installation

**1. Install Python** (if not already installed)

Download from [python.org](https://www.python.org/downloads/). During install, check **"Add Python to PATH"**.

**2. Install the dependency**

```
pip install psutil
```

**3. Clone or download this repo**

```
git clone https://github.com/YOUR_USERNAME/home-network-guardian.git
cd home-network-guardian
```

**4. Run the monitor**

Double-click `launch_monitor.bat`, or run directly:

```
python network_monitor.py
```

> **Tip:** For full visibility into all connections, right-click `launch_monitor.bat` and choose **Run as administrator**. The tool works without admin rights but may miss some system-level connections.

## Usage

### Connections Tab
Shows every active network connection on your PC in real time (updates every 3 seconds).

| Column | Meaning |
|---|---|
| Dir | OUTBOUND (your PC called out), INBOUND (something called in), LISTEN |
| Scope | WAN (internet), LAN (local network) |
| Local IP : Port | Which port on your machine is involved |
| Remote IP : Port | The other end of the connection |
| Process | Which program owns the connection |
| State | ESTABLISHED, TIME_WAIT, etc. |

Use the filter bar to narrow down to **Inbound**, **WAN only**, or **Suspicious** connections.

### LAN Scanner Tab
Scans your entire local subnet every 2 minutes (or click **Scan Now**).

- Pings every address in your subnet to find live hosts
- Probes 26 common service ports on each live host
- Reverse DNS lookup for friendly hostnames
- Guesses device type (Windows PC, Printer, IP Camera, Router, etc.)
- **Alerts on new devices** — anything that wasn't on the network before
- **Alerts on risky ports** — RDP, VNC, Telnet, and SMB flagged as potentially dangerous

### Alerts
Both tabs have their own alert panel. Alerts are colour-coded:
- 🔴 **Red** — High severity (suspicious ports, risky services)
- 🟡 **Yellow** — Warning (new device, high upload rate)

## Limitations

- The LAN Scanner can see *what* devices are on your network and *what ports they have open*, but cannot see the content or volume of traffic from other devices. For per-device traffic monitoring you would need router-level access or a dedicated network tap.
- Packet capture of other devices' traffic requires either a managed switch with port mirroring, or a device acting as the network gateway (e.g. a Raspberry Pi router).
- Scanning your own network is legal and normal. Do not use this tool to scan networks you do not own or have permission to monitor.

## License

MIT — see [LICENSE](LICENSE)
