"""
Persistence layer for the Home Network Guardian.

Saves and loads LAN device records and alert history as JSON files in the
application's data directory so state survives application restarts.

File layout:
    data/
    ├── devices.json   — discovered LAN devices
    └── lan_alerts.json — LAN scanner alert history
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from core.models import LanDevice

logger = logging.getLogger("guardian")


class PersistenceManager:
    """Saves and loads application state to/from JSON files in data_dir.

    All public methods are safe to call from any thread; file I/O is
    synchronous and intentionally lightweight (the data sets are small).
    Corrupted or missing files are handled gracefully — load methods
    return empty state and log a warning rather than raising.

    Attributes:
        data_dir: Directory where JSON files are stored.
    """

    _DEVICES_FILE    = "devices.json"
    _LAN_ALERTS_FILE = "lan_alerts.json"

    def __init__(self, data_dir: Path) -> None:
        """Initialise the persistence manager.

        Args:
            data_dir: Directory path for data files. Created on first save
                      if it does not exist.
        """
        self.data_dir: Path = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)

    # ── LAN Devices ───────────────────────────────────────────────────────────

    def save_devices(self, devices: Dict[str, LanDevice]) -> None:
        """Serialise and persist the current device map to disk.

        Args:
            devices: Mapping of IP string → LanDevice.
        """
        path = self.data_dir / self._DEVICES_FILE
        payload = [_device_to_dict(dev) for dev in devices.values()]
        _write_json(path, payload)
        logger.debug("Saved %d device(s) to %s", len(payload), path)

    def load_devices(self) -> Tuple[Dict[str, LanDevice], set]:
        """Load persisted devices from disk.

        Returns:
            A (devices_dict, known_ips) tuple where ``devices_dict`` maps
            IP → LanDevice and ``known_ips`` is a set of all IPs ever seen,
            ready to be injected into LanScanner._known_ips.
            Both are empty on failure.
        """
        path = self.data_dir / self._DEVICES_FILE
        raw = _read_json(path, default=[])
        if not isinstance(raw, list):
            logger.warning("Corrupt devices file — ignoring: %s", path)
            return {}, set()

        devices: Dict[str, LanDevice] = {}
        known_ips: set = set()
        for entry in raw:
            try:
                dev = _dict_to_device(entry)
                devices[dev.ip] = dev
                known_ips.add(dev.ip)
            except Exception as exc:
                logger.warning("Skipping malformed device entry: %s", exc)

        logger.info("Loaded %d persisted device(s) from %s", len(devices), path)
        return devices, known_ips

    # ── LAN Alerts ────────────────────────────────────────────────────────────

    def save_lan_alerts(self, alerts: List[dict]) -> None:
        """Persist LAN scanner alerts to disk (newest first, max 200).

        Args:
            alerts: List of alert dicts as produced by LanScanner.
        """
        path = self.data_dir / self._LAN_ALERTS_FILE
        _write_json(path, alerts[:200])
        logger.debug("Saved %d LAN alert(s) to %s", len(alerts), path)

    def load_lan_alerts(self) -> List[dict]:
        """Load persisted LAN alerts from disk.

        Returns:
            List of alert dicts, or [] on failure.
        """
        path = self.data_dir / self._LAN_ALERTS_FILE
        raw = _read_json(path, default=[])
        if not isinstance(raw, list):
            logger.warning("Corrupt LAN alerts file — ignoring: %s", path)
            return []
        logger.info("Loaded %d persisted LAN alert(s) from %s", len(raw), path)
        return raw


# ── Serialisation helpers ─────────────────────────────────────────────────────

def _device_to_dict(dev: LanDevice) -> dict:
    """Convert a LanDevice to a JSON-serialisable dict."""
    return {
        "ip":          dev.ip,
        "hostname":    dev.hostname,
        "open_ports":  dev.open_ports,
        "device_type": dev.device_type,
        "first_seen":  dev.first_seen,
        "last_seen":   dev.last_seen,
        "status":      dev.status,
        "risky":       dev.risky,
        # is_new is always False for persisted devices
    }


def _dict_to_device(d: dict) -> LanDevice:
    """Reconstruct a LanDevice from a persisted dict.

    Loaded devices are marked as DOWN (status will be confirmed on the next
    scan) and is_new is False (they were seen before the restart).
    """
    dev = LanDevice(d["ip"])
    dev.hostname    = d.get("hostname", "")
    dev.open_ports  = d.get("open_ports", [])
    dev.device_type = d.get("device_type", "?")
    dev.first_seen  = d.get("first_seen", dev.first_seen)
    dev.last_seen   = d.get("last_seen", dev.last_seen)
    dev.status      = "DOWN"   # confirmed alive only after next scan
    dev.is_new      = False    # not new — we've seen this before
    dev.risky       = d.get("risky", False)
    return dev


# ── File I/O helpers ──────────────────────────────────────────────────────────

def _write_json(path: Path, data) -> None:
    """Write ``data`` to ``path`` as indented JSON, atomically via a temp file."""
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
        tmp.replace(path)
    except Exception as exc:
        logger.error("Failed to write %s: %s", path, exc)
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def _read_json(path: Path, default):
    """Read and parse JSON from ``path``, returning ``default`` on any error."""
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return default
