"""
Alert model and related constants for the Home Network Guardian.

An Alert represents a security event detected by either the connection
monitor or the LAN scanner.
"""

from datetime import datetime

# UI color constants referenced when rendering alerts
from core.utils import SUSPICIOUS_PORTS  # noqa: F401 (re-exported for UI use)

# Color keys matched to severity levels (used by the UI layer)
LEVEL_COLOR_KEYS: dict = {0: "accent", 1: "warn", 2: "danger"}


class Alert:
    """A single security alert produced by a monitor or scanner.

    Severity levels:
        0 — informational
        1 — warning
        2 — danger

    Attributes:
        ts: Timestamp string (HH:MM:SS) when the alert was created.
        level: Severity level integer (0, 1, or 2).
        title: Short alert title string.
        detail: Extended description string.
    """

    ICONS: list = ["i", "!", "X"]

    def __init__(self, level: int, title: str, detail: str) -> None:
        """Create a new Alert with the current timestamp.

        Args:
            level: Severity level (0=info, 1=warn, 2=danger).
            title: Short description of the alert.
            detail: Extended detail message.
        """
        self.ts: str = datetime.now().strftime("%H:%M:%S")
        self.level: int = level
        self.title: str = title
        self.detail: str = detail

    def label(self) -> str:
        """Return a formatted header string for display.

        Returns:
            String in the format "[X]  [HH:MM:SS]  <title>".
        """
        return f"[{self.ICONS[self.level]}]  [{self.ts}]  {self.title}"
