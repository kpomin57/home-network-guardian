"""
Home Network Guardian — entry point.

Usage:
    python main.py

Requires: pip install psutil
Run as Administrator for full connection visibility.
"""

from ui.app import App


def main() -> None:
    """Launch the Home Network Guardian application."""
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()
