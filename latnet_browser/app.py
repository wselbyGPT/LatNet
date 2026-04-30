"""QApplication bootstrap and main event loop for the LatNet browser."""

import sys

from PyQt6.QtWidgets import QApplication

from .main_window import BrowserWindow


def run() -> int:
    """Start the browser UI process and block until the app exits."""
    app = QApplication(sys.argv)
    window = BrowserWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(run())
