"""Main window implementation for the LatNet browser application."""

from PyQt6.QtWidgets import QLabel, QMainWindow


class BrowserWindow(QMainWindow):
    """Top-level window for the standalone browser application."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("LatNet Browser")
        self.resize(1024, 768)
        self.setCentralWidget(QLabel("LatNet Browser UI scaffold"))
