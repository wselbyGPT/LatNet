"""Main window implementation for the LatNet browser application."""

from PyQt6.QtCore import QUrl

from latnet_browser.url_utils import normalize_user_url
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import QLineEdit, QMainWindow, QStatusBar, QToolBar


class BrowserWindow(QMainWindow):
    """Top-level window for the standalone browser application."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("LatNet Browser")
        self.resize(1024, 768)

        self._web_view = QWebEngineView(self)
        self.setCentralWidget(self._web_view)

        self._address_bar = QLineEdit(self)
        self._address_bar.setPlaceholderText("Enter URL")
        self._address_bar.returnPressed.connect(self._navigate_to_address_bar_url)

        self._toolbar = QToolBar("Navigation", self)
        self.addToolBar(self._toolbar)

        self._toolbar.addAction("Back", self._web_view.back)
        self._toolbar.addAction("Forward", self._web_view.forward)
        self._toolbar.addAction("Reload", self._web_view.reload)
        self._toolbar.addAction("Home", self._navigate_home)
        self._toolbar.addWidget(self._address_bar)

        self.setStatusBar(QStatusBar(self))
        self._web_view.urlChanged.connect(self._sync_address_bar)
        self._web_view.loadStarted.connect(self._on_load_started)
        self._web_view.loadProgress.connect(self._on_load_progress)
        self._web_view.loadFinished.connect(self._on_load_finished)

        self._navigate_home()

    def _navigate_to_address_bar_url(self) -> None:
        """Navigate to the URL currently entered in the address bar."""
        url = normalize_user_url(self._address_bar.text())
        if url is None:
            self.statusBar().showMessage("Invalid URL", 3000)
            return

        self._web_view.setUrl(url)

    def _navigate_home(self) -> None:
        """Navigate to the default home URL."""
        self._web_view.setUrl(QUrl("https://example.com"))

    def _sync_address_bar(self, url: QUrl) -> None:
        """Update the address bar when browser URL changes."""
        self._address_bar.setText(url.toString())

    def _on_load_started(self) -> None:
        """Update status UI when a page load starts."""
        self.statusBar().showMessage("Loading...")

    def _on_load_progress(self, progress: int) -> None:
        """Update status UI with load progress percentage."""
        self.statusBar().showMessage(f"Loading... {progress}%")

    def _on_load_finished(self, success: bool) -> None:
        """Update status UI when a page load finishes."""
        message = "Done" if success else "Failed to load page"
        self.statusBar().showMessage(message, 3000)
