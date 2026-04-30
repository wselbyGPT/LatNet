"""Main window implementation for the LatNet browser application."""

from urllib.parse import quote_plus

from PyQt6.QtCore import QUrl
from PyQt6.QtWidgets import QInputDialog, QLineEdit, QMainWindow, QStatusBar, QToolBar

from latnet_browser.tabs import BrowserTab, BrowserTabWidget

from latnet_browser.settings import BrowserSettings
from latnet_browser.url_utils import normalize_user_url


class BrowserWindow(QMainWindow):
    """Top-level window for the standalone browser application."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("LatNet Browser")
        self.resize(1024, 768)

        self._settings = BrowserSettings()

        self._tab_widget = BrowserTabWidget(self)
        self.setCentralWidget(self._tab_widget)

        self._address_bar = QLineEdit(self)
        self._address_bar.setPlaceholderText("Enter URL")
        self._address_bar.returnPressed.connect(self._navigate_to_address_bar_url)

        self._toolbar = QToolBar("Navigation", self)
        self.addToolBar(self._toolbar)

        self._toolbar.addAction("Back", self._navigate_back)
        self._toolbar.addAction("Forward", self._navigate_forward)
        self._toolbar.addAction("Reload", self._reload)
        self._toolbar.addAction("Home", self._navigate_home)
        self._toolbar.addWidget(self._address_bar)

        self._settings_menu = self.menuBar().addMenu("Settings")
        self._settings_menu.addAction("Set Homepage...", self._prompt_for_homepage)
        self._settings_menu.addAction("Set Search Engine...", self._prompt_for_search_template)

        self.setStatusBar(QStatusBar(self))
        self._active_tab: BrowserTab | None = None
        self._tab_widget.currentTabChanged.connect(self._bind_to_tab)
        self._bind_to_tab(self._tab_widget.current_browser_tab())

        self._navigate_home()


    def _bind_to_tab(self, tab: BrowserTab | None) -> None:
        """Connect window-level UI updates to the selected tab."""
        if self._active_tab is not None:
            self._active_tab.titleChanged.disconnect(self._on_title_changed)
            self._active_tab.urlChanged.disconnect(self._sync_address_bar)
            self._active_tab.loadStarted.disconnect(self._on_load_started)
            self._active_tab.loadProgress.disconnect(self._on_load_progress)
            self._active_tab.loadFinished.disconnect(self._on_load_finished)

        self._active_tab = tab
        if tab is None:
            self._on_title_changed("")
            return

        tab.titleChanged.connect(self._on_title_changed)
        tab.urlChanged.connect(self._sync_address_bar)
        tab.loadStarted.connect(self._on_load_started)
        tab.loadProgress.connect(self._on_load_progress)
        tab.loadFinished.connect(self._on_load_finished)
        self._on_title_changed(tab.view.title())
        self._sync_address_bar(tab.view.url())

    def _current_view(self):
        tab = self._tab_widget.current_browser_tab()
        if tab is None:
            tab = self._tab_widget.add_browser_tab(make_current=True)
        return tab.view

    def _navigate_back(self) -> None:
        self._current_view().back()

    def _navigate_forward(self) -> None:
        self._current_view().forward()

    def _reload(self) -> None:
        self._current_view().reload()

    def _navigate_to_address_bar_url(self) -> None:
        """Navigate to the URL currently entered in the address bar."""
        raw_input = self._address_bar.text().strip()
        url = normalize_user_url(raw_input)
        if url is None:
            search_url = self._build_search_url(raw_input)
            self._current_view().setUrl(search_url)
            return

        self._current_view().setUrl(url)

    def _navigate_home(self) -> None:
        """Navigate to the default home URL."""
        self._current_view().setUrl(normalize_user_url(self._settings.get_homepage_url()) or QUrl("https://example.com"))


    def _build_search_url(self, query: str) -> QUrl:
        """Build a search URL for non-URL address bar input."""
        template = self._settings.get_search_template()
        search_value = quote_plus(query)
        search_candidate = template.replace("{query}", search_value)
        return normalize_user_url(search_candidate) or QUrl("https://duckduckgo.com/?q=" + search_value)

    def _prompt_for_homepage(self) -> None:
        """Open a prompt allowing the user to set a homepage URL."""
        value, accepted = QInputDialog.getText(
            self,
            "Set Homepage",
            "Homepage URL:",
            text=self._settings.get_homepage_url(),
        )
        if not accepted:
            return

        url = normalize_user_url(value)
        if url is None:
            self.statusBar().showMessage("Invalid homepage URL", 3000)
            return

        self._settings.set_homepage_url(url.toString())
        self.statusBar().showMessage("Homepage updated", 3000)

    def _prompt_for_search_template(self) -> None:
        """Open a prompt allowing the user to set a search URL template."""
        value, accepted = QInputDialog.getText(
            self,
            "Set Search Engine",
            "Search template (use {query}):",
            text=self._settings.get_search_template(),
        )
        if not accepted:
            return

        candidate = value.strip()
        if not candidate or "{query}" not in candidate:
            self.statusBar().showMessage("Search template must include {query}", 3000)
            return

        validation_url = normalize_user_url(candidate.replace("{query}", "test"))
        if validation_url is None:
            self.statusBar().showMessage("Invalid search template URL", 3000)
            return

        self._settings.set_search_template(candidate)
        self.statusBar().showMessage("Search engine updated", 3000)

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

    def _on_title_changed(self, title: str) -> None:
        """Update the main window title from the active page title."""
        page_title = title.strip()
        if page_title:
            self.setWindowTitle(f"{page_title} - LatNet Browser")
            return

        self.setWindowTitle("LatNet Browser")
