"""Main window implementation for the LatNet browser application."""

from urllib.parse import quote_plus

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWebEngineCore import QWebEngineProfile
from PyQt6.QtWidgets import (
    QInputDialog,
    QLineEdit,
    QMainWindow,
    QMenu,
    QProgressBar,
    QStatusBar,
    QToolBar,
)

from latnet_browser.downloads import DownloadManager
from latnet_browser.settings import BrowserSettings
from latnet_browser.tabs import BrowserTab, BrowserTabWidget
from latnet_browser.url_utils import normalize_user_url


class BrowserWindow(QMainWindow):
    """Top-level window for the standalone browser application."""

    _APP_TITLE = "LatNet Browser"

    def __init__(self, incognito: bool = False) -> None:
        super().__init__()
        self._incognito = incognito
        self._settings = BrowserSettings()
        self._profile = self._build_profile()
        self.resize(1024, 768)

        self._download_manager = DownloadManager(
            self._profile,
            self._settings.get_recent_downloads(),
            self,
        )
        self._download_manager.bind_profile_signals()
        self._download_manager.downloadUpdated.connect(self._persist_recent_downloads)

        self._tab_widget = BrowserTabWidget(self._profile, self)
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
        self._toolbar.addAction("Bookmark This Page", self._bookmark_current_page)
        self._toolbar.addAction("Downloads", self._show_downloads)
        self._manage_bookmarks_action = self._toolbar.addAction("Manage Bookmarks", self._manage_bookmarks)

        self._bookmarks_toolbar = QToolBar("Bookmarks", self)
        self.addToolBar(self._bookmarks_toolbar)
        self._bookmarks_toolbar.setMovable(False)
        self._bookmarks_toolbar.setFloatable(False)

        self._tools_menu = self.menuBar().addMenu("Tools")
        self._tools_menu.addAction("Downloads", self._show_downloads)
        self._tools_menu.addAction("New Incognito Window", self._open_incognito_window)

        self._settings_menu = self.menuBar().addMenu("Settings")
        self._set_homepage_action = self._settings_menu.addAction("Set Homepage...", self._prompt_for_homepage)
        self._set_search_action = self._settings_menu.addAction("Set Search Engine...", self._prompt_for_search_template)

        self.setStatusBar(QStatusBar(self))
        self._load_progress = QProgressBar(self)
        self._load_progress.setRange(0, 100)
        self._load_progress.setValue(0)
        self._load_progress.setTextVisible(False)
        self._load_progress.setFixedWidth(140)
        self._load_progress.hide()
        self.statusBar().addPermanentWidget(self._load_progress)
        self._active_tab: BrowserTab | None = None
        self._tab_widget.currentTabChanged.connect(self._bind_to_tab)
        self._bind_to_tab(self._tab_widget.current_browser_tab())
        self._refresh_bookmarks_toolbar()
        self._apply_mode_styling()
        self._refresh_mode_actions()

        self._navigate_home()

    def _build_profile(self) -> QWebEngineProfile:
        """Create the profile attached to all tabs for this window."""
        if not self._incognito:
            return QWebEngineProfile.defaultProfile()

        profile = QWebEngineProfile(self)
        profile.setOffTheRecord(True)
        return profile

    def _open_incognito_window(self) -> None:
        """Spawn a new browser window in incognito mode."""
        window = BrowserWindow(incognito=True)
        window.show()

    def _apply_mode_styling(self) -> None:
        """Apply title/theme affordances for incognito browsing mode."""
        if not self._incognito:
            return
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor(35, 35, 35))
        palette.setColor(QPalette.ColorRole.Base, QColor(50, 50, 50))
        palette.setColor(QPalette.ColorRole.Text, QColor(235, 235, 235))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(235, 235, 235))
        self.setPalette(palette)

    def _refresh_mode_actions(self) -> None:
        """Enable/disable persistent state UI based on browsing mode."""
        if not self._incognito:
            return
        self._set_homepage_action.setEnabled(False)
        self._set_search_action.setEnabled(False)
        self._manage_bookmarks_action.setEnabled(False)

    def _can_persist(self, operation: str) -> bool:
        """Return whether a settings write is allowed for this window mode."""
        if not self._incognito:
            return True
        self.statusBar().showMessage(f"{operation} is disabled in incognito mode", 3000)
        return False

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
        raw_input = self._address_bar.text().strip()
        url = normalize_user_url(raw_input)
        if url is None:
            self._current_view().setUrl(self._build_search_url(raw_input))
            return
        self._current_view().setUrl(url)

    def _navigate_home(self) -> None:
        self._current_view().setUrl(normalize_user_url(self._settings.get_homepage_url()) or QUrl("https://example.com"))

    def _build_search_url(self, query: str) -> QUrl:
        template = self._settings.get_search_template()
        search_value = quote_plus(query)
        search_candidate = template.replace("{query}", search_value)
        return normalize_user_url(search_candidate) or QUrl("https://duckduckgo.com/?q=" + search_value)

    def _prompt_for_homepage(self) -> None:
        value, accepted = QInputDialog.getText(self, "Set Homepage", "Homepage URL:", text=self._settings.get_homepage_url())
        if not accepted:
            return
        url = normalize_user_url(value)
        if url is None:
            self.statusBar().showMessage("Invalid homepage URL", 3000)
            return
        if not self._can_persist("Updating homepage"):
            return
        self._settings.set_homepage_url(url.toString())
        self.statusBar().showMessage("Homepage updated", 3000)

    def _prompt_for_search_template(self) -> None:
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
        if not self._can_persist("Updating search engine"):
            return
        self._settings.set_search_template(candidate)
        self.statusBar().showMessage("Search engine updated", 3000)

    def _bookmark_current_page(self) -> None:
        if not self._can_persist("Saving bookmarks"):
            return
        current_url = self._current_view().url().toString().strip()
        validated_url = normalize_user_url(current_url)
        if validated_url is None:
            self.statusBar().showMessage("Cannot bookmark invalid URL", 3000)
            return
        title = self._current_view().title().strip() or validated_url.toString()
        bookmarks = self._settings.get_bookmarks()
        normalized_url = validated_url.toString()
        for bookmark in bookmarks:
            if bookmark["url"] == normalized_url:
                bookmark["title"] = title
                self._settings.set_bookmarks(bookmarks)
                self._refresh_bookmarks_toolbar()
                self.statusBar().showMessage("Bookmark updated", 3000)
                return
        bookmarks.append({"title": title, "url": normalized_url})
        self._settings.set_bookmarks(bookmarks)
        self._refresh_bookmarks_toolbar()
        self.statusBar().showMessage("Page bookmarked", 3000)

    def _manage_bookmarks(self) -> None:
        if not self._can_persist("Managing bookmarks"):
            return
        bookmarks = self._settings.get_bookmarks()
        if not bookmarks:
            self.statusBar().showMessage("No bookmarks to manage", 3000)
            return
        menu = QMenu(self)
        for bookmark in bookmarks:
            action = menu.addAction(f"Remove: {bookmark['title']} ({bookmark['url']})")
            action.triggered.connect(lambda _checked=False, url=bookmark["url"]: self._remove_bookmark_by_url(url))
        menu.exec(self.mapToGlobal(self._toolbar.geometry().bottomLeft()))

    def _remove_bookmark_by_url(self, bookmark_url: str) -> None:
        if not self._can_persist("Removing bookmarks"):
            return
        bookmarks = self._settings.get_bookmarks()
        updated_bookmarks = [entry for entry in bookmarks if entry["url"] != bookmark_url]
        if len(updated_bookmarks) == len(bookmarks):
            return
        self._settings.set_bookmarks(updated_bookmarks)
        self._refresh_bookmarks_toolbar()
        self.statusBar().showMessage("Bookmark removed", 3000)

    def _refresh_bookmarks_toolbar(self) -> None:
        self._bookmarks_toolbar.clear()
        for bookmark in self._settings.get_bookmarks():
            action = self._bookmarks_toolbar.addAction(bookmark["title"])
            action.setToolTip(bookmark["url"])
            action.triggered.connect(lambda _checked=False, url=bookmark["url"]: self._open_bookmark(url))

    def _open_bookmark(self, bookmark_url: str) -> None:
        url = normalize_user_url(bookmark_url)
        if url is None:
            self.statusBar().showMessage("Invalid bookmark URL", 3000)
            return
        self._current_view().setUrl(url)

    def _sync_address_bar(self, url: QUrl) -> None:
        self._address_bar.setText(url.toString())

    def _on_load_started(self) -> None:
        self._load_progress.setRange(0, 0)
        self._load_progress.show()
        self.statusBar().showMessage("Loading...")

    def _on_load_progress(self, progress: int) -> None:
        self._load_progress.setRange(0, 100)
        self._load_progress.setValue(progress)
        self.statusBar().showMessage(f"Loading... {progress}%")

    def _on_load_finished(self, success: bool) -> None:
        self._load_progress.hide()
        self._load_progress.setRange(0, 100)
        self._load_progress.setValue(0)
        self.statusBar().showMessage("Done" if success else "Failed to load page", 3000)

    def _on_title_changed(self, title: str) -> None:
        app_title = f"{self._APP_TITLE} (Incognito)" if self._incognito else self._APP_TITLE
        page_title = title.strip()
        if page_title:
            self.setWindowTitle(f"{page_title} - {app_title}")
            return
        self.setWindowTitle(app_title)

    def _show_downloads(self) -> None:
        self._download_manager.show_dialog(self)

    def _persist_recent_downloads(self) -> None:
        if not self._can_persist("Persisting download history"):
            return
        self._settings.set_recent_downloads(self._download_manager.recent_downloads)
