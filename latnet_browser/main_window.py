"""Main window implementation for the LatNet browser application."""

from urllib.parse import quote_plus

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWebEngineCore import QWebEngineProfile
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QCheckBox,
    QPushButton,
    QStatusBar,
    QToolButton,
    QToolBar,
    QVBoxLayout,
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
        self._site_info_button = QToolButton(self)
        self._site_info_button.setText("🔒")
        self._site_info_button.setToolTip("Site permissions")
        self._site_info_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._site_info_menu = QMenu(self)
        self._site_info_menu.addAction("Site Permissions...", self._open_current_site_permissions)
        self._site_info_button.setMenu(self._site_info_menu)
        self._toolbar.addWidget(self._site_info_button)
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
        self._permissions_action = self._settings_menu.addAction("Site Permissions...", self._open_permissions_editor)

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
        self._bind_permission_signals()

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
        self._permissions_action.setEnabled(False)

    def _bind_permission_signals(self) -> None:
        """Connect page/profile permission request hooks when available."""
        if hasattr(self._profile, "permissionRequested"):
            self._profile.permissionRequested.connect(self._handle_permission_request)

    def _permission_descriptor(self, permission: object) -> tuple[str, str]:
        """Derive stable key + user-facing label for a permission request object."""
        permission_type = getattr(permission, "permissionType", None)
        type_value = permission_type() if callable(permission_type) else permission_type
        key = str(type_value)
        label = key.split(".")[-1] if "." in key else key
        return key, label

    def _permission_origin(self, permission: object) -> str:
        origin_accessor = getattr(permission, "origin", None)
        origin = origin_accessor() if callable(origin_accessor) else origin_accessor
        if isinstance(origin, QUrl):
            return origin.toString()
        return str(origin or "")

    def _set_permission_state(self, permission: object, allow: bool) -> None:
        decision_enum = getattr(type(permission), "State", None)
        if decision_enum is not None and hasattr(permission, "setState"):
            state = decision_enum.PermissionGrantedByUser if allow else decision_enum.PermissionDeniedByUser
            permission.setState(state)
            return
        if allow and hasattr(permission, "grant"):
            permission.grant()
            return
        if not allow and hasattr(permission, "deny"):
            permission.deny()

    def _handle_permission_request(self, permission: object) -> None:
        origin = self._permission_origin(permission)
        permission_key, permission_label = self._permission_descriptor(permission)
        if not origin:
            self._set_permission_state(permission, False)
            return

        saved_decision = self._settings.get_permission_decision(origin, permission_key)
        if saved_decision in {"allow", "deny"}:
            self._set_permission_state(permission, saved_decision == "allow")
            self.statusBar().showMessage(f"Applied saved decision for {permission_label} on {origin}", 2500)
            return

        dialog = QMessageBox(self)
        dialog.setWindowTitle("Permission Request")
        dialog.setText(f"{origin} wants access to: {permission_label}")
        remember = QCheckBox("Remember for this site", dialog)
        dialog.setCheckBox(remember)
        allow_action = dialog.addButton("Allow", QMessageBox.ButtonRole.AcceptRole)
        deny_action = dialog.addButton("Deny", QMessageBox.ButtonRole.RejectRole)
        dialog.setDefaultButton(deny_action)
        dialog.exec()

        allow = dialog.clickedButton() is allow_action
        self._set_permission_state(permission, allow)
        if remember.isChecked() and self._can_persist("Saving permission decision"):
            self._settings.set_permission_decision(origin, permission_key, "allow" if allow else "deny")

    def _open_current_site_permissions(self) -> None:
        current_origin = self._current_view().url().adjusted(QUrl.UrlFormattingOption.RemovePath).toString()
        self._open_permissions_editor(current_origin)

    def _open_permissions_editor(self, origin_filter: str | None = None) -> None:
        permissions = self._settings.get_site_permissions()
        dialog = QDialog(self)
        dialog.setWindowTitle("Site Permissions")
        layout = QVBoxLayout(dialog)

        if not permissions:
            layout.addWidget(QLabel("No saved site permissions."))
            close_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
            close_box.rejected.connect(dialog.reject)
            close_box.accepted.connect(dialog.accept)
            layout.addWidget(close_box)
            dialog.exec()
            return

        list_widget = QListWidget(dialog)
        for origin, permission_map in sorted(permissions.items()):
            if origin_filter and origin_filter not in origin:
                continue
            for permission_type, decision in sorted(permission_map.items()):
                item = QListWidgetItem(f"{origin} | {permission_type} -> {decision}")
                item.setData(256, (origin, permission_type))
                list_widget.addItem(item)
        layout.addWidget(list_widget)

        form = QFormLayout()
        decision_input = QLineEdit(dialog)
        decision_input.setPlaceholderText("allow or deny")
        form.addRow("New Decision", decision_input)
        layout.addLayout(form)

        update_button = QPushButton("Update Selected", dialog)
        remove_button = QPushButton("Remove Selected", dialog)
        layout.addWidget(update_button)
        layout.addWidget(remove_button)

        def _update_selected() -> None:
            item = list_widget.currentItem()
            if item is None:
                return
            value = decision_input.text().strip().lower()
            if value not in {"allow", "deny"}:
                self.statusBar().showMessage("Decision must be 'allow' or 'deny'", 2500)
                return
            origin, permission_type = item.data(256)
            permissions.setdefault(origin, {})[permission_type] = value
            self._settings.set_site_permissions(permissions)
            item.setText(f"{origin} | {permission_type} -> {value}")

        def _remove_selected() -> None:
            item = list_widget.currentItem()
            if item is None:
                return
            origin, permission_type = item.data(256)
            if origin in permissions and permission_type in permissions[origin]:
                del permissions[origin][permission_type]
                if not permissions[origin]:
                    del permissions[origin]
                self._settings.set_site_permissions(permissions)
            list_widget.takeItem(list_widget.row(item))

        update_button.clicked.connect(_update_selected)
        remove_button.clicked.connect(_remove_selected)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        buttons.accepted.connect(dialog.accept)
        layout.addWidget(buttons)
        dialog.resize(640, 420)
        dialog.exec()

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
