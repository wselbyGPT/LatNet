"""Tab management widgets for the LatNet browser application."""

from __future__ import annotations

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import QTabWidget, QWidget


class BrowserTab(QObject):
    """Wrapper around a single :class:`QWebEngineView` instance."""

    urlChanged = pyqtSignal(object)
    loadStarted = pyqtSignal()
    loadProgress = pyqtSignal(int)
    loadFinished = pyqtSignal(bool)
    titleChanged = pyqtSignal(str)

    def __init__(self, profile: QWebEngineProfile, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.view = QWebEngineView()
        self.view.setPage(QWebEnginePage(profile, self.view))
        self.view.urlChanged.connect(self.urlChanged.emit)
        self.view.loadStarted.connect(self.loadStarted.emit)
        self.view.loadProgress.connect(self.loadProgress.emit)
        self.view.loadFinished.connect(self.loadFinished.emit)
        self.view.titleChanged.connect(self.titleChanged.emit)


class BrowserTabWidget(QTabWidget):
    """Owns all browser tab lifecycle and tab-local signal wiring."""

    currentTabChanged = pyqtSignal(object)

    def __init__(self, profile: QWebEngineProfile, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._profile = profile
        self.setDocumentMode(True)
        self.setTabsClosable(True)
        self.tabCloseRequested.connect(self.close_tab)
        self.currentChanged.connect(self._emit_current_tab_changed)

        self._new_tab_index = self.addTab(QWidget(self), "+")
        self.tabBar().setTabButton(self._new_tab_index, self.tabBar().ButtonPosition.LeftSide, None)
        self.tabBar().setTabButton(self._new_tab_index, self.tabBar().ButtonPosition.RightSide, None)

        # v1 default: instantiate one tab on startup.
        self.add_browser_tab(make_current=True)

    def _emit_current_tab_changed(self, index: int) -> None:
        if index == self._new_tab_index:
            self.add_browser_tab(make_current=True)
            return
        self.currentTabChanged.emit(self.browser_tab_at(index))

    def browser_tab_at(self, index: int) -> BrowserTab | None:
        widget = self.widget(index)
        return widget.property("browser_tab") if widget else None

    def current_browser_tab(self) -> BrowserTab | None:
        return self.browser_tab_at(self.currentIndex())

    def add_browser_tab(self, make_current: bool = False) -> BrowserTab:
        tab = BrowserTab(self._profile, self)
        title = "New Tab"
        tab_index = self.insertTab(self._new_tab_index, tab.view, title)
        tab.view.setProperty("browser_tab", tab)
        tab.titleChanged.connect(lambda text, idx=tab_index: self._set_tab_title(idx, text))

        self._new_tab_index = self.count() - 1
        if make_current:
            self.setCurrentIndex(tab_index)
            self.currentTabChanged.emit(tab)
        return tab

    def _set_tab_title(self, index: int, title: str) -> None:
        current_widget = self.widget(index)
        if current_widget is None:
            return
        current_index = self.indexOf(current_widget)
        if current_index < 0 or current_index == self._new_tab_index:
            return
        self.setTabText(current_index, title.strip() or "New Tab")

    def close_tab(self, index: int) -> None:
        if index == self._new_tab_index:
            return
        if self.count() <= 2:  # one browser tab + plus tab
            return
        widget = self.widget(index)
        self.removeTab(index)
        if widget is not None:
            widget.deleteLater()
        self._new_tab_index = self.count() - 1
