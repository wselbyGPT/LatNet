"""Persistent browser settings backed by ``QSettings``."""

from typing import TypedDict

from PyQt6.QtCore import QSettings

_DEFAULT_HOMEPAGE_URL = "https://example.com"
_DEFAULT_SEARCH_TEMPLATE = "https://duckduckgo.com/?q={query}"


class Bookmark(TypedDict):
    """Serializable bookmark structure."""

    title: str
    url: str


_DEFAULT_BOOKMARKS: list[Bookmark] = [
    {"title": "Example", "url": "https://example.com"},
    {"title": "DuckDuckGo", "url": "https://duckduckgo.com"},
]


class BrowserSettings:
    """Wrapper around ``QSettings`` keys used by the browser UI."""

    _KEY_HOMEPAGE_URL = "homepage_url"
    _KEY_SEARCH_TEMPLATE = "search_template"
    _KEY_BOOKMARKS = "bookmarks"

    def __init__(self) -> None:
        self._settings = QSettings("LatNet", "LatNet Browser")
        self._ensure_defaults()

    def _ensure_defaults(self) -> None:
        """Persist default values the first time the app runs."""
        if not self._settings.contains(self._KEY_HOMEPAGE_URL):
            self.set_homepage_url(_DEFAULT_HOMEPAGE_URL)

        if not self._settings.contains(self._KEY_SEARCH_TEMPLATE):
            self.set_search_template(_DEFAULT_SEARCH_TEMPLATE)

        if not self._settings.contains(self._KEY_BOOKMARKS):
            self.set_bookmarks(_DEFAULT_BOOKMARKS)

    def get_homepage_url(self) -> str:
        """Return the saved homepage URL."""
        return str(self._settings.value(self._KEY_HOMEPAGE_URL, _DEFAULT_HOMEPAGE_URL))

    def set_homepage_url(self, url: str) -> None:
        """Store a new homepage URL."""
        self._settings.setValue(self._KEY_HOMEPAGE_URL, url)

    def get_search_template(self) -> str:
        """Return the saved search engine URL template."""
        return str(self._settings.value(self._KEY_SEARCH_TEMPLATE, _DEFAULT_SEARCH_TEMPLATE))

    def set_search_template(self, template: str) -> None:
        """Store a new search engine URL template."""
        self._settings.setValue(self._KEY_SEARCH_TEMPLATE, template)

    def get_bookmarks(self) -> list[Bookmark]:
        """Return the saved bookmarks."""
        raw_value = self._settings.value(self._KEY_BOOKMARKS, _DEFAULT_BOOKMARKS)
        if not isinstance(raw_value, list):
            return list(_DEFAULT_BOOKMARKS)

        bookmarks: list[Bookmark] = []
        for entry in raw_value:
            if not isinstance(entry, dict):
                continue
            title = str(entry.get("title", "")).strip()
            url = str(entry.get("url", "")).strip()
            if not title or not url:
                continue
            bookmarks.append({"title": title, "url": url})
        return bookmarks

    def set_bookmarks(self, bookmarks: list[Bookmark]) -> None:
        """Store bookmarks as a list of title/URL dictionaries."""
        serializable: list[Bookmark] = []
        for entry in bookmarks:
            title = str(entry.get("title", "")).strip()
            url = str(entry.get("url", "")).strip()
            if not title or not url:
                continue
            serializable.append({"title": title, "url": url})
        self._settings.setValue(self._KEY_BOOKMARKS, serializable)
