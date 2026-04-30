"""Persistent browser settings backed by ``QSettings``."""

from PyQt6.QtCore import QSettings

_DEFAULT_HOMEPAGE_URL = "https://example.com"
_DEFAULT_SEARCH_TEMPLATE = "https://duckduckgo.com/?q={query}"


class BrowserSettings:
    """Wrapper around ``QSettings`` keys used by the browser UI."""

    _KEY_HOMEPAGE_URL = "homepage_url"
    _KEY_SEARCH_TEMPLATE = "search_template"

    def __init__(self) -> None:
        self._settings = QSettings("LatNet", "LatNet Browser")
        self._ensure_defaults()

    def _ensure_defaults(self) -> None:
        """Persist default values the first time the app runs."""
        if not self._settings.contains(self._KEY_HOMEPAGE_URL):
            self.set_homepage_url(_DEFAULT_HOMEPAGE_URL)

        if not self._settings.contains(self._KEY_SEARCH_TEMPLATE):
            self.set_search_template(_DEFAULT_SEARCH_TEMPLATE)

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
