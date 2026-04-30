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


class DownloadRecord(TypedDict):
    """Serializable recent download structure."""

    filename: str
    path: str
    state: str


class BrowserSettings:
    """Wrapper around ``QSettings`` keys used by the browser UI."""

    _KEY_HOMEPAGE_URL = "homepage_url"
    _KEY_SEARCH_TEMPLATE = "search_template"
    _KEY_BOOKMARKS = "bookmarks"
    _KEY_RECENT_DOWNLOADS = "recent_downloads"
    _KEY_SITE_PERMISSIONS = "site_permissions"

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

        if not self._settings.contains(self._KEY_RECENT_DOWNLOADS):
            self.set_recent_downloads([])

        if not self._settings.contains(self._KEY_SITE_PERMISSIONS):
            self.set_site_permissions({})

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


    def get_recent_downloads(self) -> list[DownloadRecord]:
        """Return persisted recent downloads list."""
        raw_value = self._settings.value(self._KEY_RECENT_DOWNLOADS, [])
        if not isinstance(raw_value, list):
            return []

        records: list[DownloadRecord] = []
        for entry in raw_value:
            if not isinstance(entry, dict):
                continue
            filename = str(entry.get("filename", "")).strip()
            path = str(entry.get("path", "")).strip()
            state = str(entry.get("state", "")).strip()
            if not filename or not path or not state:
                continue
            records.append({"filename": filename, "path": path, "state": state})
        return records

    def set_recent_downloads(self, downloads: list[DownloadRecord]) -> None:
        """Store recent download records in settings."""
        serializable: list[DownloadRecord] = []
        for entry in downloads:
            filename = str(entry.get("filename", "")).strip()
            path = str(entry.get("path", "")).strip()
            state = str(entry.get("state", "")).strip()
            if not filename or not path or not state:
                continue
            serializable.append({"filename": filename, "path": path, "state": state})
        self._settings.setValue(self._KEY_RECENT_DOWNLOADS, serializable)

    def get_site_permissions(self) -> dict[str, dict[str, str]]:
        """Return persisted per-origin permission decisions."""
        raw_value = self._settings.value(self._KEY_SITE_PERMISSIONS, {})
        if not isinstance(raw_value, dict):
            return {}

        parsed: dict[str, dict[str, str]] = {}
        for origin, permissions in raw_value.items():
            origin_key = str(origin).strip()
            if not origin_key or not isinstance(permissions, dict):
                continue
            parsed_permissions: dict[str, str] = {}
            for permission_type, decision in permissions.items():
                permission_key = str(permission_type).strip()
                decision_value = str(decision).strip().lower()
                if not permission_key or decision_value not in {"allow", "deny"}:
                    continue
                parsed_permissions[permission_key] = decision_value
            if parsed_permissions:
                parsed[origin_key] = parsed_permissions
        return parsed

    def set_site_permissions(self, permissions: dict[str, dict[str, str]]) -> None:
        """Persist per-origin permission decisions."""
        serializable: dict[str, dict[str, str]] = {}
        for origin, permission_map in permissions.items():
            origin_key = str(origin).strip()
            if not origin_key or not isinstance(permission_map, dict):
                continue
            normalized_map: dict[str, str] = {}
            for permission_type, decision in permission_map.items():
                permission_key = str(permission_type).strip()
                decision_value = str(decision).strip().lower()
                if not permission_key or decision_value not in {"allow", "deny"}:
                    continue
                normalized_map[permission_key] = decision_value
            if normalized_map:
                serializable[origin_key] = normalized_map
        self._settings.setValue(self._KEY_SITE_PERMISSIONS, serializable)

    def get_permission_decision(self, origin: str, permission_type: str) -> str | None:
        """Return saved decision for an origin + permission type pair."""
        permissions = self.get_site_permissions()
        return permissions.get(origin, {}).get(permission_type)

    def set_permission_decision(self, origin: str, permission_type: str, decision: str) -> None:
        """Store a single decision for an origin + permission type pair."""
        origin_key = origin.strip()
        permission_key = permission_type.strip()
        decision_value = decision.strip().lower()
        if not origin_key or not permission_key or decision_value not in {"allow", "deny"}:
            return

        permissions = self.get_site_permissions()
        permissions.setdefault(origin_key, {})[permission_key] = decision_value
        self.set_site_permissions(permissions)
