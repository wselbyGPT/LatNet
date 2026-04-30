"""URL helper utilities for browser user input normalization."""

from PyQt6.QtCore import QUrl

_ALLOWED_SCHEMES = {"http", "https"}


def normalize_user_url(text: str) -> QUrl | None:
    """Normalize user-entered URL text into a safe QUrl.

    Returns ``None`` when the input is invalid or uses a disallowed scheme.
    """
    candidate = text.strip()
    if not candidate:
        return None

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    url = QUrl(candidate)
    if not url.isValid() or url.scheme().lower() not in _ALLOWED_SCHEMES:
        return None

    if not url.host():
        return None

    return url
