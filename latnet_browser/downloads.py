"""Download lifecycle management and UI for the LatNet browser."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from PyQt6.QtCore import QObject, Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWebEngineCore import QWebEngineDownloadRequest, QWebEngineProfile
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class DownloadRecord(TypedDict):
    """Persisted metadata describing a finished/cancelled download."""

    filename: str
    path: str
    state: str


@dataclass
class DownloadEntry:
    """In-memory bookkeeping for an active profile download request."""

    request: QWebEngineDownloadRequest


class DownloadManager(QObject):
    """Tracks browser downloads and provides a lightweight list UI."""

    downloadAdded = pyqtSignal()
    downloadUpdated = pyqtSignal()

    def __init__(self, profile: QWebEngineProfile, recent_downloads: list[DownloadRecord], parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._profile = profile
        self._entries: list[DownloadEntry] = []
        self._recent_downloads = list(recent_downloads)
        self._dialog: DownloadsDialog | None = None

    @property
    def recent_downloads(self) -> list[DownloadRecord]:
        """Return a copy of persisted recent download records."""
        return list(self._recent_downloads)

    def bind_profile_signals(self) -> None:
        """Subscribe to profile-level download lifecycle events."""
        self._profile.downloadRequested.connect(self._on_download_requested)

    def show_dialog(self, parent: QWidget) -> None:
        """Open the downloads dialog and keep it modeless for live updates."""
        if self._dialog is None:
            self._dialog = DownloadsDialog(self, parent)
        self._dialog.show()
        self._dialog.raise_()
        self._dialog.activateWindow()

    def _on_download_requested(self, request: QWebEngineDownloadRequest) -> None:
        request.setParent(self)
        request.stateChanged.connect(lambda _state, req=request: self._on_state_changed(req))
        request.receivedBytesChanged.connect(self.downloadUpdated.emit)
        request.totalBytesChanged.connect(self.downloadUpdated.emit)
        self._entries.append(DownloadEntry(request=request))
        self.downloadAdded.emit()
        self.downloadUpdated.emit()

    def active_entries(self) -> list[DownloadEntry]:
        return list(self._entries)

    def start_download(self, request: QWebEngineDownloadRequest) -> None:
        if request.state() == QWebEngineDownloadRequest.DownloadState.DownloadRequested:
            request.accept()
            self.downloadUpdated.emit()

    def cancel_download(self, request: QWebEngineDownloadRequest) -> None:
        if request.state() in {
            QWebEngineDownloadRequest.DownloadState.DownloadInProgress,
            QWebEngineDownloadRequest.DownloadState.DownloadRequested,
        }:
            request.cancel()
            self.downloadUpdated.emit()

    def open_containing_folder(self, request: QWebEngineDownloadRequest) -> bool:
        file_path = Path(request.downloadDirectory()) / request.downloadFileName()
        folder = file_path.parent
        return QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def _on_state_changed(self, request: QWebEngineDownloadRequest) -> None:
        if request.state() in {
            QWebEngineDownloadRequest.DownloadState.DownloadCompleted,
            QWebEngineDownloadRequest.DownloadState.DownloadCancelled,
            QWebEngineDownloadRequest.DownloadState.DownloadInterrupted,
        }:
            self._store_recent_download(request)
        self.downloadUpdated.emit()

    def _store_recent_download(self, request: QWebEngineDownloadRequest) -> None:
        path = str(Path(request.downloadDirectory()) / request.downloadFileName())
        record: DownloadRecord = {
            "filename": request.downloadFileName(),
            "path": path,
            "state": _state_label(request.state()),
        }
        self._recent_downloads = [entry for entry in self._recent_downloads if entry["path"] != path]
        self._recent_downloads.insert(0, record)
        self._recent_downloads = self._recent_downloads[:50]


class DownloadsDialog(QDialog):
    """Simple table UI that lists and controls download requests."""

    def __init__(self, manager: DownloadManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._manager = manager
        self.setWindowTitle("Downloads")
        self.resize(760, 320)

        self._table = QTableWidget(0, 5, self)
        self._table.setHorizontalHeaderLabels(["File", "State", "Progress", "Destination", "Actions"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        layout = QVBoxLayout(self)
        layout.addWidget(self._table)

        self._manager.downloadAdded.connect(self._reload)
        self._manager.downloadUpdated.connect(self._reload)
        self._reload()

    def _reload(self) -> None:
        entries = self._manager.active_entries()
        recent = self._manager.recent_downloads
        total_rows = len(entries) + len(recent)
        self._table.setRowCount(total_rows)

        for row, entry in enumerate(entries):
            request = entry.request
            destination = str(Path(request.downloadDirectory()) / request.downloadFileName())
            self._table.setItem(row, 0, QTableWidgetItem(request.downloadFileName() or "(unnamed)"))
            self._table.setItem(row, 1, QTableWidgetItem(_state_label(request.state())))
            self._table.setItem(row, 2, QTableWidgetItem(_progress_label(request.receivedBytes(), request.totalBytes())))
            self._table.setItem(row, 3, QTableWidgetItem(destination))
            self._table.setCellWidget(row, 4, self._action_widget_for_request(request))

        for offset, item in enumerate(recent):
            row = len(entries) + offset
            self._table.setItem(row, 0, QTableWidgetItem(item["filename"]))
            self._table.setItem(row, 1, QTableWidgetItem(item["state"]))
            self._table.setItem(row, 2, QTableWidgetItem("n/a"))
            self._table.setItem(row, 3, QTableWidgetItem(item["path"]))
            open_button = QPushButton("Open Folder", self)
            open_button.clicked.connect(lambda _checked=False, p=item["path"]: self._open_folder_from_path(p))
            holder = QWidget(self)
            actions_layout = QHBoxLayout(holder)
            actions_layout.setContentsMargins(0, 0, 0, 0)
            actions_layout.addWidget(QLabel("Recent", self))
            actions_layout.addWidget(open_button)
            self._table.setCellWidget(row, 4, holder)

    def _action_widget_for_request(self, request: QWebEngineDownloadRequest) -> QWidget:
        container = QWidget(self)
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        start_button = QPushButton("Start", self)
        start_button.clicked.connect(lambda _checked=False, req=request: self._manager.start_download(req))
        cancel_button = QPushButton("Cancel", self)
        cancel_button.clicked.connect(lambda _checked=False, req=request: self._manager.cancel_download(req))
        folder_button = QPushButton("Open Folder", self)
        folder_button.clicked.connect(lambda _checked=False, req=request: self._open_folder(req))

        state = request.state()
        start_button.setEnabled(state == QWebEngineDownloadRequest.DownloadState.DownloadRequested)
        cancel_button.setEnabled(state in {
            QWebEngineDownloadRequest.DownloadState.DownloadRequested,
            QWebEngineDownloadRequest.DownloadState.DownloadInProgress,
        })
        folder_button.setEnabled(bool(request.downloadDirectory()))

        layout.addWidget(start_button)
        layout.addWidget(cancel_button)
        layout.addWidget(folder_button)
        return container

    def _open_folder(self, request: QWebEngineDownloadRequest) -> None:
        if not self._manager.open_containing_folder(request):
            QMessageBox.warning(self, "Open folder", "Unable to open containing folder on this platform.")

    def _open_folder_from_path(self, path: str) -> None:
        opened = QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path).parent)))
        if not opened:
            QMessageBox.warning(self, "Open folder", "Unable to open containing folder on this platform.")


def _state_label(state: QWebEngineDownloadRequest.DownloadState) -> str:
    mapping = {
        QWebEngineDownloadRequest.DownloadState.DownloadRequested: "Requested",
        QWebEngineDownloadRequest.DownloadState.DownloadInProgress: "In Progress",
        QWebEngineDownloadRequest.DownloadState.DownloadCompleted: "Completed",
        QWebEngineDownloadRequest.DownloadState.DownloadCancelled: "Cancelled",
        QWebEngineDownloadRequest.DownloadState.DownloadInterrupted: "Interrupted",
    }
    return mapping.get(state, "Unknown")


def _progress_label(received: int, total: int) -> str:
    if total <= 0:
        return f"{received} bytes"
    percent = int((received / total) * 100)
    return f"{percent}% ({received}/{total})"
