from __future__ import annotations

from typing import Any

from .constants import DEFAULT_TIMEOUT
from .directory import DirectoryServer, run_directory_server
from .util import atomic_write_json
from .wire import recv_msg, send_msg


def fetch_bundle_from_directory(host: str, port: int = 9200) -> dict[str, Any]:
    import socket

    with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
        send_msg(sock, {"type": "GET_BUNDLE"})
        response = recv_msg(sock)

    if not isinstance(response, dict):
        raise ValueError("directory response must be an object")
    if not response.get("ok"):
        raise ValueError(response.get("error", "directory returned error"))
    bundle = response.get("bundle")
    if not isinstance(bundle, dict):
        raise ValueError("directory response missing bundle")
    return bundle


def fetch_bundle_to_file(host: str, port: int, out_path: str) -> dict[str, Any]:
    bundle = fetch_bundle_from_directory(host, port)
    atomic_write_json(out_path, bundle)
    return bundle


__all__ = [
    "fetch_bundle_from_directory",
    "fetch_bundle_to_file",
    # deprecated directory-server import compatibility
    "DirectoryServer",
    "run_directory_server",
]
