from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from .crypto import decrypt_layer, derive_aead_key, derive_hop_keys, encrypt_layer, hkdf_expand, hkdf_extract
from .models.protocol import parse_get_bundle_request
from .util import load_json
from .wire import recv_msg, send_msg


class DirectoryServer:
    def __init__(self, bundle_path: str):
        self.bundle_path = Path(bundle_path)

    def current_bundle(self) -> dict[str, Any]:
        return load_json(self.bundle_path)

    def handle_conn(self, conn: socket.socket) -> None:
        try:
            msg = recv_msg(conn)
            if msg.get("type") == "GET_BUNDLE":
                parse_get_bundle_request(msg)
                send_msg(conn, {"ok": True, "bundle": self.current_bundle()})
            else:
                send_msg(conn, {"ok": False, "error": f"unknown message type {msg.get('type')}"})
        except Exception as exc:
            try:
                send_msg(conn, {"ok": False, "error": str(exc)})
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


def run_directory_server(bundle_path: str, host: str = "127.0.0.1", port: int = 9200) -> None:
    server = DirectoryServer(bundle_path)
    print(f"Starting directory server on {host}:{port} serving {bundle_path}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(64)
        while True:
            conn, _addr = srv.accept()
            server.handle_conn(conn)


__all__ = [
    "DirectoryServer",
    "run_directory_server",
    # deprecated crypto import compatibility
    "hkdf_extract",
    "hkdf_expand",
    "derive_aead_key",
    "derive_hop_keys",
    "encrypt_layer",
    "decrypt_layer",
]
