from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from .crypto import decrypt_layer, derive_aead_key, derive_hop_keys, encrypt_layer, hkdf_expand, hkdf_extract
from .models.hidden_service import parse_lettuce_name
from .models.hidden_service_descriptor import verify_hidden_service_descriptor_v2
from .models.protocol import parse_get_bundle_request, parse_get_hidden_service_descriptor_request
from .util import load_json
from .wire import recv_msg, send_msg


class DirectoryServer:
    def __init__(self, bundle_path: str, hidden_service_store_path: str | None = None):
        self.bundle_path = Path(bundle_path)
        self.hidden_service_store_path = Path(hidden_service_store_path) if hidden_service_store_path else None

    def current_bundle(self) -> dict[str, Any]:
        return load_json(self.bundle_path)

    def hidden_service_store(self) -> dict[str, Any]:
        if self.hidden_service_store_path is None:
            return {"version": 1, "descriptors": []}
        return load_json(self.hidden_service_store_path)

    def current_hidden_service_descriptors(self) -> dict[str, Any]:
        store = self.hidden_service_store()
        descriptors = store.get("descriptors")
        if not isinstance(descriptors, list):
            raise ValueError("hidden service descriptor store must include descriptors list")
        out: dict[str, Any] = {}
        for descriptor in descriptors:
            parsed = verify_hidden_service_descriptor_v2(descriptor)
            out[parsed.service_name] = descriptor
        return out

    def handle_conn(self, conn: socket.socket) -> None:
        try:
            msg = recv_msg(conn)
            if msg.get("type") == "GET_BUNDLE":
                parse_get_bundle_request(msg)
                send_msg(conn, {"ok": True, "bundle": self.current_bundle()})
            elif msg.get("type") == "GET_HS_DESCRIPTOR":
                service_name = parse_get_hidden_service_descriptor_request(msg)
                parse_lettuce_name(service_name)
                descriptor = self.current_hidden_service_descriptors().get(service_name)
                if descriptor is None:
                    send_msg(conn, {"ok": False, "error": f"hidden service descriptor not found: {service_name}"})
                else:
                    send_msg(conn, {"ok": True, "service_name": service_name, "descriptor": descriptor})
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


def run_directory_server(
    bundle_path: str,
    host: str = "127.0.0.1",
    port: int = 9200,
    hidden_service_store_path: str | None = None,
) -> None:
    server = DirectoryServer(bundle_path, hidden_service_store_path=hidden_service_store_path)
    hs_msg = f" and hidden service store {hidden_service_store_path}" if hidden_service_store_path else ""
    print(f"Starting directory server on {host}:{port} serving {bundle_path}{hs_msg}")

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
