from __future__ import annotations

import socket
import time
from pathlib import Path
from typing import Any

from .models.hidden_service import parse_lettuce_name
from .models.hidden_service_descriptor import verify_hidden_service_descriptor_v2
from .models.network_status import parse_network_status_document
from .models.protocol import (
    parse_get_bundle_request,
    parse_get_hidden_service_descriptor_request,
    parse_get_network_status_request,
    parse_publish_hidden_service_descriptor_request,
)
from .util import atomic_write_json, load_json
from . import wire


class DirectoryServer:
    def __init__(
        self,
        bundle_path: str,
        hidden_service_store_path: str | None = None,
        network_status_path: str | None = None,
    ):
        self.bundle_path = Path(bundle_path)
        self.hidden_service_store_path = Path(hidden_service_store_path) if hidden_service_store_path else None
        self.network_status_path = Path(network_status_path) if network_status_path else None

    def current_bundle(self) -> dict[str, Any]:
        return load_json(self.bundle_path)

    def current_network_status(self) -> dict[str, Any]:
        if self.network_status_path is None:
            raise FileNotFoundError("network-status snapshot path not configured")
        network_status = load_json(self.network_status_path)
        parse_network_status_document(network_status)
        return network_status

    def hidden_service_store(self) -> dict[str, Any]:
        if self.hidden_service_store_path is None:
            return {"version": 2, "descriptors": {}}
        return load_json(self.hidden_service_store_path)

    def current_hidden_service_descriptors(self) -> dict[str, Any]:
        store = self.hidden_service_store()
        descriptors = store.get("descriptors")
        if isinstance(descriptors, dict):
            out: dict[str, Any] = {}
            for service_name, descriptor in descriptors.items():
                parse_lettuce_name(str(service_name))
                parsed = verify_hidden_service_descriptor_v2(descriptor)
                if parsed.service_name != service_name:
                    raise ValueError("descriptor service_name does not match hidden service store key")
                out[parsed.service_name] = descriptor
            return out
        if isinstance(descriptors, list):
            out = {}
            for descriptor in descriptors:
                parsed = verify_hidden_service_descriptor_v2(descriptor)
                out[parsed.service_name] = descriptor
            return out
        raise ValueError("hidden service descriptor store must include descriptors dict or list")

    def _write_hidden_service_descriptors(self, descriptors_by_name: dict[str, Any]) -> None:
        if self.hidden_service_store_path is None:
            raise ValueError("hidden service descriptor publishing disabled")
        atomic_write_json(
            self.hidden_service_store_path,
            {
                "version": 2,
                "descriptors": dict(sorted(descriptors_by_name.items())),
            },
        )

    def handle_conn(self, conn: socket.socket) -> None:
        try:
            msg = wire.recv_msg(conn)
            if msg.get("type") == "GET_BUNDLE":
                parse_get_bundle_request(msg)
                wire.send_msg(conn, {"ok": True, "bundle": self.current_bundle()})
            elif msg.get("type") == "GET_NETWORK_STATUS":
                parse_get_network_status_request(msg)
                now = int(time.time())
                try:
                    network_status = self.current_network_status()
                except FileNotFoundError as exc:
                    wire.send_msg(
                        conn,
                        {
                            "ok": False,
                            "error_class": "network_status_unavailable",
                            "error": str(exc),
                            "server_time": now,
                        },
                    )
                    return
                except Exception as exc:
                    wire.send_msg(
                        conn,
                        {
                            "ok": False,
                            "error_class": "invalid_network_status",
                            "error": str(exc),
                            "server_time": now,
                        },
                    )
                    return

                validity = network_status.get("validity", {})
                valid_after = validity.get("valid_after")
                valid_until = validity.get("valid_until")
                if not isinstance(valid_after, int) or not isinstance(valid_until, int):
                    wire.send_msg(
                        conn,
                        {
                            "ok": False,
                            "error_class": "invalid_network_status",
                            "error": "network status validity interval is malformed",
                            "status_version": network_status.get("version"),
                            "server_time": now,
                        },
                    )
                    return
                if now < valid_after:
                    wire.send_msg(
                        conn,
                        {
                            "ok": False,
                            "error_class": "premature_network_status",
                            "error": "network status snapshot is not yet valid",
                            "status_version": network_status.get("version"),
                            "server_time": now,
                        },
                    )
                    return
                if now >= valid_until:
                    wire.send_msg(
                        conn,
                        {
                            "ok": False,
                            "error_class": "expired_network_status",
                            "error": "network status snapshot is expired",
                            "status_version": network_status.get("version"),
                            "server_time": now,
                        },
                    )
                    return
                wire.send_msg(
                    conn,
                    {
                        "ok": True,
                        "network_status": network_status,
                        "status_version": network_status.get("version"),
                        "server_time": now,
                    },
                )
            elif msg.get("type") == "GET_HS_DESCRIPTOR":
                service_name = parse_get_hidden_service_descriptor_request(msg)
                parse_lettuce_name(service_name)
                descriptor = self.current_hidden_service_descriptors().get(service_name)
                if descriptor is None:
                    wire.send_msg(conn, {"ok": False, "error": f"hidden service descriptor not found: {service_name}"})
                else:
                    wire.send_msg(conn, {"ok": True, "service_name": service_name, "descriptor": descriptor})
            elif msg.get("type") == "PUBLISH_HS_DESCRIPTOR":
                request = parse_publish_hidden_service_descriptor_request(msg)
                now = int(time.time())
                parse_lettuce_name(request.service_name)
                service_name = request.service_name
                if self.hidden_service_store_path is None:
                    wire.send_msg(
                        conn,
                        {
                            "ok": False,
                            "error_class": "unauthorized",
                            "error": "hidden service descriptor publishing disabled",
                            "service_name": service_name,
                            "idempotency_key": request.idempotency_key,
                        },
                    )
                    return
                try:
                    parsed = verify_hidden_service_descriptor_v2(request.descriptor, now=now)
                except Exception as exc:
                    wire.send_msg(
                        conn,
                        {
                            "ok": False,
                            "error_class": "invalid_signature",
                            "error": str(exc),
                            "service_name": service_name,
                            "idempotency_key": request.idempotency_key,
                        },
                    )
                    return
                if parsed.service_name != service_name:
                    wire.send_msg(
                        conn,
                        {
                            "ok": False,
                            "error_class": "invalid_signature",
                            "error": "descriptor service_name does not match request service_name",
                            "service_name": service_name,
                            "idempotency_key": request.idempotency_key,
                        },
                    )
                    return
                if parsed.valid_until <= now:
                    wire.send_msg(
                        conn,
                        {
                            "ok": False,
                            "error_class": "expired_descriptor",
                            "error": "hidden service descriptor is expired",
                            "service_name": service_name,
                            "idempotency_key": request.idempotency_key,
                        },
                    )
                    return
                descriptors_by_name = self.current_hidden_service_descriptors()
                existing = descriptors_by_name.get(service_name)
                current_revision = None
                if isinstance(existing, dict):
                    current_revision = verify_hidden_service_descriptor_v2(existing, now=now).revision

                if request.expected_previous_revision is not None and request.expected_previous_revision != current_revision:
                    wire.send_msg(
                        conn,
                        {
                            "ok": False,
                            "error_class": "revision_conflict",
                            "error": "expected_previous_revision does not match current revision",
                            "service_name": service_name,
                            "expected_previous_revision": request.expected_previous_revision,
                            "current_revision": current_revision,
                            "idempotency_key": request.idempotency_key,
                        },
                    )
                    return

                if current_revision is not None and parsed.revision <= current_revision:
                    wire.send_msg(
                        conn,
                        {
                            "ok": False,
                            "error_class": "revision_conflict",
                            "error": "descriptor revision must be strictly increasing",
                            "service_name": service_name,
                            "current_revision": current_revision,
                            "candidate_revision": parsed.revision,
                            "idempotency_key": request.idempotency_key,
                        },
                    )
                    return

                descriptors_by_name[service_name] = request.descriptor
                self._write_hidden_service_descriptors(descriptors_by_name)
                wire.send_msg(
                    conn,
                    {
                        "ok": True,
                        "service_name": service_name,
                        "accepted_revision": parsed.revision,
                        "expected_previous_revision": request.expected_previous_revision,
                        "idempotency_key": request.idempotency_key,
                    },
                )
            else:
                wire.send_msg(conn, {"ok": False, "error": f"unknown message type {msg.get('type')}"})
        except Exception as exc:
            try:
                wire.send_msg(conn, {"ok": False, "error": str(exc)})
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
    network_status_path: str | None = None,
) -> None:
    server = DirectoryServer(
        bundle_path,
        hidden_service_store_path=hidden_service_store_path,
        network_status_path=network_status_path,
    )
    hs_msg = f" and hidden service store {hidden_service_store_path}" if hidden_service_store_path else ""
    ns_msg = f" and network status {network_status_path}" if network_status_path else ""
    print(f"Starting directory server on {host}:{port} serving {bundle_path}{hs_msg}{ns_msg}")

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
]
