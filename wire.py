from __future__ import annotations

import json
import socket
import struct
from typing import Any

from .constants import APP_SALT, AUTH_SIGALG, DEFAULT_TIMEOUT, KEMALG
from .util import canonical_bytes, recv_exact


def send_msg(sock: socket.socket, obj: dict[str, Any]) -> None:
    blob = canonical_bytes(obj)
    sock.sendall(struct.pack("!I", len(blob)))
    sock.sendall(blob)


def recv_msg(sock: socket.socket) -> dict[str, Any]:
    length = struct.unpack("!I", recv_exact(sock, 4))[0]
    blob = recv_exact(sock, length)
    msg = json.loads(blob.decode("utf-8"))
    if not isinstance(msg, dict):
        raise ValueError("wire message must be an object")
    return msg


__all__ = [
    "send_msg",
    "recv_msg",
    # deprecated constants import-surface compatibility
    "KEMALG",
    "AUTH_SIGALG",
    "APP_SALT",
    "DEFAULT_TIMEOUT",
]
