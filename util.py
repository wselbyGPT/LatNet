from __future__ import annotations

import base64
import hashlib
import json
import socket
from pathlib import Path
from typing import Any


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < n:
        chunk = sock.recv(n - total)
        if not chunk:
            raise ConnectionError("socket closed")
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def atomic_write_json(path: str | Path, obj: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    temp.replace(target)


def load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
