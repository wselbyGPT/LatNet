from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Protocol


@dataclass(slots=True)
class ConnectorSession:
    stream_id: int
    target_host: str
    target_port: int
    created_at: float
    last_activity_at: float
    handle: object | None = None


class OutboundConnector(Protocol):
    def connect(self, target: dict[str, object]) -> ConnectorSession: ...

    def send(self, stream_id: int, data: bytes) -> None: ...

    def recv(self, stream_id: int) -> bytes: ...

    def close(self, stream_id: int) -> None: ...


class DemoOutboundConnector:
    """No-op/demo connector for safe default behavior and tests."""

    def __init__(self) -> None:
        self._sessions: dict[int, ConnectorSession] = {}
        self._last_payload: dict[int, bytes] = {}

    def connect(self, target: dict[str, object]) -> ConnectorSession:
        stream_id = int(target["stream_id"])
        now = time.time()
        host = str(target.get("host", "demo"))
        port = int(target.get("port", 0))
        session = ConnectorSession(stream_id, host, port, now, now, handle=f"demo:{host}:{port}")
        self._sessions[stream_id] = session
        return session

    def send(self, stream_id: int, data: bytes) -> None:
        self._last_payload[stream_id] = bytes(data)
        if stream_id in self._sessions:
            self._sessions[stream_id].last_activity_at = time.time()

    def recv(self, stream_id: int) -> bytes:
        payload = self._last_payload.get(stream_id, b"")
        session = self._sessions.get(stream_id)
        if session is not None:
            session.last_activity_at = time.time()
        return f"echo[{stream_id}] ".encode("utf-8") + payload

    def close(self, stream_id: int) -> None:
        self._sessions.pop(stream_id, None)
        self._last_payload.pop(stream_id, None)


class TcpOutboundConnector:
    def __init__(self, *, connect_timeout: float, recv_timeout: float = 2.0) -> None:
        self.connect_timeout = max(float(connect_timeout), 0.1)
        self.recv_timeout = max(float(recv_timeout), 0.1)
        self._sessions: dict[int, ConnectorSession] = {}

    def connect(self, target: dict[str, object]) -> ConnectorSession:
        stream_id = int(target["stream_id"])
        host = str(target["host"])
        port = int(target["port"])
        sock = socket.create_connection((host, port), timeout=self.connect_timeout)
        sock.settimeout(self.recv_timeout)
        now = time.time()
        session = ConnectorSession(stream_id, host, port, now, now, handle=sock)
        self._sessions[stream_id] = session
        return session

    def send(self, stream_id: int, data: bytes) -> None:
        session = self._sessions[stream_id]
        sock = session.handle
        assert isinstance(sock, socket.socket)
        sock.sendall(data)
        session.last_activity_at = time.time()

    def recv(self, stream_id: int) -> bytes:
        session = self._sessions[stream_id]
        sock = session.handle
        assert isinstance(sock, socket.socket)
        data = sock.recv(4096)
        session.last_activity_at = time.time()
        return data

    def close(self, stream_id: int) -> None:
        session = self._sessions.pop(stream_id, None)
        if session is None:
            return
        sock = session.handle
        if isinstance(sock, socket.socket):
            try:
                sock.close()
            except OSError:
                pass
