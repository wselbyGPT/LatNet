from __future__ import annotations

import fnmatch
import ipaddress
import socket
import time
from collections import deque
from dataclasses import dataclass, field
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


@dataclass(slots=True)
class ExitPolicy:
    allow_ports: list[int] = field(default_factory=list)
    deny_ports: list[int] = field(default_factory=list)
    allow_domains: list[str] = field(default_factory=lambda: ["*"])
    deny_domains: list[str] = field(default_factory=list)
    dns_server: str | None = None
    deny_private_addresses: bool = True
    max_concurrent_streams: int = 128
    max_new_connections_per_window: int = 256
    rate_window_seconds: float = 60.0
    max_attempts_per_destination: int | None = None


class EgressPolicyError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ControlledResolver:
    def __init__(self, dns_server: str | None = None) -> None:
        self.dns_server = dns_server

    def resolve(self, host: str, port: int) -> list[tuple]:
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


class PolicyEnforcedTcpConnector:
    def __init__(self, *, connect_timeout: float, recv_timeout: float = 2.0, policy: ExitPolicy | None = None) -> None:
        self.connect_timeout = max(float(connect_timeout), 0.1)
        self.recv_timeout = max(float(recv_timeout), 0.1)
        self.policy = policy or ExitPolicy()
        self._sessions: dict[int, ConnectorSession] = {}
        self._resolver = ControlledResolver(dns_server=self.policy.dns_server)
        self._new_conn_times: deque[float] = deque()
        self._attempts_per_destination: dict[str, int] = {}

    def _matches_any(self, value: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(value.lower(), p.lower()) for p in patterns)

    def _check_policy(self, host: str, port: int) -> None:
        if self.policy.allow_ports and port not in self.policy.allow_ports:
            raise EgressPolicyError("egress_denied_port", f"port {port} not allowed")
        if port in self.policy.deny_ports:
            raise EgressPolicyError("egress_denied_port", f"port {port} denied")
        if self.policy.allow_domains and not self._matches_any(host, self.policy.allow_domains):
            raise EgressPolicyError("egress_denied_domain", f"domain {host} not allowed")
        if self.policy.deny_domains and self._matches_any(host, self.policy.deny_domains):
            raise EgressPolicyError("egress_denied_domain", f"domain {host} denied")

    def _check_rate_limits(self, destination: str) -> None:
        if len(self._sessions) >= self.policy.max_concurrent_streams:
            raise EgressPolicyError("egress_rate_limited", "max concurrent outbound streams reached")
        now = time.time()
        cutoff = now - max(self.policy.rate_window_seconds, 0.1)
        while self._new_conn_times and self._new_conn_times[0] < cutoff:
            self._new_conn_times.popleft()
        if len(self._new_conn_times) >= self.policy.max_new_connections_per_window:
            raise EgressPolicyError("egress_rate_limited", "new connection rate limit reached")
        if self.policy.max_attempts_per_destination is not None:
            attempts = self._attempts_per_destination.get(destination, 0)
            if attempts >= self.policy.max_attempts_per_destination:
                raise EgressPolicyError("egress_rate_limited", f"destination attempt limit reached for {destination}")

    def _resolve_and_validate(self, host: str, port: int) -> list[tuple]:
        try:
            infos = self._resolver.resolve(host, port)
        except OSError as exc:
            raise EgressPolicyError("dns_resolution_failed", f"failed to resolve {host}: {exc}") from exc
        if not infos:
            raise EgressPolicyError("dns_resolution_failed", f"no records for {host}")
        if self.policy.deny_private_addresses:
            for info in infos:
                ip = ipaddress.ip_address(info[4][0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                    raise EgressPolicyError("dns_resolution_failed", f"resolved address {ip} for {host} is private/reserved")
        return infos

    def connect(self, target: dict[str, object]) -> ConnectorSession:
        stream_id = int(target["stream_id"]); host = str(target["host"]); port = int(target["port"])
        destination = f"{host}:{port}"
        self._check_policy(host, port)
        self._check_rate_limits(destination)
        infos = self._resolve_and_validate(host, port)
        last_exc: Exception | None = None
        sock=None
        for family, socktype, proto, _canon, sockaddr in infos:
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(self.connect_timeout)
                sock.connect(sockaddr)
                break
            except OSError as exc:
                last_exc = exc
                if sock is not None:
                    sock.close()
                sock = None
        if sock is None:
            raise EgressPolicyError("dns_resolution_failed", f"connect failed for all resolved addresses: {last_exc}")
        sock.settimeout(self.recv_timeout)
        now=time.time(); session=ConnectorSession(stream_id, host, port, now, now, handle=sock)
        self._sessions[stream_id]=session
        self._new_conn_times.append(now)
        self._attempts_per_destination[destination]=self._attempts_per_destination.get(destination,0)+1
        return session

    send = TcpOutboundConnector.send
    recv = TcpOutboundConnector.recv
    close = TcpOutboundConnector.close
