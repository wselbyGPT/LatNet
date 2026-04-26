from __future__ import annotations

import random
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Literal

import pytest


class _DeterministicKEM:
    def __init__(self, _alg: str, secret_key: bytes | None = None):
        self._secret_key = secret_key

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def encap_secret(self, public_key: bytes) -> tuple[bytes, bytes]:
        return (b"ct:" + public_key, b"ss:" + public_key)

    def decap_secret(self, ciphertext: bytes) -> bytes:
        if not ciphertext.startswith(b"ct:"):
            raise ValueError("invalid deterministic ciphertext")
        return b"ss:" + ciphertext[3:]


@dataclass(frozen=True)
class RelayFaultProfile:
    fixed_delay_s: float = 0.0
    jitter_max_s: float = 0.0
    drop_mode: Literal["none", "before_response", "partial_after_flow", "probabilistic"] = "none"
    drop_probability: float = 0.0


@dataclass
class _RunningTcpServer:
    host: str
    port: int
    thread: threading.Thread
    stop_event: threading.Event
    listener: socket.socket

    def stop(self) -> None:
        self.stop_event.set()
        try:
            self.listener.close()
        except OSError:
            pass
        self.thread.join(timeout=2)


class _ChaosRelayHandler:
    def __init__(self, relay_server: Any, profile: RelayFaultProfile, *, seed: int, wire: Any, util: Any):
        self.relay_server = relay_server
        self.profile = profile
        self.rng = random.Random(seed)
        self.wire = wire
        self.util = util
        self.applied_delays: list[float] = []
        self.drop_decisions: list[bool] = []

    def _delay(self) -> None:
        delay = max(0.0, self.profile.fixed_delay_s)
        if self.profile.jitter_max_s > 0:
            delay += self.rng.uniform(0.0, self.profile.jitter_max_s)
        self.applied_delays.append(delay)
        if delay > 0:
            time.sleep(delay)

    def _should_drop(self) -> bool:
        mode = self.profile.drop_mode
        if mode == "none":
            return False
        if mode == "before_response":
            return True
        if mode == "probabilistic":
            return self.rng.random() < self.profile.drop_probability
        return False

    def handle_conn(self, conn: socket.socket) -> None:
        self._delay()
        try:
            msg = self.wire.recv_msg(conn)
            msg_type = msg.get("type")

            if msg_type == "BUILD":
                response = self.relay_server.handle_build(msg)
            elif msg_type == "CELL":
                response = self.relay_server.handle_cell(msg)
            elif msg_type == "DESTROY":
                response = self.relay_server.handle_destroy(msg)
            else:
                response = {"ok": False, "error": f"unknown message type {msg_type}"}

            drop = self._should_drop()
            self.drop_decisions.append(drop)
            if drop:
                return

            if self.profile.drop_mode == "partial_after_flow":
                blob = self.util.canonical_bytes(response)
                header = struct.pack("!I", len(blob))
                split_at = max(1, min(len(blob), len(blob) // 2))
                conn.sendall(header)
                conn.sendall(blob[:split_at])
                return

            self.wire.send_msg(conn, response)
        except Exception as exc:
            try:
                self.wire.send_msg(conn, {"ok": False, "error": str(exc)})
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


def _start_tcp_server(handler: object, *, host: str = "127.0.0.1") -> _RunningTcpServer:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, 0))
    listener.listen(64)
    listener.settimeout(0.1)
    stop_event = threading.Event()

    def _loop() -> None:
        while not stop_event.is_set():
            try:
                conn, _addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            handler.handle_conn(conn)

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()

    return _RunningTcpServer(host=host, port=listener.getsockname()[1], thread=thread, stop_event=stop_event, listener=listener)


def _relay_doc(util, *, name: str, key_seed: bytes) -> dict[str, Any]:
    return {
        "name": name,
        "host": "127.0.0.1",
        "port": 0,
        "kemalg": "ML-KEM-768",
        "public_key": util.b64e(key_seed),
        "secret_key": util.b64e(key_seed),
    }


def test_intro_handler_fault_profile_is_seeded_and_reproducible(monkeypatch, latnet_modules):
    runtime = latnet_modules["hidden_service_runtime"]
    relay_mod = latnet_modules["relay"]
    util = latnet_modules["util"]
    wire = latnet_modules["wire"]

    monkeypatch.setattr(runtime.oqs, "KeyEncapsulation", _DeterministicKEM)
    monkeypatch.setattr(relay_mod.oqs, "KeyEncapsulation", _DeterministicKEM)

    relay_doc = _relay_doc(util, name="intro-chaos", key_seed=b"intro" * 8)
    relay_server = relay_mod.RelayServer(relay_doc)
    profile = RelayFaultProfile(fixed_delay_s=0.002, jitter_max_s=0.003)
    chaos = _ChaosRelayHandler(relay_server, profile, seed=2026, wire=wire, util=util)

    running = _start_tcp_server(chaos)
    relay_doc["port"] = running.port
    relay_server.relay_doc["port"] = running.port

    try:
        intro_circuit = runtime.build_service_circuit([relay_doc], terminal_cmd="INTRO_READY")
        runtime._send_circuit_cmd(
            intro_circuit,
            {"cmd": "INTRODUCE", "rendezvous_cookie": "cookie-seeded", "introduction": {"rendezvous_relay": relay_doc}},
        )
        pending = runtime.poll_intro_requests(intro_circuit)

        assert len(pending) == 1
        assert pending[0]["rendezvous_cookie"] == "cookie-seeded"

        expected_rng = random.Random(2026)
        expected = [0.002 + expected_rng.uniform(0.0, 0.003) for _ in chaos.applied_delays]
        assert chaos.applied_delays == pytest.approx(expected)
        assert chaos.drop_decisions == [False] * len(chaos.drop_decisions)
    finally:
        running.stop()


def test_rendezvous_handler_drop_profiles_fail_and_recover(monkeypatch, latnet_modules):
    runtime = latnet_modules["hidden_service_runtime"]
    relay_mod = latnet_modules["relay"]
    util = latnet_modules["util"]
    wire = latnet_modules["wire"]

    monkeypatch.setattr(runtime.oqs, "KeyEncapsulation", _DeterministicKEM)
    monkeypatch.setattr(relay_mod.oqs, "KeyEncapsulation", _DeterministicKEM)

    relay_doc = _relay_doc(util, name="rdv-chaos", key_seed=b"rdv" * 10 + b"xx")
    relay_server = relay_mod.RelayServer(relay_doc)

    partial_profile = RelayFaultProfile(drop_mode="partial_after_flow")
    dropping = _ChaosRelayHandler(relay_server, partial_profile, seed=17, wire=wire, util=util)

    running = _start_tcp_server(dropping)
    relay_doc["port"] = running.port
    relay_server.relay_doc["port"] = running.port

    try:
        with pytest.raises(runtime.RelayUnreachableError):
            runtime.build_service_circuit([relay_doc], terminal_cmd="RENDEZVOUS_READY")

        running.stop()

        probabilistic_profile = RelayFaultProfile(drop_mode="probabilistic", drop_probability=0.0)
        stable = _ChaosRelayHandler(relay_server, probabilistic_profile, seed=17, wire=wire, util=util)
        running2 = _start_tcp_server(stable)
        relay_doc["port"] = running2.port
        relay_server.relay_doc["port"] = running2.port

        client_circuit = runtime.build_service_circuit([relay_doc], terminal_cmd="RENDEZVOUS_READY")
        est = runtime._send_circuit_cmd(
            client_circuit,
            {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie-rdv", "side": "client"},
        )
        assert est["cmd"] == "RENDEZVOUS_STATE"
        assert est["joined"] is False

        service_circuit, joined = runtime.establish_service_rendezvous(relay_doc, "cookie-rdv")
        assert joined is True

        runtime.rendezvous_send(client_circuit, "cookie-rdv", "hello-chaos")
        got = runtime.rendezvous_recv(service_circuit, "cookie-rdv")
        assert got == "hello-chaos"

        expected_rng = random.Random(17)
        expected_decisions = [expected_rng.random() < 0.0 for _ in stable.drop_decisions]
        assert stable.drop_decisions == expected_decisions

        running2.stop()
    finally:
        if not running.stop_event.is_set():
            running.stop()
