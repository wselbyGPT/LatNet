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


class _TransientDropRelayHandler:
    def __init__(self, relay_server: Any, *, wire: Any):
        self.relay_server = relay_server
        self.wire = wire
        self.remaining_failures = 0
        self.dropped_connections = 0
        self.total_connections = 0

    def fail_next(self, count: int) -> None:
        self.remaining_failures += max(0, int(count))

    def handle_conn(self, conn: socket.socket) -> None:
        self.total_connections += 1
        try:
            msg = self.wire.recv_msg(conn)
            if self.remaining_failures > 0:
                self.remaining_failures -= 1
                self.dropped_connections += 1
                return

            msg_type = msg.get("type")
            if msg_type == "BUILD":
                response = self.relay_server.handle_build(msg)
            elif msg_type == "CELL":
                response = self.relay_server.handle_cell(msg)
            elif msg_type == "DESTROY":
                response = self.relay_server.handle_destroy(msg)
            else:
                response = {"ok": False, "error": f"unknown message type {msg_type}"}
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


def _establish_client_intro_and_rdv(runtime, intro_relay: dict[str, Any], rdv_relay: dict[str, Any], cookie: str) -> tuple[Any, Any]:
    client_intro = runtime.build_service_circuit([intro_relay], terminal_cmd="INTRO_READY")
    client_rdv = runtime.build_service_circuit([rdv_relay], terminal_cmd="RENDEZVOUS_READY")
    runtime._send_circuit_cmd(client_rdv, {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": cookie, "side": "client"})
    runtime._send_circuit_cmd(
        client_intro,
        {"cmd": "INTRODUCE", "rendezvous_cookie": cookie, "introduction": {"rendezvous_relay": rdv_relay}},
    )
    return client_intro, client_rdv


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


def test_full_flow_intro_transient_faults_eventually_join(monkeypatch, latnet_modules):
    runtime = latnet_modules["hidden_service_runtime"]
    relay_mod = latnet_modules["relay"]
    util = latnet_modules["util"]
    wire = latnet_modules["wire"]

    monkeypatch.setattr(runtime.oqs, "KeyEncapsulation", _DeterministicKEM)
    monkeypatch.setattr(relay_mod.oqs, "KeyEncapsulation", _DeterministicKEM)

    intro_relay = _relay_doc(util, name="intro-transient", key_seed=b"intro-t" * 6)
    rdv_relay = _relay_doc(util, name="rdv-stable", key_seed=b"rdv-s" * 8)
    intro_server = relay_mod.RelayServer(intro_relay)
    rdv_server = relay_mod.RelayServer(rdv_relay)

    intro_handler = _TransientDropRelayHandler(intro_server, wire=wire)
    rdv_handler = _TransientDropRelayHandler(rdv_server, wire=wire)
    running_intro = _start_tcp_server(intro_handler)
    running_rdv = _start_tcp_server(rdv_handler)
    intro_relay["port"] = running_intro.port
    rdv_relay["port"] = running_rdv.port
    intro_server.relay_doc["port"] = running_intro.port
    rdv_server.relay_doc["port"] = running_rdv.port

    try:
        cookie = "cookie-intro-transient"
        service_intro = runtime.build_service_circuit([intro_relay], terminal_cmd="INTRO_READY")
        client_intro, _client_rdv = _establish_client_intro_and_rdv(runtime, intro_relay, rdv_relay, cookie)

        intro_handler.fail_next(2)
        cfg = runtime.ReliabilityConfig(max_retries=4, retry_backoff_base_s=0.01, retry_backoff_max_s=0.05)
        pending = runtime.poll_intro_requests(service_intro, config=cfg)
        assert len(pending) == 1
        assert intro_handler.dropped_connections == 2

        service_rdv, joined = runtime.establish_service_rendezvous(rdv_relay, cookie, config=cfg)
        assert joined is True
        state = runtime._send_circuit_cmd(
            service_rdv,
            {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": cookie, "side": "service"},
        )
        assert state["cmd"] == "RENDEZVOUS_STATE"
        assert state["joined"] is True
        assert client_intro.circuit_id
    finally:
        running_intro.stop()
        running_rdv.stop()


@pytest.mark.parametrize(
    ("arm_failures", "join_timeout_s", "expected_error"),
    [
        (6, 0.05, "relay_unreachable"),
        (0, 0.01, "rendezvous_not_joined"),
    ],
)
def test_rendezvous_transient_retry_exhaustion_classification(monkeypatch, latnet_modules, arm_failures, join_timeout_s, expected_error):
    runtime = latnet_modules["hidden_service_runtime"]
    relay_mod = latnet_modules["relay"]
    util = latnet_modules["util"]
    wire = latnet_modules["wire"]
    cli = latnet_modules["cli"]

    monkeypatch.setattr(runtime.oqs, "KeyEncapsulation", _DeterministicKEM)
    monkeypatch.setattr(relay_mod.oqs, "KeyEncapsulation", _DeterministicKEM)

    rdv_relay = _relay_doc(util, name="rdv-retry-classify", key_seed=b"rdv-c" * 8)
    rdv_server = relay_mod.RelayServer(rdv_relay)
    rdv_handler = _TransientDropRelayHandler(rdv_server, wire=wire)
    running = _start_tcp_server(rdv_handler)
    rdv_relay["port"] = running.port
    rdv_server.relay_doc["port"] = running.port

    try:
        rdv_handler.fail_next(arm_failures)
        cfg = runtime.ReliabilityConfig(max_retries=3, join_timeout_s=join_timeout_s, retry_backoff_base_s=0.01, retry_backoff_max_s=0.02)
        if expected_error == "rendezvous_not_joined":
            monkeypatch.setattr(runtime, "rendezvous_recv", lambda *_args, **_kwargs: None)
        with pytest.raises(Exception) as raised:
            runtime.establish_service_rendezvous(rdv_relay, "cookie-rdv-classify", config=cfg)
        err = raised.value
        runtime_err = runtime.error_to_dict(err)
        assert runtime_err["code"] == expected_error
        assert cli._error_code(err) == expected_error
        if expected_error == "relay_unreachable":
            assert isinstance(err, runtime.RelayUnreachableError)
        else:
            assert isinstance(err, runtime.RendezvousNotJoinedError)
    finally:
        running.stop()


def test_full_flow_mixed_intro_and_rendezvous_faults_backoff_sequence(monkeypatch, latnet_modules):
    runtime = latnet_modules["hidden_service_runtime"]
    relay_mod = latnet_modules["relay"]
    util = latnet_modules["util"]
    wire = latnet_modules["wire"]

    monkeypatch.setattr(runtime.oqs, "KeyEncapsulation", _DeterministicKEM)
    monkeypatch.setattr(relay_mod.oqs, "KeyEncapsulation", _DeterministicKEM)

    intro_relay = _relay_doc(util, name="intro-mixed", key_seed=b"intro-m" * 8)
    rdv_relay = _relay_doc(util, name="rdv-mixed", key_seed=b"rdv-m" * 8)
    intro_server = relay_mod.RelayServer(intro_relay)
    rdv_server = relay_mod.RelayServer(rdv_relay)
    intro_handler = _TransientDropRelayHandler(intro_server, wire=wire)
    rdv_handler = _TransientDropRelayHandler(rdv_server, wire=wire)

    running_intro = _start_tcp_server(intro_handler)
    running_rdv = _start_tcp_server(rdv_handler)
    intro_relay["port"] = running_intro.port
    rdv_relay["port"] = running_rdv.port
    intro_server.relay_doc["port"] = running_intro.port
    rdv_server.relay_doc["port"] = running_rdv.port

    sleeps: list[float] = []
    monkeypatch.setattr(runtime.time, "sleep", lambda duration: sleeps.append(duration))

    try:
        cookie = "cookie-mixed-chaos"
        cfg = runtime.ReliabilityConfig(max_retries=4, retry_backoff_base_s=0.05, retry_backoff_max_s=0.2, join_timeout_s=0.05)
        service_intro = runtime.build_service_circuit([intro_relay], terminal_cmd="INTRO_READY")
        _client_intro, _client_rdv = _establish_client_intro_and_rdv(runtime, intro_relay, rdv_relay, cookie)

        intro_handler.fail_next(2)
        pending = runtime.poll_intro_requests(service_intro, config=cfg)
        assert len(pending) == 1

        rdv_handler.fail_next(1)
        _service_rdv, joined = runtime.establish_service_rendezvous(rdv_relay, cookie, config=cfg)
        assert joined is True

        assert intro_handler.dropped_connections + rdv_handler.dropped_connections == 3
        assert sleeps == [0.05, 0.1, 0.05]
    finally:
        running_intro.stop()
        running_rdv.stop()
