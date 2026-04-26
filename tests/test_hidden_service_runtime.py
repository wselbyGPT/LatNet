from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass

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


@dataclass
class _RunningTcpServer:
    host: str
    port: int
    server: object
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


def _start_tcp_server(server: object, *, host: str = "127.0.0.1") -> _RunningTcpServer:
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
            server.handle_conn(conn)

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()

    return _RunningTcpServer(
        host=host,
        port=listener.getsockname()[1],
        server=server,
        thread=thread,
        stop_event=stop_event,
        listener=listener,
    )


def _make_descriptor_doc(latnet_modules, tmp_path, relay_name: str, relay_port: int) -> tuple[dict, dict]:
    hs_keys = latnet_modules["hidden_service_keys"]
    util = latnet_modules["util"]

    service = hs_keys.generate_service_master("svc", tmp_path / "service_master.json")
    desc_key = hs_keys.generate_descriptor_signing_key()
    now = int(time.time())
    cert = hs_keys.build_descriptor_signing_certificate(
        service,
        desc_key["descriptor_signing_public_key"],
        valid_for=120,
        now=now,
    )

    signed = {
        "service_name": service["service_name"],
        "service_master_public_key": service["service_master_public_key"],
        "descriptor_signing_public_key": desc_key["descriptor_signing_public_key"],
        "descriptor_signing_certificate": cert,
        "valid_after": now,
        "valid_until": now + 60,
        "revision": 1,
        "period": 1,
        "introduction_points": [
            {
                "relay_name": relay_name,
                "relay_addr": {"host": "127.0.0.1", "port": relay_port},
                "intro_auth_pub": util.b64e(b"intro-auth-pub"),
                "intro_key_id": "intro-key-1",
                "expires_at": now + 60,
            }
        ],
    }

    signer = hs_keys.Ed25519PrivateKey.from_private_bytes(util.b64d(desc_key["descriptor_signing_private_key"]))
    descriptor = {
        "version": 2,
        "sigalg": hs_keys.HS_SIGALG,
        "signed": signed,
        "signature": util.b64e(signer.sign(util.canonical_bytes(signed))),
    }

    descriptor_path = tmp_path / "descriptor.json"
    descriptor_path.write_text(json.dumps(descriptor), encoding="utf-8")
    return service, descriptor


def test_load_service_material_validates_match(latnet_modules, tmp_path):
    runtime = latnet_modules["hidden_service_runtime"]

    service, descriptor = _make_descriptor_doc(latnet_modules, tmp_path, "relay-intro", 9001)
    loaded = runtime.load_service_material(str(tmp_path / "service_master.json"), str(tmp_path / "descriptor.json"))

    assert loaded["service_master"]["service_name"] == service["service_name"]
    assert loaded["parsed_descriptor"].service_name == descriptor["signed"]["service_name"]


def test_service_intro_to_rendezvous_echo_flow(monkeypatch, latnet_modules, tmp_path):
    runtime = latnet_modules["hidden_service_runtime"]
    relay_mod = latnet_modules["relay"]

    monkeypatch.setattr(runtime.oqs, "KeyEncapsulation", _DeterministicKEM)
    monkeypatch.setattr(relay_mod.oqs, "KeyEncapsulation", _DeterministicKEM)

    started: list[_RunningTcpServer] = []
    try:
        intro_relay = {
            "name": "relay-intro",
            "host": "127.0.0.1",
            "port": 0,
            "kemalg": "ML-KEM-768",
            "public_key": latnet_modules["util"].b64e(b"intro" * 8),
            "secret_key": latnet_modules["util"].b64e(b"intro" * 8),
        }
        rendezvous_relay = {
            "name": "relay-rdv",
            "host": "127.0.0.1",
            "port": 0,
            "kemalg": "ML-KEM-768",
            "public_key": latnet_modules["util"].b64e(b"rdv" * 10 + b"xx"),
            "secret_key": latnet_modules["util"].b64e(b"rdv" * 10 + b"xx"),
        }

        intro_server = relay_mod.RelayServer(intro_relay)
        running_intro = _start_tcp_server(intro_server)
        intro_relay["port"] = running_intro.port
        intro_server.relay_doc["port"] = running_intro.port
        started.append(running_intro)

        rdv_server = relay_mod.RelayServer(rendezvous_relay)
        running_rdv = _start_tcp_server(rdv_server)
        rendezvous_relay["port"] = running_rdv.port
        rdv_server.relay_doc["port"] = running_rdv.port
        started.append(running_rdv)

        _service, descriptor = _make_descriptor_doc(latnet_modules, tmp_path, intro_relay["name"], intro_relay["port"])

        intro_circuits = runtime.build_intro_circuits(descriptor, {intro_relay["name"]: intro_relay})
        assert len(intro_circuits) == 1

        client_intro_circuit = runtime.build_service_circuit([intro_relay], terminal_cmd="INTRO_READY")
        client_rdv_circuit = runtime.build_service_circuit([rendezvous_relay], terminal_cmd="RENDEZVOUS_READY")

        client_establish = runtime._send_circuit_cmd(
            client_rdv_circuit,
            {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie-echo", "side": "client"},
        )
        assert client_establish["cmd"] == "RENDEZVOUS_STATE"
        assert client_establish["joined"] is False

        intro_reply = runtime._send_circuit_cmd(
            client_intro_circuit,
            {
                "cmd": "INTRODUCE",
                "rendezvous_cookie": "cookie-echo",
                "introduction": {"rendezvous_relay": rendezvous_relay},
            },
        )
        assert intro_reply["cmd"] == "INTRO_STORED"

        intro_requests = runtime.poll_intro_requests(intro_circuits[0]["circuit"])
        assert len(intro_requests) == 1

        service_rdv_circuit, joined = runtime.establish_service_rendezvous(rendezvous_relay, "cookie-echo")
        assert joined is True

        runtime.rendezvous_send(client_rdv_circuit, "cookie-echo", "hello-service")
        service_payload = runtime.rendezvous_recv(service_rdv_circuit, "cookie-echo")
        assert service_payload == "hello-service"
        runtime.rendezvous_send(service_rdv_circuit, "cookie-echo", f"echo[hs] {service_payload}")

        echoed = runtime.rendezvous_recv(client_rdv_circuit, "cookie-echo")
        assert echoed == "echo[hs] hello-service"

    finally:
        while started:
            started.pop().stop()


def test_establish_service_rendezvous_retries_then_success(monkeypatch, latnet_modules):
    runtime = latnet_modules["hidden_service_runtime"]
    circuit = runtime.ServiceCircuit("c1", "127.0.0.1", 1, [b"f"], [b"r"])
    monkeypatch.setattr(runtime, "build_service_circuit", lambda *_args, **_kwargs: circuit)

    calls = {"n": 0}

    def _fake_send(_circuit, cmd):
        if cmd["cmd"] == "RENDEZVOUS_ESTABLISH":
            calls["n"] += 1
            if calls["n"] == 1:
                raise runtime.RelayUnreachableError("temporary")
            return {"cmd": "RENDEZVOUS_STATE", "joined": True}
        raise AssertionError("unexpected command")

    sleeps: list[float] = []
    monkeypatch.setattr(runtime, "_send_circuit_cmd", _fake_send)
    monkeypatch.setattr(runtime.time, "sleep", lambda v: sleeps.append(v))

    cfg = runtime.ReliabilityConfig(max_retries=3, retry_backoff_base_s=0.2, retry_backoff_max_s=1.0)
    built, joined = runtime.establish_service_rendezvous({"name": "r", "host": "h", "port": 1}, "cookie", config=cfg)

    assert built is circuit
    assert joined is True
    assert sleeps == [0.2]


def test_establish_service_rendezvous_retry_exhaustion(monkeypatch, latnet_modules):
    runtime = latnet_modules["hidden_service_runtime"]
    circuit = runtime.ServiceCircuit("c1", "127.0.0.1", 1, [b"f"], [b"r"])
    monkeypatch.setattr(runtime, "build_service_circuit", lambda *_args, **_kwargs: circuit)
    monkeypatch.setattr(runtime, "_send_circuit_cmd", lambda *_args, **_kwargs: (_ for _ in ()).throw(runtime.RelayUnreachableError("down")))

    sleeps: list[float] = []
    monkeypatch.setattr(runtime.time, "sleep", lambda v: sleeps.append(v))

    cfg = runtime.ReliabilityConfig(max_retries=3, retry_backoff_base_s=0.1, retry_backoff_max_s=0.5)
    with pytest.raises(runtime.RelayUnreachableError):
        runtime.establish_service_rendezvous({"name": "r", "host": "h", "port": 1}, "cookie", config=cfg)

    assert sleeps == [0.1, 0.2]


def test_establish_service_rendezvous_succeeds_when_payload_arrives_before_deadline(monkeypatch, latnet_modules):
    runtime = latnet_modules["hidden_service_runtime"]
    circuit = runtime.ServiceCircuit("c1", "127.0.0.1", 1, [b"f"], [b"r"])
    monkeypatch.setattr(runtime, "build_service_circuit", lambda *_args, **_kwargs: circuit)
    monkeypatch.setattr(
        runtime,
        "_send_circuit_cmd",
        lambda *_args, **_kwargs: {"cmd": "RENDEZVOUS_STATE", "joined": False},
    )

    recv_payloads = [None, None, "payload-before-deadline"]
    recv_calls: list[str] = []

    def _fake_recv(_circuit, rendezvous_cookie, *, config):
        recv_calls.append(rendezvous_cookie)
        return recv_payloads.pop(0)

    monotonic_values = iter([10.0, 10.0, 10.5, 10.99])
    sleeps: list[float] = []
    monkeypatch.setattr(runtime, "rendezvous_recv", _fake_recv)
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(runtime.time, "sleep", lambda v: sleeps.append(v))

    cfg = runtime.ReliabilityConfig(max_retries=1, join_timeout_s=1.0, poll_interval_s=0.05)
    built, joined = runtime.establish_service_rendezvous({"name": "r", "host": "h", "port": 1}, "cookie", config=cfg)

    assert built is circuit
    assert joined is True
    assert recv_calls == ["cookie", "cookie", "cookie"]
    assert sleeps == [0.05, 0.05]


def test_establish_service_rendezvous_raises_when_deadline_reached_without_payload(monkeypatch, latnet_modules):
    runtime = latnet_modules["hidden_service_runtime"]
    circuit = runtime.ServiceCircuit("c1", "127.0.0.1", 1, [b"f"], [b"r"])
    monkeypatch.setattr(runtime, "build_service_circuit", lambda *_args, **_kwargs: circuit)
    monkeypatch.setattr(
        runtime,
        "_send_circuit_cmd",
        lambda *_args, **_kwargs: {"cmd": "RENDEZVOUS_STATE", "joined": False},
    )

    recv_calls = {"n": 0}
    monkeypatch.setattr(
        runtime,
        "rendezvous_recv",
        lambda *_args, **_kwargs: recv_calls.__setitem__("n", recv_calls["n"] + 1) or None,
    )

    monotonic_values = iter([20.0, 20.0, 20.2, 20.3])
    sleeps: list[float] = []
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(runtime.time, "sleep", lambda v: sleeps.append(v))

    cfg = runtime.ReliabilityConfig(max_retries=1, join_timeout_s=0.3, poll_interval_s=0.1)
    with pytest.raises(runtime.RendezvousNotJoinedError):
        runtime.establish_service_rendezvous({"name": "r", "host": "h", "port": 1}, "cookie", config=cfg)

    assert recv_calls["n"] == 2
    assert sleeps == [0.1, 0.1]


@pytest.mark.parametrize(
    ("join_timeout_s", "monotonic_series", "expected_recv_calls", "expected_sleeps"),
    [
        (0.0, [30.0, 30.0], 0, []),
        (1e-6, [40.0, 40.0, 40.000001], 1, [0.002]),
    ],
)
def test_establish_service_rendezvous_zero_and_tiny_timeouts(monkeypatch, latnet_modules, join_timeout_s, monotonic_series, expected_recv_calls, expected_sleeps):
    runtime = latnet_modules["hidden_service_runtime"]
    circuit = runtime.ServiceCircuit("c1", "127.0.0.1", 1, [b"f"], [b"r"])
    monkeypatch.setattr(runtime, "build_service_circuit", lambda *_args, **_kwargs: circuit)
    monkeypatch.setattr(
        runtime,
        "_send_circuit_cmd",
        lambda *_args, **_kwargs: {"cmd": "RENDEZVOUS_STATE", "joined": False},
    )

    recv_calls = {"n": 0}
    monkeypatch.setattr(
        runtime,
        "rendezvous_recv",
        lambda *_args, **_kwargs: recv_calls.__setitem__("n", recv_calls["n"] + 1) or None,
    )

    monotonic_values = iter(monotonic_series)
    sleeps: list[float] = []
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(runtime.time, "sleep", lambda v: sleeps.append(v))

    cfg = runtime.ReliabilityConfig(max_retries=1, join_timeout_s=join_timeout_s, poll_interval_s=0.002)
    with pytest.raises(runtime.RendezvousNotJoinedError):
        runtime.establish_service_rendezvous({"name": "r", "host": "h", "port": 1}, "cookie", config=cfg)

    assert recv_calls["n"] == expected_recv_calls
    assert sleeps == expected_sleeps


def test_establish_service_rendezvous_protocol_error_is_fatal(monkeypatch, latnet_modules):
    runtime = latnet_modules["hidden_service_runtime"]
    circuit = runtime.ServiceCircuit("c1", "127.0.0.1", 1, [b"f"], [b"r"])
    monkeypatch.setattr(runtime, "build_service_circuit", lambda *_args, **_kwargs: circuit)

    calls = {"n": 0}

    def _bad(_circuit, cmd):
        if cmd["cmd"] == "RENDEZVOUS_ESTABLISH":
            calls["n"] += 1
            return {"cmd": "WRONG"}
        raise AssertionError("unexpected")

    monkeypatch.setattr(runtime, "_send_circuit_cmd", _bad)
    with pytest.raises(runtime.ProtocolMismatchError):
        runtime.establish_service_rendezvous({"name": "r", "host": "h", "port": 1}, "cookie")

    assert calls["n"] == 1


def test_rendezvous_recv_backoff_schedule(monkeypatch, latnet_modules):
    runtime = latnet_modules["hidden_service_runtime"]
    circuit = runtime.ServiceCircuit("c1", "127.0.0.1", 1, [b"f"], [b"r"])

    calls = {"n": 0}

    def _recv(_circuit, cmd):
        calls["n"] += 1
        if calls["n"] < 4:
            raise runtime.RelayUnreachableError("flaky")
        return {"cmd": "RENDEZVOUS_MESSAGE", "payload": "ok"}

    sleeps: list[float] = []
    monkeypatch.setattr(runtime, "_send_circuit_cmd", _recv)
    monkeypatch.setattr(runtime.time, "sleep", lambda v: sleeps.append(v))

    cfg = runtime.ReliabilityConfig(max_retries=5, retry_backoff_base_s=0.1, retry_backoff_max_s=0.25)
    payload = runtime.rendezvous_recv(circuit, "cookie", config=cfg)

    assert payload == "ok"
    assert sleeps == [0.1, 0.2, 0.25]
