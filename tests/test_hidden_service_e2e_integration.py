from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass



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


def _make_descriptor(latnet_modules, service, intro_relay):
    hs_keys = latnet_modules["hidden_service_keys"]
    util = latnet_modules["util"]
    now = int(time.time())
    signing = hs_keys.generate_descriptor_signing_key()
    cert = hs_keys.build_descriptor_signing_certificate(service, signing["descriptor_signing_public_key"], valid_for=180, now=now)
    signed = {
        "service_name": service["service_name"],
        "service_master_public_key": service["service_master_public_key"],
        "descriptor_signing_public_key": signing["descriptor_signing_public_key"],
        "descriptor_signing_certificate": cert,
        "valid_after": now - 1,
        "valid_until": now + 120,
        "revision": 1,
        "period": 1,
        "introduction_points": [
            {
                "relay_name": intro_relay["name"],
                "relay_addr": {"host": intro_relay["host"], "port": intro_relay["port"]},
                "intro_auth_pub": util.b64e(b"intro-auth"),
                "intro_key_id": "intro-k-1",
                "expires_at": now + 120,
            }
        ],
    }
    signer = hs_keys.Ed25519PrivateKey.from_private_bytes(util.b64d(signing["descriptor_signing_private_key"]))
    return {
        "version": 2,
        "sigalg": hs_keys.HS_SIGALG,
        "signed": signed,
        "signature": util.b64e(signer.sign(util.canonical_bytes(signed))),
    }


def test_hidden_service_end_to_end_echo_via_directory(monkeypatch, latnet_modules, tmp_path):
    relay_mod = latnet_modules["relay"]
    runtime = latnet_modules["hidden_service_runtime"]
    directory_mod = latnet_modules["directory"]
    client = latnet_modules["client"]
    util = latnet_modules["util"]
    hs_keys = latnet_modules["hidden_service_keys"]

    monkeypatch.setattr(relay_mod.oqs, "KeyEncapsulation", _DeterministicKEM)
    monkeypatch.setattr(runtime.oqs, "KeyEncapsulation", _DeterministicKEM)

    servers: list[_RunningTcpServer] = []
    try:
        intro_relay = {
            "name": "intro-r",
            "host": "127.0.0.1",
            "port": 0,
            "kemalg": "ML-KEM-768",
            "public_key": util.b64e(b"intro" * 8),
            "secret_key": util.b64e(b"intro" * 8),
        }
        rdv_relay = {
            "name": "rdv-r",
            "host": "127.0.0.1",
            "port": 0,
            "kemalg": "ML-KEM-768",
            "public_key": util.b64e(b"rdv" * 10 + b"xx"),
            "secret_key": util.b64e(b"rdv" * 10 + b"xx"),
        }

        intro_server = relay_mod.RelayServer(intro_relay)
        run_intro = _start_tcp_server(intro_server)
        servers.append(run_intro)
        intro_relay["port"] = run_intro.port
        intro_server.relay_doc["port"] = run_intro.port

        rdv_server = relay_mod.RelayServer(rdv_relay)
        run_rdv = _start_tcp_server(rdv_server)
        servers.append(run_rdv)
        rdv_relay["port"] = run_rdv.port
        rdv_server.relay_doc["port"] = run_rdv.port

        service = hs_keys.generate_service_master("svc", tmp_path / "service_master.json")
        descriptor = _make_descriptor(latnet_modules, service, intro_relay)

        bundle_path = tmp_path / "bundle.json"
        bundle_path.write_text(json.dumps({"version": 1, "relays": [intro_relay, rdv_relay]}), encoding="utf-8")
        hs_store = tmp_path / "hs_store.json"
        hs_store.write_text(json.dumps({"version": 1, "descriptors": [descriptor]}), encoding="utf-8")

        directory_server = directory_mod.DirectoryServer(str(bundle_path), hidden_service_store_path=str(hs_store))
        run_dir = _start_tcp_server(directory_server)
        servers.append(run_dir)

        fetched = client.fetch_hidden_service_descriptor_from_directory(run_dir.host, service["service_name"], port=run_dir.port)
        intro_point = client.select_intro_point_for_phase1(fetched)
        assert intro_point["relay_name"] == intro_relay["name"]

        service_intro = runtime.build_intro_circuits(descriptor, {intro_relay["name"]: intro_relay})[0]["circuit"]
        client_intro = runtime.build_service_circuit([intro_relay], terminal_cmd="INTRO_READY")
        client_rdv = runtime.build_service_circuit([rdv_relay], terminal_cmd="RENDEZVOUS_READY")

        cookie = "cookie-e2e"
        est_client = runtime._send_circuit_cmd(
            client_rdv, {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": cookie, "side": "client"}
        )
        assert est_client["joined"] is False

        runtime._send_circuit_cmd(
            client_intro,
            {"cmd": "INTRODUCE", "rendezvous_cookie": cookie, "introduction": {"rendezvous_relay": rdv_relay}},
        )

        pending = runtime.poll_intro_requests(service_intro)
        assert len(pending) == 1

        service_rdv, joined = runtime.establish_service_rendezvous(rdv_relay, cookie)
        assert joined is True

        runtime.rendezvous_send(client_rdv, cookie, "hello-e2e")
        got = runtime.rendezvous_recv(service_rdv, cookie)
        runtime.rendezvous_send(service_rdv, cookie, f"echo[hs] {got}")

        echoed = runtime.rendezvous_recv(client_rdv, cookie)
        assert echoed == "echo[hs] hello-e2e"

        for circuit in (client_intro, client_rdv, service_intro, service_rdv):
            destroy = runtime._send_guard_message(
                circuit.guard_host,
                circuit.guard_port,
                {"type": "DESTROY", "circuit_id": circuit.circuit_id},
            )
            assert destroy["ok"] is True

    finally:
        while servers:
            servers.pop().stop()
