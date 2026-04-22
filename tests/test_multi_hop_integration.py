from __future__ import annotations

import json
import socket
import threading
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


@pytest.mark.parametrize("hop_count", [2, 3])
def test_multi_hop_full_build_cell_destroy_path(monkeypatch, tmp_path, latnet_modules, hop_count):
    client_mod = latnet_modules["client"]
    relay_mod = latnet_modules["relay"]
    directory_mod = latnet_modules["directory"]
    util = latnet_modules["util"]

    monkeypatch.setattr(client_mod.oqs, "KeyEncapsulation", _DeterministicKEM)
    monkeypatch.setattr(relay_mod.oqs, "KeyEncapsulation", _DeterministicKEM)

    started: list[_RunningTcpServer] = []
    try:
        relay_docs = []
        for relay_name in ["guard", "middle", "exit"]:
            key_material = relay_name.encode("utf-8") * 4
            relay_doc = {
                "name": relay_name,
                "host": "127.0.0.1",
                "port": 0,
                "kemalg": "ML-KEM-768",
                "public_key": util.b64e(key_material),
                "secret_key": util.b64e(key_material),
            }
            relay_server = relay_mod.RelayServer(relay_doc)
            running = _start_tcp_server(relay_server)
            relay_doc["port"] = running.port
            relay_server.relay_doc["port"] = running.port
            relay_docs.append(relay_doc)
            started.append(running)

        bundle = {
            "version": 1,
            "authority_key_id": "integration-test",
            "descriptors": relay_docs,
        }
        bundle_path = tmp_path / "bundle.json"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        directory_server = directory_mod.DirectoryServer(str(bundle_path))
        running_directory = _start_tcp_server(directory_server)
        started.append(running_directory)

        fetched_bundle = client_mod.fetch_bundle_from_directory(running_directory.host, running_directory.port)
        path = fetched_bundle["descriptors"][:hop_count]

        circuit = client_mod.build_circuit(path, circuit_id=f"multi-hop-{hop_count}")

        for hop_index, hop in enumerate(path):
            relay_server = started[hop_index].server
            state = relay_server.circuit_snapshot(circuit.circuit_id)
            assert state is not None
            assert state["lifecycle_state"] == "ready"
            expected_role = "exit" if hop_index == (hop_count - 1) else "forward"
            assert state["role"] == expected_role

        connected = client_mod.open_stream(circuit, stream_id=21, target="example.org:443")
        assert connected["cell_type"] == "CONNECTED"
        assert connected["seq"] == 1

        echoed = client_mod.send_stream_data(circuit, stream_id=21, payload="hello through chain")
        assert echoed["cell_type"] == "DATA"
        assert echoed["seq"] == 2
        assert "echo[21] hello through chain" == echoed["payload"]

        ended = client_mod.end_stream(circuit, stream_id=21, payload="done")
        assert ended["cell_type"] == "ENDED"
        assert ended["seq"] == 3

        destroyed = client_mod.destroy_circuit(circuit)
        assert destroyed == {"ok": True, "status": "destroyed"}

        for hop_index in range(hop_count):
            relay_server = started[hop_index].server
            assert relay_server.circuit_snapshot(circuit.circuit_id) is None

    finally:
        while started:
            started.pop().stop()
