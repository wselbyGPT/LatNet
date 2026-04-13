from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

import oqs

from .constants import DEFAULT_TIMEOUT, KEMALG
from .crypto import decrypt_layer, derive_hop_keys, encrypt_layer
from .models.protocol import parse_build_envelope, parse_cell_envelope, parse_destroy_envelope, parse_exit_cell_layer, parse_layer
from .util import atomic_write_json, b64d, b64e, load_json
from .wire import recv_msg, send_msg


def init_relay_file(name: str, host: str, port: int, out_path: str | Path) -> dict[str, Any]:
    with oqs.KeyEncapsulation(KEMALG) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()

    relay_doc = {
        "name": name,
        "host": host,
        "port": port,
        "kemalg": KEMALG,
        "public_key": b64e(public_key),
        "secret_key": b64e(secret_key),
    }
    atomic_write_json(out_path, relay_doc)
    return relay_doc


class RelayServer:
    def __init__(self, relay_doc: dict[str, Any]):
        self.relay_doc = relay_doc
        self.circuits: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()

    def circuit_snapshot(self, circuit_id: str) -> dict[str, Any] | None:
        with self.lock:
            state = self.circuits.get(circuit_id)
            if state is None:
                return None
            return json.loads(json.dumps(state))

    def set_circuit_state(self, circuit_id: str, state: dict[str, Any]) -> None:
        with self.lock:
            self.circuits[circuit_id] = state

    def update_stream_state(self, circuit_id: str, stream_id: int, stream_state: dict[str, Any] | None) -> None:
        with self.lock:
            circuit = self.circuits[circuit_id]
            streams = circuit.setdefault("streams", {})
            sid = str(stream_id)
            if stream_state is None:
                streams.pop(sid, None)
            else:
                streams[sid] = stream_state

    def relay_decap_and_keys(self, ct_b64: str, circuit_id: str) -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self.relay_doc["kemalg"], b64d(self.relay_doc["secret_key"])) as kem:
            shared_secret = kem.decap_secret(b64d(ct_b64))
        return derive_hop_keys(shared_secret, circuit_id, self.relay_doc["name"])

    def wrap_reverse_hop(self, reverse_key: bytes, next_response: dict[str, Any]) -> dict[str, Any]:
        if not next_response.get("ok"):
            return next_response
        return {
            "ok": True,
            "reply_layer": encrypt_layer(
                reverse_key,
                {
                    "cmd": "RELAY_BACK",
                    "inner": next_response["reply_layer"],
                },
            ),
        }

    def handle_exit_cell(self, circuit_id: str, state: dict[str, Any], cell: dict[str, Any]) -> dict[str, Any]:
        parsed_cell = parse_exit_cell_layer({"cmd": "EXIT_CELL", "cell": cell}).cell
        stream_id = parsed_cell.stream_id
        seq = parsed_cell.seq
        cell_type = parsed_cell.cell_type
        payload = parsed_cell.payload

        streams = state.setdefault("streams", {})
        sid = str(stream_id)
        stream_state = streams.get(sid)

        if cell_type == "BEGIN":
            stream_state = {
                "open": True,
                "opened_at": time.time(),
                "last_seq": seq,
            }
            self.update_stream_state(circuit_id, stream_id, stream_state)
            reply_cell = {
                "stream_id": stream_id,
                "seq": seq,
                "cell_type": "CONNECTED",
                "payload": f"stream {stream_id} opened at exit {self.relay_doc['name']}",
            }
        elif cell_type == "DATA":
            if not stream_state or not stream_state.get("open"):
                reply_cell = {
                    "stream_id": stream_id,
                    "seq": seq,
                    "cell_type": "ERROR",
                    "payload": f"stream {stream_id} is not open",
                }
            else:
                stream_state["last_seq"] = seq
                self.update_stream_state(circuit_id, stream_id, stream_state)
                reply_cell = {
                    "stream_id": stream_id,
                    "seq": seq,
                    "cell_type": "DATA",
                    "payload": f"echo[{stream_id}] {payload}",
                }
        elif cell_type == "END":
            if not stream_state or not stream_state.get("open"):
                reply_cell = {
                    "stream_id": stream_id,
                    "seq": seq,
                    "cell_type": "ENDED",
                    "payload": f"stream {stream_id} was already closed",
                }
            else:
                self.update_stream_state(circuit_id, stream_id, None)
                reply_cell = {
                    "stream_id": stream_id,
                    "seq": seq,
                    "cell_type": "ENDED",
                    "payload": f"stream {stream_id} closed at exit {self.relay_doc['name']}",
                }
        else:
            reply_cell = {
                "stream_id": stream_id,
                "seq": seq,
                "cell_type": "ERROR",
                "payload": f"unknown cell_type {cell_type}",
            }

        print()
        print(
            f"[EXIT {self.relay_doc['name']}] circuit={circuit_id} "
            f"stream={stream_id} seq={seq} type={cell_type} payload={payload!r}"
        )
        print(
            f"[EXIT {self.relay_doc['name']}] reply "
            f"stream={reply_cell['stream_id']} seq={reply_cell['seq']} "
            f"type={reply_cell['cell_type']} payload={reply_cell['payload']!r}"
        )
        print()

        return {
            "ok": True,
            "reply_layer": encrypt_layer(
                b64d(state["reverse_key"]),
                {
                    "cmd": "REPLY_CELL",
                    "cell": reply_cell,
                },
            ),
        }

    def forward_to_next(self, state: dict[str, Any], msg: dict[str, Any]) -> dict[str, Any]:
        next_hop = state["next"]
        with socket.create_connection((next_hop["host"], next_hop["port"]), timeout=DEFAULT_TIMEOUT) as sock:
            send_msg(sock, msg)
            return recv_msg(sock)

    def handle_build(self, msg: dict[str, Any]) -> dict[str, Any]:
        env = parse_build_envelope(msg)
        circuit_id = env.circuit_id
        forward_key, reverse_key = self.relay_decap_and_keys(env.ct, circuit_id)
        layer = parse_layer(decrypt_layer(forward_key, env.layer))

        if layer.cmd == "FORWARD_BUILD":
            state = {
                "role": "forward",
                "forward_key": b64e(forward_key),
                "reverse_key": b64e(reverse_key),
                "next": {"host": layer.next.host, "port": layer.next.port},
                "streams": {},
                "created_at": time.time(),
            }
            self.set_circuit_state(circuit_id, state)

            next_build = {
                "type": "BUILD",
                "circuit_id": circuit_id,
                "ct": layer.next_ct,
                "layer": layer.inner,
            }
            return self.forward_to_next(state, next_build)

        if layer.cmd == "EXIT_READY":
            state = {
                "role": "exit",
                "forward_key": b64e(forward_key),
                "reverse_key": b64e(reverse_key),
                "streams": {},
                "created_at": time.time(),
            }
            self.set_circuit_state(circuit_id, state)
            print(f"[{self.relay_doc['name']}] circuit {circuit_id} ready as exit")
            return {"ok": True, "status": "circuit_built", "role": "exit"}

        return {"ok": False, "error": f"unknown build cmd: {layer.cmd}"}

    def handle_cell(self, msg: dict[str, Any]) -> dict[str, Any]:
        env = parse_cell_envelope(msg)
        circuit_id = env.circuit_id
        state = self.circuit_snapshot(circuit_id)
        if state is None:
            return {"ok": False, "error": f"unknown circuit_id {circuit_id}"}

        forward_key = b64d(state["forward_key"])
        reverse_key = b64d(state["reverse_key"])
        layer = parse_layer(decrypt_layer(forward_key, env.layer))

        if state["role"] == "forward":
            if layer.cmd != "FORWARD_CELL":
                return {"ok": False, "error": f"expected FORWARD_CELL, got {layer.cmd}"}

            next_msg = {
                "type": "CELL",
                "circuit_id": circuit_id,
                "layer": layer.inner,
            }
            next_response = self.forward_to_next(state, next_msg)
            return self.wrap_reverse_hop(reverse_key, next_response)

        if state["role"] == "exit":
            if layer.cmd != "EXIT_CELL":
                return {"ok": False, "error": f"expected EXIT_CELL, got {layer.cmd}"}
            return self.handle_exit_cell(circuit_id, state, {
                "stream_id": layer.cell.stream_id,
                "seq": layer.cell.seq,
                "cell_type": layer.cell.cell_type,
                "payload": layer.cell.payload,
            })

        return {"ok": False, "error": f"unknown circuit role {state['role']}"}

    def handle_destroy(self, msg: dict[str, Any]) -> dict[str, Any]:
        env = parse_destroy_envelope(msg)
        circuit_id = env.circuit_id
        state = self.circuit_snapshot(circuit_id)
        if state is None:
            return {"ok": True, "status": "already_gone"}

        if state["role"] == "forward":
            try:
                self.forward_to_next(state, {"type": "DESTROY", "circuit_id": circuit_id})
            except Exception:
                pass

        with self.lock:
            self.circuits.pop(circuit_id, None)

        print(f"[{self.relay_doc['name']}] circuit {circuit_id} destroyed")
        return {"ok": True, "status": "destroyed"}

    def handle_conn(self, conn: socket.socket) -> None:
        try:
            msg = recv_msg(conn)
            msg_type = msg.get("type")

            if msg_type == "BUILD":
                response = self.handle_build(msg)
            elif msg_type == "CELL":
                response = self.handle_cell(msg)
            elif msg_type == "DESTROY":
                response = self.handle_destroy(msg)
            else:
                response = {"ok": False, "error": f"unknown message type {msg_type}"}

            send_msg(conn, response)
        except Exception as exc:
            try:
                send_msg(conn, {"ok": False, "error": str(exc)})
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


def run_relay_server(relay_path: str) -> None:
    relay_doc = load_json(relay_path)
    host = relay_doc["host"]
    port = relay_doc["port"]
    server = RelayServer(relay_doc)

    print(f"Starting relay {relay_doc['name']} on {host}:{port} using {relay_doc['kemalg']}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(128)

        while True:
            conn, _addr = srv.accept()
            server.handle_conn(conn)
