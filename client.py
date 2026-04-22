from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import oqs

from .constants import DEFAULT_TIMEOUT
from .crypto import decrypt_layer, derive_hop_keys, encrypt_layer
from .directory import DirectoryServer, run_directory_server
from .models.hidden_service import parse_lettuce_name
from .models.hidden_service_descriptor import verify_hidden_service_descriptor_v2
from .util import atomic_write_json, b64d, b64e
from .wire import recv_msg, send_msg


@dataclass
class HopSession:
    name: str
    host: str
    port: int
    forward_key: bytes
    reverse_key: bytes


@dataclass
class CircuitSession:
    circuit_id: str
    guard_host: str
    guard_port: int
    hops: list[HopSession]
    stream_next_seq: dict[int, int] = field(default_factory=dict)



def fetch_bundle_from_directory(host: str, port: int = 9200) -> dict[str, Any]:
    import socket

    with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
        send_msg(sock, {"type": "GET_BUNDLE"})
        response = recv_msg(sock)

    if not isinstance(response, dict):
        raise ValueError("directory response must be an object")
    if not response.get("ok"):
        raise ValueError(response.get("error", "directory returned error"))
    bundle = response.get("bundle")
    if not isinstance(bundle, dict):
        raise ValueError("directory response missing bundle")
    return bundle



def fetch_bundle_to_file(host: str, port: int, out_path: str) -> dict[str, Any]:
    bundle = fetch_bundle_from_directory(host, port)
    atomic_write_json(out_path, bundle)
    return bundle



def fetch_hidden_service_descriptor_from_directory(host: str, service_name: str, port: int = 9200) -> dict[str, Any]:
    import socket

    parse_lettuce_name(service_name)
    with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
        send_msg(sock, {"type": "GET_HS_DESCRIPTOR", "service_name": service_name})
        response = recv_msg(sock)

    if not isinstance(response, dict):
        raise ValueError("directory response must be an object")
    if not response.get("ok"):
        raise ValueError(response.get("error", "directory returned error"))
    descriptor = response.get("descriptor")
    if not isinstance(descriptor, dict):
        raise ValueError("directory response missing descriptor")
    parsed = verify_hidden_service_descriptor_v2(descriptor)
    if parsed.service_name != service_name:
        raise ValueError("directory returned descriptor for unexpected service name")
    return descriptor



def _send_guard_message(host: str, port: int, msg: dict[str, Any]) -> dict[str, Any]:
    import socket

    with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
        send_msg(sock, msg)
        response = recv_msg(sock)
    if not isinstance(response, dict):
        raise ValueError("relay response must be an object")
    return response



def _encapsulate_for_hop(hop: dict[str, Any], circuit_id: str) -> tuple[str, bytes, bytes]:
    with oqs.KeyEncapsulation(hop["kemalg"]) as kem:
        ct, shared_secret = kem.encap_secret(b64d(hop["public_key"]))
    forward_key, reverse_key = derive_hop_keys(shared_secret, circuit_id, hop["name"])
    return b64e(ct), forward_key, reverse_key



def build_circuit(path_of_relays: list[dict[str, Any]], circuit_id: str | None = None) -> CircuitSession:
    if len(path_of_relays) < 1:
        raise ValueError("path_of_relays must contain at least one relay")

    circuit_id = circuit_id or uuid.uuid4().hex

    per_hop: list[dict[str, Any]] = []
    for hop in path_of_relays:
        ct_b64, forward_key, reverse_key = _encapsulate_for_hop(hop, circuit_id)
        per_hop.append({
            "hop": hop,
            "ct": ct_b64,
            "forward_key": forward_key,
            "reverse_key": reverse_key,
        })

    inner_plain: dict[str, Any] = {"cmd": "EXIT_READY"}
    inner_wrapped = encrypt_layer(per_hop[-1]["forward_key"], inner_plain)

    for idx in range(len(per_hop) - 2, -1, -1):
        current = per_hop[idx]
        nxt = per_hop[idx + 1]
        inner_plain = {
            "cmd": "FORWARD_BUILD",
            "next": {
                "host": nxt["hop"]["host"],
                "port": nxt["hop"]["port"],
            },
            "next_ct": nxt["ct"],
            "inner": inner_wrapped,
        }
        inner_wrapped = encrypt_layer(current["forward_key"], inner_plain)

    guard = per_hop[0]["hop"]
    response = _send_guard_message(
        guard["host"],
        int(guard["port"]),
        {
            "type": "BUILD",
            "circuit_id": circuit_id,
            "ct": per_hop[0]["ct"],
            "layer": inner_wrapped,
        },
    )
    if not response.get("ok"):
        raise ValueError(response.get("error", "BUILD failed"))

    return CircuitSession(
        circuit_id=circuit_id,
        guard_host=guard["host"],
        guard_port=int(guard["port"]),
        hops=[
            HopSession(
                name=item["hop"]["name"],
                host=item["hop"]["host"],
                port=int(item["hop"]["port"]),
                forward_key=item["forward_key"],
                reverse_key=item["reverse_key"],
            )
            for item in per_hop
        ],
    )



def _wrap_forward_cell(circuit: CircuitSession, cell: dict[str, Any]) -> dict[str, str]:
    inner = encrypt_layer(circuit.hops[-1].forward_key, {"cmd": "EXIT_CELL", "cell": cell})
    for hop in reversed(circuit.hops[:-1]):
        inner = encrypt_layer(hop.forward_key, {"cmd": "FORWARD_CELL", "inner": inner})
    return inner



def _unwrap_reply_cell(circuit: CircuitSession, response: dict[str, Any]) -> dict[str, Any]:
    if not response.get("ok"):
        raise ValueError(response.get("error", "CELL failed"))
    if "reply_layer" not in response:
        raise ValueError("CELL response missing reply_layer")

    layer = decrypt_layer(circuit.hops[0].reverse_key, response["reply_layer"])
    for hop in circuit.hops[1:]:
        if layer.get("cmd") != "RELAY_BACK":
            raise ValueError(f"expected RELAY_BACK layer, got {layer.get('cmd')}")
        layer = decrypt_layer(hop.reverse_key, layer["inner"])

    if layer.get("cmd") != "REPLY_CELL":
        raise ValueError(f"expected REPLY_CELL, got {layer.get('cmd')}")
    cell = layer.get("cell")
    if not isinstance(cell, dict):
        raise ValueError("reply cell missing")
    return cell



def open_stream(circuit: CircuitSession, stream_id: int, target: str = "") -> dict[str, Any]:
    cell = {"stream_id": stream_id, "seq": 1, "cell_type": "BEGIN", "payload": target}
    response = _send_guard_message(
        circuit.guard_host,
        circuit.guard_port,
        {"type": "CELL", "circuit_id": circuit.circuit_id, "layer": _wrap_forward_cell(circuit, cell)},
    )
    reply_cell = _unwrap_reply_cell(circuit, response)
    if reply_cell.get("cell_type") == "CONNECTED":
        circuit.stream_next_seq[stream_id] = 2
    return reply_cell



def send_stream_data(circuit: CircuitSession, stream_id: int, payload: str) -> dict[str, Any]:
    seq = circuit.stream_next_seq.get(stream_id)
    if seq is None:
        raise ValueError(f"stream {stream_id} is not open")
    cell = {"stream_id": stream_id, "seq": seq, "cell_type": "DATA", "payload": payload}
    response = _send_guard_message(
        circuit.guard_host,
        circuit.guard_port,
        {"type": "CELL", "circuit_id": circuit.circuit_id, "layer": _wrap_forward_cell(circuit, cell)},
    )
    reply_cell = _unwrap_reply_cell(circuit, response)
    if reply_cell.get("cell_type") != "ERROR":
        circuit.stream_next_seq[stream_id] = seq + 1
    return reply_cell



def end_stream(circuit: CircuitSession, stream_id: int, payload: str = "") -> dict[str, Any]:
    seq = circuit.stream_next_seq.get(stream_id)
    if seq is None:
        raise ValueError(f"stream {stream_id} is not open")
    cell = {"stream_id": stream_id, "seq": seq, "cell_type": "END", "payload": payload}
    response = _send_guard_message(
        circuit.guard_host,
        circuit.guard_port,
        {"type": "CELL", "circuit_id": circuit.circuit_id, "layer": _wrap_forward_cell(circuit, cell)},
    )
    reply_cell = _unwrap_reply_cell(circuit, response)
    if reply_cell.get("cell_type") in {"ENDED", "ERROR"}:
        circuit.stream_next_seq.pop(stream_id, None)
    return reply_cell



def destroy_circuit(circuit: CircuitSession) -> dict[str, Any]:
    response = _send_guard_message(
        circuit.guard_host,
        circuit.guard_port,
        {"type": "DESTROY", "circuit_id": circuit.circuit_id},
    )
    circuit.stream_next_seq.clear()
    if not response.get("ok"):
        raise ValueError(response.get("error", "DESTROY failed"))
    return response



def demo_circuit_echo(
    path_of_relays: list[dict[str, Any]],
    *,
    stream_id: int = 1,
    target: str = "demo:443",
    payload: str = "hello",
) -> dict[str, Any]:
    circuit = build_circuit(path_of_relays)
    opened = open_stream(circuit, stream_id=stream_id, target=target)
    data = send_stream_data(circuit, stream_id=stream_id, payload=payload)
    ended = end_stream(circuit, stream_id=stream_id, payload="done")
    destroyed = destroy_circuit(circuit)
    return {
        "circuit_id": circuit.circuit_id,
        "open": opened,
        "data": data,
        "end": ended,
        "destroy": destroyed,
    }


__all__ = [
    "fetch_bundle_from_directory",
    "fetch_bundle_to_file",
    "fetch_hidden_service_descriptor_from_directory",
    "build_circuit",
    "open_stream",
    "send_stream_data",
    "end_stream",
    "destroy_circuit",
    "demo_circuit_echo",
    "CircuitSession",
    # deprecated directory-server import compatibility
    "DirectoryServer",
    "run_directory_server",
]
