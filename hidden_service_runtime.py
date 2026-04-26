from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

import oqs

from .constants import DEFAULT_TIMEOUT
from .crypto import decrypt_layer, derive_hop_keys, encrypt_layer
from .hidden_service_keys import load_service_master
from .models.hidden_service_descriptor import verify_hidden_service_descriptor_v2
from .util import b64d, b64e, load_json
from .wire import recv_msg, send_msg


@dataclass(frozen=True)
class ReliabilityConfig:
    """Runtime reliability policy for hidden-service rendezvous operations.

    Defaults are tuned for local development where relay RTT is small but transient
    relay unavailability can happen during startup.

    Tuning guidance:
    - Increase ``join_timeout_s`` when service/client introduction and rendezvous are
      expected to complete over higher-latency paths.
    - Increase ``max_retries`` and ``retry_backoff_max_s`` if relays are often
      booting/restarting and temporary connection errors are common.
    - Lower ``poll_interval_s`` for lower end-to-end latency at the cost of extra
      control-cell traffic.
    """

    join_timeout_s: float = 5.0
    poll_interval_s: float = 0.05
    max_retries: int = 3
    retry_backoff_base_s: float = 0.05
    retry_backoff_max_s: float = 0.5


DEFAULT_RELIABILITY_CONFIG = ReliabilityConfig()


class HiddenServiceRuntimeError(Exception):
    code = "runtime_error"
    retriable = False

    def __init__(self, message: str, *, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_error_dict(self) -> dict[str, Any]:
        data = {
            "type": type(self).__name__,
            "code": self.code,
            "message": self.message,
            "retriable": self.retriable,
        }
        if self.details:
            data["details"] = self.details
        return data


class TimeoutRuntimeError(HiddenServiceRuntimeError):
    code = "timeout"
    retriable = True


class RelayUnreachableError(HiddenServiceRuntimeError):
    code = "relay_unreachable"
    retriable = True


class ProtocolMismatchError(HiddenServiceRuntimeError):
    code = "protocol_mismatch"
    retriable = False


class InvalidIntroPayloadError(HiddenServiceRuntimeError):
    code = "invalid_intro_payload"
    retriable = False


class RendezvousNotJoinedError(HiddenServiceRuntimeError):
    code = "rendezvous_not_joined"
    retriable = True


@dataclass
class ServiceCircuit:
    circuit_id: str
    guard_host: str
    guard_port: int
    forward_keys: list[bytes]
    reverse_keys: list[bytes]


def load_service_material(service_master_path: str, descriptor_path: str, *, now: int | None = None) -> dict[str, Any]:
    service_master = load_service_master(service_master_path)
    descriptor_doc = load_json(descriptor_path)
    parsed_descriptor = verify_hidden_service_descriptor_v2(descriptor_doc, now=now)
    if parsed_descriptor.service_name != service_master["service_name"]:
        raise ValueError("descriptor service_name does not match service master")
    return {
        "service_master": service_master,
        "descriptor": descriptor_doc,
        "parsed_descriptor": parsed_descriptor,
    }


def _send_guard_message(host: str, port: int, msg: dict[str, Any]) -> dict[str, Any]:
    import socket

    try:
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
            send_msg(sock, msg)
            response = recv_msg(sock)
    except OSError as exc:
        raise RelayUnreachableError(
            f"unable to reach relay {host}:{port}",
            details={"host": host, "port": port, "error": str(exc)},
        ) from exc

    if not isinstance(response, dict):
        raise ProtocolMismatchError("relay response must be an object")
    return response


def _encapsulate_for_hop(hop: dict[str, Any], circuit_id: str) -> tuple[str, bytes, bytes]:
    with oqs.KeyEncapsulation(hop["kemalg"]) as kem:
        ct, shared_secret = kem.encap_secret(b64d(hop["public_key"]))
    forward_key, reverse_key = derive_hop_keys(shared_secret, circuit_id, hop["name"])
    return b64e(ct), forward_key, reverse_key


def _retry_delay(attempt: int, config: ReliabilityConfig) -> float:
    return min(config.retry_backoff_max_s, config.retry_backoff_base_s * (2 ** max(0, attempt - 1)))


def build_service_circuit(path_of_relays: list[dict[str, Any]], *, terminal_cmd: str, circuit_id: str | None = None) -> ServiceCircuit:
    if len(path_of_relays) < 1:
        raise ValueError("path_of_relays must contain at least one relay")
    if terminal_cmd not in {"INTRO_READY", "RENDEZVOUS_READY"}:
        raise ValueError("missing or invalid field: terminal_cmd")

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

    inner_plain: dict[str, Any] = {"cmd": terminal_cmd}
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
        raise ProtocolMismatchError(str(response.get("error", "BUILD failed")))

    return ServiceCircuit(
        circuit_id=circuit_id,
        guard_host=guard["host"],
        guard_port=int(guard["port"]),
        forward_keys=[item["forward_key"] for item in per_hop],
        reverse_keys=[item["reverse_key"] for item in per_hop],
    )


def _send_circuit_cmd(circuit: ServiceCircuit, cmd: dict[str, Any]) -> dict[str, Any]:
    layer = encrypt_layer(circuit.forward_keys[0], cmd)
    response = _send_guard_message(
        circuit.guard_host,
        circuit.guard_port,
        {"type": "CELL", "circuit_id": circuit.circuit_id, "layer": layer},
    )
    if not response.get("ok"):
        raise ProtocolMismatchError(str(response.get("error", "CELL failed")))

    reply_layer = response.get("reply_layer")
    if not isinstance(reply_layer, dict):
        raise ProtocolMismatchError("CELL response missing reply_layer")
    return decrypt_layer(circuit.reverse_keys[0], reply_layer)


def build_intro_circuits(descriptor: dict[str, Any], relays_by_name: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    parsed = verify_hidden_service_descriptor_v2(descriptor)
    intro_circuits: list[dict[str, Any]] = []
    for point in parsed.introduction_points:
        relay_doc = relays_by_name.get(point.relay_name)
        if not relay_doc:
            continue
        circuit = build_service_circuit([relay_doc], terminal_cmd="INTRO_READY")
        intro_circuits.append({
            "intro_point": point,
            "relay": relay_doc,
            "circuit": circuit,
        })
    return intro_circuits


def poll_intro_requests(intro_circuit: ServiceCircuit, *, config: ReliabilityConfig = DEFAULT_RELIABILITY_CONFIG) -> list[dict[str, Any]]:
    for attempt in range(1, config.max_retries + 1):
        try:
            reply = _send_circuit_cmd(intro_circuit, {"cmd": "INTRO_POLL"})
            if reply.get("cmd") != "INTRO_PENDING":
                raise ProtocolMismatchError(f"expected INTRO_PENDING, got {reply.get('cmd')}")
            items = reply.get("items")
            if not isinstance(items, list):
                raise InvalidIntroPayloadError("intro poll response missing items")
            return [item for item in items if isinstance(item, dict)]
        except RelayUnreachableError:
            if attempt >= config.max_retries:
                raise
            time.sleep(_retry_delay(attempt, config))
    return []


def establish_service_rendezvous(
    relay_doc: dict[str, Any], rendezvous_cookie: str, *, config: ReliabilityConfig = DEFAULT_RELIABILITY_CONFIG
) -> tuple[ServiceCircuit, bool]:
    for attempt in range(1, config.max_retries + 1):
        try:
            circuit = build_service_circuit([relay_doc], terminal_cmd="RENDEZVOUS_READY")
            reply = _send_circuit_cmd(
                circuit,
                {
                    "cmd": "RENDEZVOUS_ESTABLISH",
                    "rendezvous_cookie": rendezvous_cookie,
                    "side": "service",
                },
            )
            if reply.get("cmd") != "RENDEZVOUS_STATE":
                raise ProtocolMismatchError(f"expected RENDEZVOUS_STATE, got {reply.get('cmd')}")
            joined = bool(reply.get("joined"))
            if joined:
                return circuit, True

            deadline = time.monotonic() + max(0.0, config.join_timeout_s)
            while time.monotonic() < deadline:
                payload = rendezvous_recv(circuit, rendezvous_cookie, config=config)
                if payload is not None:
                    return circuit, True
                time.sleep(max(0.0, config.poll_interval_s))
            raise RendezvousNotJoinedError(
                "rendezvous peer did not join before timeout",
                details={"join_timeout_s": config.join_timeout_s},
            )
        except (RelayUnreachableError, RendezvousNotJoinedError):
            if attempt >= config.max_retries:
                raise
            time.sleep(_retry_delay(attempt, config))

    raise RendezvousNotJoinedError("rendezvous peer did not join")


def rendezvous_recv(
    circuit: ServiceCircuit, rendezvous_cookie: str, *, config: ReliabilityConfig = DEFAULT_RELIABILITY_CONFIG
) -> str | None:
    for attempt in range(1, config.max_retries + 1):
        try:
            reply = _send_circuit_cmd(
                circuit,
                {
                    "cmd": "RENDEZVOUS_RECV",
                    "rendezvous_cookie": rendezvous_cookie,
                },
            )
            if reply.get("cmd") != "RENDEZVOUS_MESSAGE":
                raise ProtocolMismatchError(f"expected RENDEZVOUS_MESSAGE, got {reply.get('cmd')}")
            payload = reply.get("payload")
            return payload if isinstance(payload, str) else None
        except RelayUnreachableError:
            if attempt >= config.max_retries:
                raise
            time.sleep(_retry_delay(attempt, config))
    return None


def rendezvous_send(circuit: ServiceCircuit, rendezvous_cookie: str, payload: str) -> dict[str, Any]:
    return _send_circuit_cmd(
        circuit,
        {
            "cmd": "RENDEZVOUS_RELAY",
            "rendezvous_cookie": rendezvous_cookie,
            "payload": payload,
        },
    )


def rendezvous_close(circuit: ServiceCircuit, rendezvous_cookie: str, final_payload: str = "") -> dict[str, Any]:
    return rendezvous_send(circuit, rendezvous_cookie, final_payload)


def handle_intro_request_with_echo(
    intro_request: dict[str, Any], *, service_prefix: str = "echo", config: ReliabilityConfig = DEFAULT_RELIABILITY_CONFIG
) -> dict[str, Any]:
    cookie = intro_request.get("rendezvous_cookie")
    intro = intro_request.get("introduction")
    if not isinstance(cookie, str) or not cookie:
        raise InvalidIntroPayloadError("missing or invalid field: rendezvous_cookie")
    if not isinstance(intro, dict):
        raise InvalidIntroPayloadError("missing or invalid field: introduction")

    rendezvous_relay = intro.get("rendezvous_relay")
    if not isinstance(rendezvous_relay, dict):
        raise InvalidIntroPayloadError("missing or invalid field: rendezvous_relay")

    service_rdv_circuit, joined = establish_service_rendezvous(rendezvous_relay, cookie, config=config)

    payload = rendezvous_recv(service_rdv_circuit, cookie, config=config)
    echoed = None
    if payload is not None:
        echoed = f"{service_prefix} {payload}"
        rendezvous_send(service_rdv_circuit, cookie, echoed)

    return {
        "rendezvous_cookie": cookie,
        "joined": joined,
        "received_payload": payload,
        "echoed_payload": echoed,
        "service_circuit_id": service_rdv_circuit.circuit_id,
    }


def error_to_dict(error: Exception) -> dict[str, Any]:
    if isinstance(error, HiddenServiceRuntimeError):
        return error.to_error_dict()
    if hasattr(error, "code") and hasattr(error, "retriable"):
        return {
            "type": type(error).__name__,
            "code": str(getattr(error, "code")),
            "message": str(error),
            "retriable": bool(getattr(error, "retriable")),
        }
    return {
        "type": type(error).__name__,
        "code": "unknown_error",
        "message": str(error),
        "retriable": False,
    }


__all__ = [
    "DEFAULT_RELIABILITY_CONFIG",
    "HiddenServiceRuntimeError",
    "InvalidIntroPayloadError",
    "ProtocolMismatchError",
    "ReliabilityConfig",
    "RelayUnreachableError",
    "RendezvousNotJoinedError",
    "ServiceCircuit",
    "TimeoutRuntimeError",
    "build_intro_circuits",
    "build_service_circuit",
    "error_to_dict",
    "establish_service_rendezvous",
    "handle_intro_request_with_echo",
    "load_service_material",
    "poll_intro_requests",
    "rendezvous_close",
    "rendezvous_recv",
    "rendezvous_send",
]
