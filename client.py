from __future__ import annotations

import time
import uuid
import os
import json
import random
import threading
from dataclasses import dataclass, field
from typing import Any, Literal

import oqs

from .authority import verify_network_status
from .constants import CELL_PAYLOAD_BYTES, DEFAULT_TIMEOUT
from .crypto import decrypt_layer, derive_hop_keys, encrypt_layer
from .models.hidden_service import parse_lettuce_name
from .models.hidden_service_descriptor import verify_hidden_service_descriptor_v2
from .models.protocol import (
    encode_stream_cell_payload,
    parse_publish_hidden_service_descriptor_request,
    parse_publish_hidden_service_descriptor_response,
)
from .util import atomic_write_json, b64d, b64e, load_json
from .wire import recv_msg, send_msg

NO_DESCRIPTOR_ERROR = "no descriptor available for hidden service"
EXPIRED_DESCRIPTOR_ERROR = "hidden service descriptor is expired"
NO_REACHABLE_INTRO_POINTS_ERROR = "all introduction points are expired or unreachable"
_MIN_SELECTION_PROBABILITY = 0.05
_DEFAULT_TOP_N = 3


class PublishDescriptorError(ValueError):
    pass


class PublishDescriptorRevisionConflictError(PublishDescriptorError):
    pass


class PublishDescriptorExpiredError(PublishDescriptorError):
    pass


class PublishDescriptorInvalidSignatureError(PublishDescriptorError):
    pass


class PublishDescriptorUnauthorizedError(PublishDescriptorError):
    pass


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
    cell_batcher: "CircuitCellBatcher | None" = None
    keepalive_scheduler: "CircuitKeepaliveScheduler | None" = None
    keepalive_paused_until: float = 0.0
    last_real_traffic_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class PaddingPolicyConfig:
    mode: Literal["disabled", "opportunistic", "constant-rate"] = "disabled"
    min_interval_s: float = 0.25
    max_interval_s: float = 2.0
    burst_limit: int = 4




@dataclass(frozen=True)
class KeepaliveConfig:
    base_interval_s: float = 15.0
    jitter_ratio: float = 0.2
    pause_after_real_traffic_s: float = 5.0


DEFAULT_KEEPALIVE_CONFIG = KeepaliveConfig()


class CircuitKeepaliveScheduler:
    def __init__(self, circuit: CircuitSession, config: KeepaliveConfig = DEFAULT_KEEPALIVE_CONFIG):
        self.circuit = circuit
        self.config = config
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"keepalive-{circuit.circuit_id[:8]}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def note_real_traffic(self) -> None:
        now = time.time()
        self.circuit.last_real_traffic_at = now
        self.circuit.keepalive_paused_until = now + max(0.0, self.config.pause_after_real_traffic_s)

    def _next_interval(self) -> float:
        base = max(0.1, self.config.base_interval_s)
        jitter = max(0.0, min(self.config.jitter_ratio, 0.95))
        return base * (1.0 + random.uniform(-jitter, jitter))

    def _run(self) -> None:
        while not self._stop.wait(self._next_interval()):
            if time.time() < self.circuit.keepalive_paused_until:
                continue
            try:
                _send_batched_cells(self.circuit, include_current={"stream_id": 0, "seq": 0, "cell_type": "PADDING", "payload": ""}, force_flush=True)
            except Exception:
                continue

@dataclass
class _QueuedCell:
    cell: dict[str, Any]
    enqueued_at: float


@dataclass
class CircuitCellBatcher:
    flush_window_ms: int = 30
    max_batch_size: int = 8
    queue: list[_QueuedCell] = field(default_factory=list)

    def enqueue(self, cell: dict[str, Any], *, now: float | None = None) -> None:
        self.queue.append(_QueuedCell(cell=dict(cell), enqueued_at=time.time() if now is None else now))

    def should_flush(self, *, now: float | None = None, force: bool = False) -> bool:
        if force:
            return bool(self.queue)
        if not self.queue:
            return False
        if len(self.queue) >= self.max_batch_size:
            return True
        ts = time.time() if now is None else now
        age_ms = (ts - self.queue[0].enqueued_at) * 1000.0
        return age_ms >= self.flush_window_ms

    def pop_batch(self) -> list[dict[str, Any]]:
        batch = [entry.cell for entry in self.queue[: self.max_batch_size]]
        self.queue = self.queue[len(batch) :]
        return batch


@dataclass(frozen=True)
class ClientTrustConfig:
    trusted_authorities: list[dict[str, str]]
    min_signers: int
    authority_set_version: int | None = None


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


def fetch_network_status_from_directory(host: str, port: int = 9200) -> dict[str, Any]:
    import socket

    with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
        send_msg(sock, {"type": "GET_NETWORK_STATUS"})
        response = recv_msg(sock)

    if not isinstance(response, dict):
        raise ValueError("directory response must be an object")
    if not response.get("ok"):
        raise ValueError(response.get("error", "directory returned error"))
    status = response.get("network_status")
    if not isinstance(status, dict):
        raise ValueError("directory response missing network_status")
    return status


def load_client_trust_config(
    *,
    trust_config_path: str | None = None,
    trusted_authorities: list[dict[str, str]] | None = None,
    min_signers: int | None = None,
    authority_set_version: int | None = None,
) -> ClientTrustConfig:
    env_path = os.getenv("LATNET_TRUST_CONFIG")
    chosen_path = trust_config_path or env_path
    file_config: dict[str, Any] = {}
    if chosen_path:
        file_config = load_json(chosen_path)
        if not isinstance(file_config, dict):
            raise ValueError("trust config file must be a JSON object")

    env_authorities_raw = os.getenv("LATNET_TRUSTED_AUTHORITIES")
    env_authorities: list[dict[str, str]] | None = None
    if env_authorities_raw:
        parsed = json.loads(env_authorities_raw)
        if not isinstance(parsed, list):
            raise ValueError("LATNET_TRUSTED_AUTHORITIES must be a JSON list")
        env_authorities = parsed

    merged_authorities = trusted_authorities or env_authorities or file_config.get("trusted_authorities")
    if not isinstance(merged_authorities, list) or not merged_authorities:
        raise ValueError("trust config requires trusted_authorities list")

    normalized_authorities: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for item in merged_authorities:
        if not isinstance(item, dict):
            raise ValueError("trusted authority entries must be objects")
        authority_id = item.get("authority_id") or item.get("key_id")
        public_key = item.get("public_key")
        if not isinstance(authority_id, str) or not authority_id:
            raise ValueError("trusted authority missing authority_id")
        if authority_id in seen_ids:
            raise ValueError(f"duplicate trusted authority id: {authority_id}")
        seen_ids.add(authority_id)
        if not isinstance(public_key, str) or not public_key:
            raise ValueError(f"trusted authority missing public_key for {authority_id}")
        normalized_authorities.append({"authority_id": authority_id, "public_key": public_key})

    env_min_signers = os.getenv("LATNET_MIN_SIGNERS")
    effective_min_signers = min_signers
    if effective_min_signers is None and env_min_signers is not None:
        effective_min_signers = int(env_min_signers)
    if effective_min_signers is None:
        effective_min_signers = file_config.get("min_signers")
    if not isinstance(effective_min_signers, int) or effective_min_signers <= 0:
        raise ValueError("trust config requires positive min_signers")
    if effective_min_signers > len(normalized_authorities):
        raise ValueError("min_signers cannot exceed trusted authority count")

    env_authority_set_version = os.getenv("LATNET_AUTHORITY_SET_VERSION")
    effective_set_version = authority_set_version
    if effective_set_version is None and env_authority_set_version is not None:
        effective_set_version = int(env_authority_set_version)
    if effective_set_version is None:
        file_value = file_config.get("authority_set_version")
        if file_value is None:
            file_value = file_config.get("authority_set_epoch")
        effective_set_version = file_value
    if effective_set_version is not None and not isinstance(effective_set_version, int):
        raise ValueError("authority_set_version must be an integer when provided")

    return ClientTrustConfig(
        trusted_authorities=normalized_authorities,
        min_signers=effective_min_signers,
        authority_set_version=effective_set_version,
    )


def verified_relays_from_network_status(
    network_status: dict[str, Any],
    trust: ClientTrustConfig,
    *,
    now: int | None = None,
) -> dict[str, dict[str, Any]]:
    if trust.authority_set_version is not None:
        declared_version = network_status.get("authority_set_version")
        if declared_version is None:
            declared_version = network_status.get("authority_set_epoch")
        if declared_version != trust.authority_set_version:
            raise ValueError(
                "network status authority set version mismatch: "
                f"expected={trust.authority_set_version} got={declared_version}"
            )

    return verify_network_status(
        network_status,
        trusted_authorities=[
            {"key_id": item["authority_id"], "public_key": item["public_key"]} for item in trust.trusted_authorities
        ],
        threshold_policy={"k": trust.min_signers, "n": len(trust.trusted_authorities)},
        now=now,
    )


def fetch_verified_relays_from_directory(
    host: str,
    *,
    port: int = 9200,
    trust: ClientTrustConfig | None = None,
    allow_legacy_single_authority: bool = False,
    now: int | None = None,
) -> dict[str, dict[str, Any]]:
    if trust is None:
        if not allow_legacy_single_authority:
            raise ValueError("trust config is required for verified directory relay fetch")
        bundle = fetch_bundle_from_directory(host=host, port=port)
        descriptors = bundle.get("descriptors")
        if not isinstance(descriptors, list):
            raise ValueError("legacy bundle descriptors must be a list")
        return {
            descriptor["signed"]["relay"]["name"]: descriptor["signed"]["relay"]
            for descriptor in descriptors
            if isinstance(descriptor, dict) and isinstance(descriptor.get("signed"), dict)
            and isinstance(descriptor["signed"].get("relay"), dict)
            and isinstance(descriptor["signed"]["relay"].get("name"), str)
        }

    network_status = fetch_network_status_from_directory(host=host, port=port)
    return verified_relays_from_network_status(network_status, trust, now=now)



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
        error = response.get("error", "directory returned error")
        if isinstance(error, str) and "hidden service descriptor not found" in error:
            raise ValueError(NO_DESCRIPTOR_ERROR)
        raise ValueError(error)
    descriptor = response.get("descriptor")
    if not isinstance(descriptor, dict):
        raise ValueError(NO_DESCRIPTOR_ERROR)
    parsed = verify_hidden_service_descriptor_v2(descriptor)
    if parsed.service_name != service_name:
        raise ValueError("directory returned descriptor for unexpected service name")
    now = int(time.time())
    if parsed.valid_until <= now:
        raise ValueError(EXPIRED_DESCRIPTOR_ERROR)
    order_intro_points_for_phase1(descriptor, now=now)
    return descriptor


def publish_hidden_service_descriptor_to_directory(
    host: str,
    service_name: str,
    descriptor: dict[str, Any],
    *,
    port: int = 9200,
    expected_previous_revision: int | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    import socket

    parse_lettuce_name(service_name)
    request = parse_publish_hidden_service_descriptor_request(
        {
            "type": "PUBLISH_HS_DESCRIPTOR",
            "service_name": service_name,
            "descriptor": descriptor,
            "expected_previous_revision": expected_previous_revision,
            "idempotency_key": idempotency_key,
        }
    )
    with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
        send_msg(
            sock,
            {
                "type": request.type,
                "service_name": request.service_name,
                "descriptor": request.descriptor,
                "expected_previous_revision": request.expected_previous_revision,
                "idempotency_key": request.idempotency_key,
            },
        )
        response = recv_msg(sock)

    parsed = parse_publish_hidden_service_descriptor_response(response)
    if parsed.ok:
        return {
            "ok": True,
            "service_name": parsed.service_name,
            "accepted_revision": parsed.accepted_revision,
            "expected_previous_revision": parsed.expected_previous_revision,
            "idempotency_key": parsed.idempotency_key,
        }

    error_class = parsed.error_class or "directory_error"
    error_message = parsed.error or "directory returned error"
    if error_class == "revision_conflict":
        raise PublishDescriptorRevisionConflictError(error_message)
    if error_class == "expired_descriptor":
        raise PublishDescriptorExpiredError(error_message)
    if error_class == "invalid_signature":
        raise PublishDescriptorInvalidSignatureError(error_message)
    if error_class == "unauthorized":
        raise PublishDescriptorUnauthorizedError(error_message)
    raise PublishDescriptorError(error_message)


def order_intro_points_for_phase1(descriptor: dict[str, Any], *, now: int | None = None) -> list[dict[str, Any]]:
    if not isinstance(descriptor, dict):
        raise ValueError(NO_DESCRIPTOR_ERROR)

    now = int(time.time()) if now is None else int(now)
    parsed = verify_hidden_service_descriptor_v2(descriptor, now=now)
    if parsed.valid_until <= now:
        raise ValueError(EXPIRED_DESCRIPTOR_ERROR)

    signed = descriptor.get("signed")
    if not isinstance(signed, dict):
        raise ValueError(NO_DESCRIPTOR_ERROR)
    points = signed.get("introduction_points")
    if not isinstance(points, list) or not points:
        raise ValueError(NO_REACHABLE_INTRO_POINTS_ERROR)

    reachable: list[dict[str, Any]] = []
    for point in points:
        if not isinstance(point, dict):
            continue
        relay_addr = point.get("relay_addr")
        if not isinstance(relay_addr, dict):
            continue
        host = relay_addr.get("host")
        port = relay_addr.get("port")
        expires_at = point.get("expires_at")
        if not isinstance(host, str) or not host:
            continue
        if not isinstance(port, int) or port <= 0:
            continue
        if not isinstance(expires_at, int) or expires_at <= now:
            continue
        reachable.append(point)

    if not reachable:
        raise ValueError(NO_REACHABLE_INTRO_POINTS_ERROR)

    ranked = _score_and_order_relays(reachable, now=now)
    return ranked


def select_intro_point_for_phase1(descriptor: dict[str, Any], *, now: int | None = None) -> dict[str, Any]:
    return order_intro_points_for_phase1(descriptor, now=now)[0]


def _relay_key_from_point(point: dict[str, Any]) -> str:
    relay_addr = point.get("relay_addr", {})
    return f"{point.get('relay_name', '')}|{relay_addr.get('host', '')}|{relay_addr.get('port', 0)}"


def _score_and_order_relays(
    candidates: list[dict[str, Any]],
    *,
    now: int,
    top_n: int = _DEFAULT_TOP_N,
    rng_seed: int | None = None,
) -> list[dict[str, Any]]:
    rng = random.Random(rng_seed)
    scored: list[tuple[float, dict[str, Any]]] = []
    for point in candidates:
        score = _relay_health_score_from_point(point, now=now)
        scored.append((score, point))
    scored.sort(key=lambda item: item[0], reverse=True)
    if len(scored) <= 1:
        return [item[1] for item in scored]

    head = scored[: max(1, min(top_n, len(scored)))]
    tail = scored[max(1, min(top_n, len(scored))) :]
    picked_head = _weighted_shuffle(head, rng=rng)
    return [item[1] for item in picked_head + tail]


def _weighted_shuffle(weighted: list[tuple[float, dict[str, Any]]], *, rng: random.Random) -> list[tuple[float, dict[str, Any]]]:
    remaining = list(weighted)
    ordered: list[tuple[float, dict[str, Any]]] = []
    while remaining:
        weights = [max(_MIN_SELECTION_PROBABILITY, item[0]) for item in remaining]
        idx = rng.choices(range(len(remaining)), weights=weights, k=1)[0]
        ordered.append(remaining.pop(idx))
    return ordered


def _relay_health_score_from_point(point: dict[str, Any], *, now: int) -> float:
    telemetry = point.get("relay_health")
    if not isinstance(telemetry, dict):
        telemetry = {}
    if "health_score" in point and isinstance(point["health_score"], (int, float)):
        return max(_MIN_SELECTION_PROBABILITY, float(point["health_score"]))

    success_rate = float(telemetry.get("success_rate", 0.5))
    timeout_rate = float(telemetry.get("timeout_rate", 0.0))
    recent_latency_ms = float(telemetry.get("recent_latency_ms", 200.0))
    fail_streak = float(telemetry.get("recent_failures", 0.0))
    success_streak = float(telemetry.get("recent_successes", 0.0))
    measured_at = telemetry.get("measured_at")
    age_s = max(0.0, float(now - measured_at)) if isinstance(measured_at, int) else 0.0

    latency_factor = 1.0 / (1.0 + (recent_latency_ms / 400.0))
    freshness = 1.0 / (1.0 + age_s / 1800.0)
    failure_penalty = min(0.7, fail_streak * 0.2)
    recovery_bonus = min(0.25, success_streak * 0.05)
    score = (0.55 * success_rate) + (0.25 * latency_factor) + (0.20 * (1.0 - timeout_rate))
    score = score * freshness
    score = max(0.0, score - failure_penalty + recovery_bonus)
    return max(_MIN_SELECTION_PROBABILITY, min(1.0, score))



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

    circuit = CircuitSession(
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
    circuit.keepalive_scheduler = CircuitKeepaliveScheduler(circuit)
    circuit.keepalive_scheduler.start()
    return circuit



def _wrap_forward_cell(circuit: CircuitSession, cell: dict[str, Any]) -> dict[str, str]:
    payload_text = cell.get("payload", "")
    if not isinstance(payload_text, str):
        raise ValueError("cell payload must be a string")
    payload_raw = payload_text.encode("utf-8")
    if len(payload_raw) > CELL_PAYLOAD_BYTES:
        raise ValueError(f"stream payload exceeds cell budget ({len(payload_raw)}>{CELL_PAYLOAD_BYTES})")
    payload_b64, padding_b64 = encode_stream_cell_payload(payload_raw, padded_len=CELL_PAYLOAD_BYTES)
    wrapped_cell = dict(cell)
    wrapped_cell["padded_len"] = CELL_PAYLOAD_BYTES
    wrapped_cell["payload_b64"] = payload_b64
    wrapped_cell["padding_b64"] = padding_b64
    wrapped_cell["is_padding"] = cell.get("cell_type") == "PADDING"
    inner = encrypt_layer(circuit.hops[-1].forward_key, {"cmd": "EXIT_CELL", "cell": wrapped_cell})
    for hop in reversed(circuit.hops[:-1]):
        inner = encrypt_layer(hop.forward_key, {"cmd": "FORWARD_CELL", "inner": inner})
    return inner


def build_padding_cell(stream_id: int, seq: int = 0) -> dict[str, Any]:
    return {"stream_id": stream_id, "seq": seq, "cell_type": "PADDING", "payload": ""}


def build_keepalive_cell() -> dict[str, Any]:
    return {"stream_id": 0, "seq": 0, "cell_type": "PADDING", "payload": ""}



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
    payload_b64 = cell.get("payload_b64")
    if isinstance(payload_b64, str) and not cell.get("is_padding", False):
        try:
            payload_raw = b64d(payload_b64)
            cell["payload"] = payload_raw.decode("utf-8", errors="replace")
        except Exception as exc:
            raise ValueError("invalid reply payload_b64") from exc
    return cell


def _unwrap_reply_cells(circuit: CircuitSession, response: dict[str, Any]) -> list[dict[str, Any]]:
    if "replies" not in response:
        return [_unwrap_reply_cell(circuit, response)]
    replies = response.get("replies")
    if not isinstance(replies, list):
        raise ValueError("CELL_BATCH response replies must be a list")
    return [_unwrap_reply_cell(circuit, item) for item in replies]


def _send_batched_cells(
    circuit: CircuitSession,
    *,
    force_flush: bool = False,
    include_current: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    batcher = circuit.cell_batcher or CircuitCellBatcher()
    circuit.cell_batcher = batcher
    if include_current is not None:
        batcher.enqueue(include_current)
    if not batcher.should_flush(force=force_flush):
        return []

    replies: list[dict[str, Any]] = []
    while batcher.queue:
        cells = batcher.pop_batch()
        if len(cells) == 1:
            response = _send_guard_message(
                circuit.guard_host,
                circuit.guard_port,
                {"type": "CELL", "circuit_id": circuit.circuit_id, "layer": _wrap_forward_cell(circuit, cells[0])},
            )
        else:
            response = _send_guard_message(
                circuit.guard_host,
                circuit.guard_port,
                {
                    "type": "CELL_BATCH",
                    "circuit_id": circuit.circuit_id,
                    "layers": [_wrap_forward_cell(circuit, cell) for cell in cells],
                },
            )
        replies.extend(_unwrap_reply_cells(circuit, response))
    return replies



def open_stream(circuit: CircuitSession, stream_id: int, target: str = "") -> dict[str, Any]:
    cell = {"stream_id": stream_id, "seq": 1, "cell_type": "BEGIN", "payload": target}
    if circuit.keepalive_scheduler:
        circuit.keepalive_scheduler.note_real_traffic()
    reply_cells = _send_batched_cells(circuit, include_current=cell, force_flush=True)
    if not reply_cells:
        raise ValueError("missing BEGIN reply")
    reply_cell = reply_cells[-1]
    if reply_cell.get("cell_type") == "CONNECTED":
        circuit.stream_next_seq[stream_id] = 2
    return reply_cell



def send_stream_data(circuit: CircuitSession, stream_id: int, payload: str) -> dict[str, Any]:
    seq = circuit.stream_next_seq.get(stream_id)
    if seq is None:
        raise ValueError(f"stream {stream_id} is not open")
    cell = {"stream_id": stream_id, "seq": seq, "cell_type": "DATA", "payload": payload}
    if circuit.keepalive_scheduler:
        circuit.keepalive_scheduler.note_real_traffic()
    reply_cells = _send_batched_cells(circuit, include_current=cell, force_flush=True)
    if not reply_cells:
        raise ValueError("missing DATA reply")
    reply_cell = reply_cells[-1]
    if reply_cell.get("cell_type") != "ERROR":
        circuit.stream_next_seq[stream_id] = seq + 1
    return reply_cell



def end_stream(circuit: CircuitSession, stream_id: int, payload: str = "") -> dict[str, Any]:
    seq = circuit.stream_next_seq.get(stream_id)
    if seq is None:
        raise ValueError(f"stream {stream_id} is not open")
    cell = {"stream_id": stream_id, "seq": seq, "cell_type": "END", "payload": payload}
    if circuit.keepalive_scheduler:
        circuit.keepalive_scheduler.note_real_traffic()
    reply_cells = _send_batched_cells(circuit, include_current=cell, force_flush=True)
    if not reply_cells:
        raise ValueError("missing END reply")
    reply_cell = reply_cells[-1]
    if reply_cell.get("cell_type") in {"ENDED", "ERROR"}:
        circuit.stream_next_seq.pop(stream_id, None)
    return reply_cell



def destroy_circuit(circuit: CircuitSession) -> dict[str, Any]:
    if circuit.keepalive_scheduler:
        circuit.keepalive_scheduler.stop()
        circuit.keepalive_scheduler = None
    _send_batched_cells(circuit, force_flush=True)
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
    "ClientTrustConfig",
    "fetch_bundle_from_directory",
    "fetch_bundle_to_file",
    "fetch_network_status_from_directory",
    "load_client_trust_config",
    "verified_relays_from_network_status",
    "fetch_verified_relays_from_directory",
    "fetch_hidden_service_descriptor_from_directory",
    "order_intro_points_for_phase1",
    "select_intro_point_for_phase1",
    "build_circuit",
    "open_stream",
    "send_stream_data",
    "end_stream",
    "destroy_circuit",
    "demo_circuit_echo",
    "CircuitSession",
    "PaddingPolicyConfig",
    "build_padding_cell",
    "build_keepalive_cell",
    "KeepaliveConfig",
]
