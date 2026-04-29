from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from ..constants import CELL_PAYLOAD_BYTES
from ..util import b64d, b64e

TRUST_BUNDLE_PROTOCOL_VERSION = 1
TRUST_STATUS_PROTOCOL_VERSION = 2

LayerCmd = Literal[
    "FORWARD_BUILD",
    "EXIT_READY",
    "INTRO_READY",
    "RENDEZVOUS_READY",
    "FORWARD_CELL",
    "EXIT_CELL",
    "RELAY_BACK",
    "REPLY_CELL",
]
StreamCellType = Literal["BEGIN", "DATA", "END", "CONNECTED", "ENDED", "ERROR"]


def _as_dict(obj: Any, *, context: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError(f"{context} must be an object")
    return obj


def _req_str(src: dict[str, Any], field: str) -> str:
    value = src.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing or invalid field: {field}")
    return value


def _req_int(src: dict[str, Any], field: str) -> int:
    value = src.get(field)
    if not isinstance(value, int):
        raise ValueError(f"missing or invalid field: {field}")
    return value


def _opt_int(src: dict[str, Any], field: str) -> int | None:
    value = src.get(field)
    if value is None:
        return None
    if not isinstance(value, int):
        raise ValueError(f"missing or invalid field: {field}")
    return value


def _opt_str(src: dict[str, Any], field: str) -> str | None:
    value = src.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing or invalid field: {field}")
    return value


@dataclass(frozen=True)
class NextHop:
    host: str
    port: int


@dataclass(frozen=True)
class BuildEnvelope:
    type: Literal["BUILD"]
    circuit_id: str
    ct: str
    layer: dict[str, str]


@dataclass(frozen=True)
class CellEnvelope:
    type: Literal["CELL"]
    circuit_id: str
    layer: dict[str, str]


@dataclass(frozen=True)
class DestroyEnvelope:
    type: Literal["DESTROY"]
    circuit_id: str


@dataclass(frozen=True)
class ForwardBuildLayer:
    cmd: Literal["FORWARD_BUILD"]
    next: NextHop
    next_ct: str
    inner: dict[str, str]


@dataclass(frozen=True)
class ExitReadyLayer:
    cmd: Literal["EXIT_READY"]


@dataclass(frozen=True)
class IntroReadyLayer:
    cmd: Literal["INTRO_READY"]


@dataclass(frozen=True)
class RendezvousReadyLayer:
    cmd: Literal["RENDEZVOUS_READY"]


@dataclass(frozen=True)
class ForwardCellLayer:
    cmd: Literal["FORWARD_CELL"]
    inner: dict[str, str]


@dataclass(frozen=True)
class StreamCell:
    stream_id: int
    seq: int
    cell_type: StreamCellType
    payload: str = ""
    padded_len: int = CELL_PAYLOAD_BYTES
    payload_b64: str = ""
    is_padding: bool = False


@dataclass(frozen=True)
class ExitCellLayer:
    cmd: Literal["EXIT_CELL"]
    cell: StreamCell


def encode_stream_cell_payload(payload: bytes, *, padded_len: int = CELL_PAYLOAD_BYTES) -> tuple[str, str]:
    if len(payload) > padded_len:
        raise ValueError(f"payload too large: {len(payload)} > {padded_len}")
    payload_b64 = b64e(payload)
    padding = b"\x00" * (padded_len - len(payload))
    return payload_b64, b64e(padding)


def decode_stream_cell_payload(payload_b64: str, is_padding: bool = False) -> bytes:
    if is_padding:
        return b""
    return b64d(payload_b64)


@dataclass(frozen=True)
class ReplyCellLayer:
    cmd: Literal["REPLY_CELL"]
    cell: StreamCell


@dataclass(frozen=True)
class PublishHSDescriptorRequest:
    type: Literal["PUBLISH_HS_DESCRIPTOR"]
    service_name: str
    descriptor: dict[str, Any]
    expected_previous_revision: int | None = None
    idempotency_key: str | None = None


@dataclass(frozen=True)
class PublishHSDescriptorResponse:
    ok: bool
    service_name: str | None = None
    accepted_revision: int | None = None
    expected_previous_revision: int | None = None
    idempotency_key: str | None = None
    error: str | None = None
    error_class: str | None = None


@dataclass(frozen=True)
class GetBundleRequest:
    type: Literal["GET_BUNDLE"]
    protocol_version: int = TRUST_BUNDLE_PROTOCOL_VERSION


@dataclass(frozen=True)
class GetNetworkStatusRequest:
    type: Literal["GET_NETWORK_STATUS"]
    protocol_version: int = TRUST_STATUS_PROTOCOL_VERSION


@dataclass(frozen=True)
class GetNetworkStatusResponse:
    ok: bool
    network_status: dict[str, Any] | None = None
    protocol_version: int = TRUST_STATUS_PROTOCOL_VERSION
    status_version: int | None = None
    server_time: int | None = None
    error: str | None = None
    error_class: str | None = None


def parse_build_envelope(obj: Any) -> BuildEnvelope:
    src = _as_dict(obj, context="BUILD envelope")
    if src.get("type") != "BUILD":
        raise ValueError("unknown message type")
    return BuildEnvelope(
        type="BUILD",
        circuit_id=_req_str(src, "circuit_id"),
        ct=_req_str(src, "ct"),
        layer=_as_dict(src.get("layer"), context="layer"),
    )


def parse_cell_envelope(obj: Any) -> CellEnvelope:
    src = _as_dict(obj, context="CELL envelope")
    if src.get("type") != "CELL":
        raise ValueError("unknown message type")
    return CellEnvelope(type="CELL", circuit_id=_req_str(src, "circuit_id"), layer=_as_dict(src.get("layer"), context="layer"))


def parse_destroy_envelope(obj: Any) -> DestroyEnvelope:
    src = _as_dict(obj, context="DESTROY envelope")
    if src.get("type") != "DESTROY":
        raise ValueError("unknown message type")
    return DestroyEnvelope(type="DESTROY", circuit_id=_req_str(src, "circuit_id"))


def parse_stream_cell(obj: Any) -> StreamCell:
    src = _as_dict(obj, context="stream cell")
    cell_type = _req_str(src, "cell_type")
    if cell_type not in {"BEGIN", "DATA", "END", "CONNECTED", "ENDED", "ERROR"}:
        raise ValueError("missing or invalid field: cell_type")
    payload = src.get("payload", "")
    if not isinstance(payload, str):
        raise ValueError("missing or invalid field: payload")
    padded_len = src.get("padded_len", CELL_PAYLOAD_BYTES)
    if not isinstance(padded_len, int) or padded_len <= 0:
        raise ValueError("missing or invalid field: padded_len")
    payload_b64 = src.get("payload_b64")
    if payload_b64 is None:
        payload_b64 = b64e(payload.encode("utf-8"))
    if not isinstance(payload_b64, str):
        raise ValueError("missing or invalid field: payload_b64")
    is_padding = src.get("is_padding", False)
    if not isinstance(is_padding, bool):
        raise ValueError("missing or invalid field: is_padding")
    decoded = b64d(payload_b64)
    if len(decoded) > padded_len:
        raise ValueError("payload exceeds padded_len")
    if padded_len != CELL_PAYLOAD_BYTES:
        raise ValueError("unsupported padded_len")
    if payload == "" and not is_padding:
        payload = decoded.decode("utf-8", errors="replace")
    return StreamCell(
        stream_id=_req_int(src, "stream_id"),
        seq=_req_int(src, "seq"),
        cell_type=cell_type,
        payload=payload,
        padded_len=padded_len,
        payload_b64=payload_b64,
        is_padding=is_padding,
    )


def parse_layer(
    obj: Any,
) -> ForwardBuildLayer | ExitReadyLayer | IntroReadyLayer | RendezvousReadyLayer | ForwardCellLayer | ExitCellLayer:
    src = _as_dict(obj, context="layer")
    cmd = _req_str(src, "cmd")
    if cmd == "FORWARD_BUILD":
        next_src = _as_dict(src.get("next"), context="next")
        return ForwardBuildLayer(
            cmd="FORWARD_BUILD",
            next=NextHop(host=_req_str(next_src, "host"), port=_req_int(next_src, "port")),
            next_ct=_req_str(src, "next_ct"),
            inner=_as_dict(src.get("inner"), context="inner"),
        )
    if cmd == "EXIT_READY":
        return ExitReadyLayer(cmd="EXIT_READY")
    if cmd == "INTRO_READY":
        return IntroReadyLayer(cmd="INTRO_READY")
    if cmd == "RENDEZVOUS_READY":
        return RendezvousReadyLayer(cmd="RENDEZVOUS_READY")
    if cmd == "FORWARD_CELL":
        return ForwardCellLayer(cmd="FORWARD_CELL", inner=_as_dict(src.get("inner"), context="inner"))
    if cmd == "EXIT_CELL":
        return ExitCellLayer(cmd="EXIT_CELL", cell=parse_stream_cell(src.get("cell")))
    raise ValueError(f"unknown layer cmd: {cmd}")


def parse_exit_cell_layer(obj: Any) -> ExitCellLayer:
    layer = parse_layer(obj)
    if not isinstance(layer, ExitCellLayer):
        raise ValueError(f"expected EXIT_CELL, got {layer.cmd}")
    return layer


def parse_get_bundle_request(obj: Any) -> GetBundleRequest:
    src = _as_dict(obj, context="directory request")
    if src.get("type") != "GET_BUNDLE":
        raise ValueError("unknown message type")
    protocol_version = _opt_int(src, "protocol_version")
    if protocol_version is None:
        protocol_version = TRUST_BUNDLE_PROTOCOL_VERSION
    if protocol_version != TRUST_BUNDLE_PROTOCOL_VERSION:
        raise ValueError("unsupported GET_BUNDLE protocol_version")
    return GetBundleRequest(type="GET_BUNDLE", protocol_version=protocol_version)


def parse_get_network_status_request(obj: Any) -> GetNetworkStatusRequest:
    src = _as_dict(obj, context="directory request")
    if src.get("type") != "GET_NETWORK_STATUS":
        raise ValueError("unknown message type")
    protocol_version = _opt_int(src, "protocol_version")
    if protocol_version is None:
        protocol_version = TRUST_STATUS_PROTOCOL_VERSION
    if protocol_version != TRUST_STATUS_PROTOCOL_VERSION:
        raise ValueError("unsupported GET_NETWORK_STATUS protocol_version")
    return GetNetworkStatusRequest(type="GET_NETWORK_STATUS", protocol_version=protocol_version)


def parse_get_network_status_response(obj: Any) -> GetNetworkStatusResponse:
    src = _as_dict(obj, context="directory response")
    ok = src.get("ok")
    if not isinstance(ok, bool):
        raise ValueError("missing or invalid field: ok")
    protocol_version = _opt_int(src, "protocol_version")
    if protocol_version is None:
        protocol_version = TRUST_STATUS_PROTOCOL_VERSION
    if protocol_version != TRUST_STATUS_PROTOCOL_VERSION:
        raise ValueError("unsupported GET_NETWORK_STATUS protocol_version")
    status_version = _opt_int(src, "status_version")
    server_time = _opt_int(src, "server_time")
    if ok:
        return GetNetworkStatusResponse(
            ok=True,
            network_status=_as_dict(src.get("network_status"), context="network_status"),
            protocol_version=protocol_version,
            status_version=status_version,
            server_time=server_time,
        )
    return GetNetworkStatusResponse(
        ok=False,
        error=_req_str(src, "error"),
        error_class=_req_str(src, "error_class"),
        protocol_version=protocol_version,
        status_version=status_version,
        server_time=server_time,
    )


def parse_get_hidden_service_descriptor_request(obj: Any) -> str:
    src = _as_dict(obj, context="directory request")
    if src.get("type") != "GET_HS_DESCRIPTOR":
        raise ValueError("unknown message type")
    return _req_str(src, "service_name")


def parse_publish_hidden_service_descriptor_request(obj: Any) -> PublishHSDescriptorRequest:
    src = _as_dict(obj, context="directory request")
    if src.get("type") != "PUBLISH_HS_DESCRIPTOR":
        raise ValueError("unknown message type")
    expected_previous_revision = _opt_int(src, "expected_previous_revision")
    if expected_previous_revision is not None and expected_previous_revision < 0:
        raise ValueError("missing or invalid field: expected_previous_revision")
    return PublishHSDescriptorRequest(
        type="PUBLISH_HS_DESCRIPTOR",
        service_name=_req_str(src, "service_name"),
        descriptor=_as_dict(src.get("descriptor"), context="descriptor"),
        expected_previous_revision=expected_previous_revision,
        idempotency_key=_opt_str(src, "idempotency_key"),
    )


def parse_publish_hidden_service_descriptor_response(obj: Any) -> PublishHSDescriptorResponse:
    src = _as_dict(obj, context="directory response")
    ok = src.get("ok")
    if not isinstance(ok, bool):
        raise ValueError("missing or invalid field: ok")
    if ok:
        return PublishHSDescriptorResponse(
            ok=True,
            service_name=_req_str(src, "service_name"),
            accepted_revision=_req_int(src, "accepted_revision"),
            expected_previous_revision=_opt_int(src, "expected_previous_revision"),
            idempotency_key=_opt_str(src, "idempotency_key"),
        )
    return PublishHSDescriptorResponse(
        ok=False,
        error=_req_str(src, "error"),
        error_class=_req_str(src, "error_class"),
        service_name=_opt_str(src, "service_name"),
        expected_previous_revision=_opt_int(src, "expected_previous_revision"),
        idempotency_key=_opt_str(src, "idempotency_key"),
    )
