from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

LayerCmd = Literal[
    "FORWARD_BUILD",
    "EXIT_READY",
    "FORWARD_CELL",
    "EXIT_CELL",
    "RELAY_BACK",
    "REPLY_CELL",
    "HS_INTRO",
    "HS_RENDEZVOUS",
    "HS_RENDEZVOUS_RELAY",
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


def _req_service_name(src: dict[str, Any]) -> str:
    return _req_str(src, "service_name")


def _req_rendezvous_cookie(src: dict[str, Any]) -> str:
    return _req_str(src, "rendezvous_cookie")


def _req_client_ephemeral(src: dict[str, Any]) -> str:
    return _req_str(src, "client_ephemeral")


def _req_service_ephemeral(src: dict[str, Any]) -> str:
    return _req_str(src, "service_ephemeral")


def _req_circuit_id(src: dict[str, Any]) -> str:
    return _req_str(src, "circuit_id")


@dataclass(frozen=True)
class NextHop:
    host: str
    port: int


@dataclass(frozen=True)
class RelayRoute:
    relay: str
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
class IntroduceEnvelope:
    type: Literal["INTRODUCE"]
    circuit_id: str
    service_name: str
    rendezvous_cookie: str
    client_ephemeral: str
    rendezvous_relay: RelayRoute


@dataclass(frozen=True)
class RendezvousJoinEnvelope:
    type: Literal["RENDEZVOUS_JOIN"]
    circuit_id: str
    service_name: str
    rendezvous_cookie: str
    service_ephemeral: str
    rendezvous_relay: RelayRoute


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
class ForwardCellLayer:
    cmd: Literal["FORWARD_CELL"]
    inner: dict[str, str]


@dataclass(frozen=True)
class StreamCell:
    stream_id: int
    seq: int
    cell_type: StreamCellType
    payload: str = ""


@dataclass(frozen=True)
class ExitCellLayer:
    cmd: Literal["EXIT_CELL"]
    cell: StreamCell


@dataclass(frozen=True)
class ReplyCellLayer:
    cmd: Literal["REPLY_CELL"]
    cell: StreamCell


@dataclass(frozen=True)
class HSIntroLayer:
    cmd: Literal["HS_INTRO"]
    circuit_id: str
    service_name: str
    rendezvous_cookie: str
    client_ephemeral: str
    rendezvous_relay: RelayRoute


@dataclass(frozen=True)
class HSRendezvousLayer:
    cmd: Literal["HS_RENDEZVOUS"]
    circuit_id: str
    service_name: str
    rendezvous_cookie: str
    service_ephemeral: str
    rendezvous_relay: RelayRoute


@dataclass(frozen=True)
class HSRendezvousRelayLayer:
    cmd: Literal["HS_RENDEZVOUS_RELAY"]
    inner: dict[str, str]


def _req_relay_route(src: dict[str, Any], field: str) -> RelayRoute:
    route_src = _as_dict(src.get(field), context=field)
    return RelayRoute(
        relay=_req_str(route_src, "relay"),
        host=_req_str(route_src, "host"),
        port=_req_int(route_src, "port"),
    )


def parse_build_envelope(obj: Any) -> BuildEnvelope:
    src = _as_dict(obj, context="BUILD envelope")
    if src.get("type") != "BUILD":
        raise ValueError("unknown message type")
    return BuildEnvelope(type="BUILD", circuit_id=_req_circuit_id(src), ct=_req_str(src, "ct"), layer=_as_dict(src.get("layer"), context="layer"))


def parse_cell_envelope(obj: Any) -> CellEnvelope:
    src = _as_dict(obj, context="CELL envelope")
    if src.get("type") != "CELL":
        raise ValueError("unknown message type")
    return CellEnvelope(type="CELL", circuit_id=_req_circuit_id(src), layer=_as_dict(src.get("layer"), context="layer"))


def parse_destroy_envelope(obj: Any) -> DestroyEnvelope:
    src = _as_dict(obj, context="DESTROY envelope")
    if src.get("type") != "DESTROY":
        raise ValueError("unknown message type")
    return DestroyEnvelope(type="DESTROY", circuit_id=_req_circuit_id(src))


def parse_introduce_envelope(obj: Any) -> IntroduceEnvelope:
    src = _as_dict(obj, context="INTRODUCE envelope")
    if src.get("type") != "INTRODUCE":
        raise ValueError("unknown message type")
    return IntroduceEnvelope(
        type="INTRODUCE",
        circuit_id=_req_circuit_id(src),
        service_name=_req_service_name(src),
        rendezvous_cookie=_req_rendezvous_cookie(src),
        client_ephemeral=_req_client_ephemeral(src),
        rendezvous_relay=_req_relay_route(src, "rendezvous_relay"),
    )


def parse_rendezvous_join_envelope(obj: Any) -> RendezvousJoinEnvelope:
    src = _as_dict(obj, context="RENDEZVOUS_JOIN envelope")
    if src.get("type") != "RENDEZVOUS_JOIN":
        raise ValueError("unknown message type")
    return RendezvousJoinEnvelope(
        type="RENDEZVOUS_JOIN",
        circuit_id=_req_circuit_id(src),
        service_name=_req_service_name(src),
        rendezvous_cookie=_req_rendezvous_cookie(src),
        service_ephemeral=_req_service_ephemeral(src),
        rendezvous_relay=_req_relay_route(src, "rendezvous_relay"),
    )


def parse_envelope(
    obj: Any,
) -> BuildEnvelope | CellEnvelope | DestroyEnvelope | IntroduceEnvelope | RendezvousJoinEnvelope:
    src = _as_dict(obj, context="envelope")
    msg_type = _req_str(src, "type")
    if msg_type == "BUILD":
        return parse_build_envelope(src)
    if msg_type == "CELL":
        return parse_cell_envelope(src)
    if msg_type == "DESTROY":
        return parse_destroy_envelope(src)
    if msg_type == "INTRODUCE":
        return parse_introduce_envelope(src)
    if msg_type == "RENDEZVOUS_JOIN":
        return parse_rendezvous_join_envelope(src)
    raise ValueError("unknown message type")


def parse_stream_cell(obj: Any) -> StreamCell:
    src = _as_dict(obj, context="stream cell")
    cell_type = _req_str(src, "cell_type")
    if cell_type not in {"BEGIN", "DATA", "END", "CONNECTED", "ENDED", "ERROR"}:
        raise ValueError("missing or invalid field: cell_type")
    payload = src.get("payload", "")
    if not isinstance(payload, str):
        raise ValueError("missing or invalid field: payload")
    return StreamCell(
        stream_id=_req_int(src, "stream_id"),
        seq=_req_int(src, "seq"),
        cell_type=cell_type,
        payload=payload,
    )


def parse_layer(
    obj: Any,
) -> (
    ForwardBuildLayer
    | ExitReadyLayer
    | ForwardCellLayer
    | ExitCellLayer
    | HSIntroLayer
    | HSRendezvousLayer
    | HSRendezvousRelayLayer
):
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
    if cmd == "FORWARD_CELL":
        return ForwardCellLayer(cmd="FORWARD_CELL", inner=_as_dict(src.get("inner"), context="inner"))
    if cmd == "EXIT_CELL":
        return ExitCellLayer(cmd="EXIT_CELL", cell=parse_stream_cell(src.get("cell")))
    if cmd == "HS_INTRO":
        return HSIntroLayer(
            cmd="HS_INTRO",
            circuit_id=_req_circuit_id(src),
            service_name=_req_service_name(src),
            rendezvous_cookie=_req_rendezvous_cookie(src),
            client_ephemeral=_req_client_ephemeral(src),
            rendezvous_relay=_req_relay_route(src, "rendezvous_relay"),
        )
    if cmd == "HS_RENDEZVOUS":
        return HSRendezvousLayer(
            cmd="HS_RENDEZVOUS",
            circuit_id=_req_circuit_id(src),
            service_name=_req_service_name(src),
            rendezvous_cookie=_req_rendezvous_cookie(src),
            service_ephemeral=_req_service_ephemeral(src),
            rendezvous_relay=_req_relay_route(src, "rendezvous_relay"),
        )
    if cmd == "HS_RENDEZVOUS_RELAY":
        return HSRendezvousRelayLayer(cmd="HS_RENDEZVOUS_RELAY", inner=_as_dict(src.get("inner"), context="inner"))
    raise ValueError(f"unknown layer cmd: {cmd}")


def parse_exit_cell_layer(obj: Any) -> ExitCellLayer:
    layer = parse_layer(obj)
    if not isinstance(layer, ExitCellLayer):
        raise ValueError(f"expected EXIT_CELL, got {layer.cmd}")
    return layer


def parse_get_bundle_request(obj: Any) -> None:
    src = _as_dict(obj, context="directory request")
    if src.get("type") != "GET_BUNDLE":
        raise ValueError("unknown message type")


def parse_get_hidden_service_descriptor_request(obj: Any) -> str:
    src = _as_dict(obj, context="directory request")
    if src.get("type") != "GET_HS_DESCRIPTOR":
        raise ValueError("unknown message type")
    return _req_str(src, "service_name")
