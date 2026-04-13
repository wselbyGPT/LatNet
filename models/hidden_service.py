from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any

from util import b64d, sha256_hex

_LETTUCE_SUFFIX = ".lettuce"
_SERVICE_ID_LEN = 32
_HEX_ALPHABET = set("0123456789abcdef")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


__all__ = [
    "HiddenServiceDescriptor",
    "IntroductionPoint",
    "IntroductionPointAuth",
    "derive_lettuce_name",
    "derive_lettuce_name_from_b64",
    "is_valid_lettuce_name",
    "parse_hidden_service_descriptor",
    "parse_lettuce_name",
]


@dataclass(frozen=True)
class IntroductionPointAuth:
    key_type: str
    auth_key: str


@dataclass(frozen=True)
class IntroductionPoint:
    relay: str
    ntor_onion_key: str
    enc_key: str
    auth: IntroductionPointAuth | None = None


@dataclass(frozen=True)
class HiddenServiceDescriptor:
    version: int
    service_name: str
    service_public_key: str
    valid_after: int
    valid_until: int
    introduction_points: list[IntroductionPoint]


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


def _req_b64(src: dict[str, Any], field: str) -> str:
    value = _req_str(src, field)
    if len(value) % 4 != 0 or not _B64_RE.fullmatch(value):
        raise ValueError(f"missing or invalid field: {field}")

    try:
        base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # pragma: no cover - decoder specifics
        raise ValueError(f"missing or invalid field: {field}") from exc
    return value


def derive_lettuce_name(public_key: bytes) -> str:
    if not isinstance(public_key, bytes) or not public_key:
        raise ValueError("missing or invalid field: service_public_key")

    service_id = sha256_hex(public_key)[:_SERVICE_ID_LEN]
    return f"{service_id}{_LETTUCE_SUFFIX}"


def derive_lettuce_name_from_b64(public_key_b64: str) -> str:
    if not isinstance(public_key_b64, str) or not public_key_b64:
        raise ValueError("missing or invalid field: service_public_key")

    try:
        public_key = b64d(public_key_b64)
    except Exception as exc:  # pragma: no cover - b64 decoder specifics
        raise ValueError("missing or invalid field: service_public_key") from exc

    return derive_lettuce_name(public_key)


def is_valid_lettuce_name(name: str) -> bool:
    if not isinstance(name, str):
        return False
    if name != name.lower():
        return False
    if not name.endswith(_LETTUCE_SUFFIX):
        return False

    label = name[: -len(_LETTUCE_SUFFIX)]
    if len(label) != _SERVICE_ID_LEN:
        return False
    return all(char in _HEX_ALPHABET for char in label)


def parse_lettuce_name(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise ValueError("missing or invalid field: lettuce_name")
    if name != name.lower():
        raise ValueError("missing or invalid field: lettuce_name")
    if not name.endswith(_LETTUCE_SUFFIX):
        raise ValueError("missing or invalid field: lettuce_name")

    service_id = name[: -len(_LETTUCE_SUFFIX)]
    if len(service_id) != _SERVICE_ID_LEN:
        raise ValueError("missing or invalid field: lettuce_name")
    if not all(char in _HEX_ALPHABET for char in service_id):
        raise ValueError("missing or invalid field: lettuce_name")
    return service_id


def _parse_intro_auth(obj: Any) -> IntroductionPointAuth:
    src = _as_dict(obj, context="introduction point auth")
    return IntroductionPointAuth(key_type=_req_str(src, "key_type"), auth_key=_req_b64(src, "auth_key"))


def _parse_intro_point(obj: Any) -> IntroductionPoint:
    src = _as_dict(obj, context="introduction point")

    auth_value = src.get("auth")
    auth: IntroductionPointAuth | None = None
    if auth_value is not None:
        auth = _parse_intro_auth(auth_value)

    return IntroductionPoint(
        relay=_req_str(src, "relay"),
        ntor_onion_key=_req_b64(src, "ntor_onion_key"),
        enc_key=_req_b64(src, "enc_key"),
        auth=auth,
    )


def parse_hidden_service_descriptor(obj: Any) -> HiddenServiceDescriptor:
    src = _as_dict(obj, context="hidden service descriptor")

    version = _req_int(src, "version")
    if version != 1:
        raise ValueError("missing or invalid field: version")

    service_name = _req_str(src, "service_name")
    parse_lettuce_name(service_name)

    service_public_key = _req_b64(src, "service_public_key")
    if derive_lettuce_name_from_b64(service_public_key) != service_name:
        raise ValueError("missing or invalid field: service_name")

    valid_after = _req_int(src, "valid_after")
    valid_until = _req_int(src, "valid_until")
    if valid_after >= valid_until:
        raise ValueError("missing or invalid field: valid_until")

    points_raw = src.get("introduction_points")
    if not isinstance(points_raw, list) or not points_raw:
        raise ValueError("missing or invalid field: introduction_points")

    introduction_points = [_parse_intro_point(point) for point in points_raw]

    return HiddenServiceDescriptor(
        version=version,
        service_name=service_name,
        service_public_key=service_public_key,
        valid_after=valid_after,
        valid_until=valid_until,
        introduction_points=introduction_points,
    )
