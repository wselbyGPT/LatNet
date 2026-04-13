from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..hidden_service_keys import (
    HS_SIGALG,
    derive_service_name_from_master_public_b64,
    verify_descriptor_signing_certificate,
)
from ..util import b64d, canonical_bytes


__all__ = [
    "HSDescriptorV2",
    "HSIntroductionPointV2",
    "parse_hidden_service_descriptor_v2",
    "verify_hidden_service_descriptor_v2",
]


@dataclass(frozen=True)
class HSIntroductionPointV2:
    relay_name: str
    relay_host: str
    relay_port: int
    intro_auth_pub: str
    intro_key_id: str
    expires_at: int


@dataclass(frozen=True)
class HSDescriptorV2:
    version: int
    sigalg: str
    signature: str
    service_name: str
    service_master_public_key: str
    descriptor_signing_public_key: str
    descriptor_signing_certificate: dict[str, Any]
    valid_after: int
    valid_until: int
    revision: int
    period: int
    introduction_points: list[HSIntroductionPointV2]


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


def _parse_intro_point(obj: Any) -> HSIntroductionPointV2:
    src = _as_dict(obj, context="introduction point")
    relay_addr = _as_dict(src.get("relay_addr"), context="relay_addr")
    return HSIntroductionPointV2(
        relay_name=_req_str(src, "relay_name"),
        relay_host=_req_str(relay_addr, "host"),
        relay_port=_req_int(relay_addr, "port"),
        intro_auth_pub=_req_str(src, "intro_auth_pub"),
        intro_key_id=_req_str(src, "intro_key_id"),
        expires_at=_req_int(src, "expires_at"),
    )


def parse_hidden_service_descriptor_v2(obj: Any) -> HSDescriptorV2:
    src = _as_dict(obj, context="hidden service descriptor v2")

    version = _req_int(src, "version")
    if version != 2:
        raise ValueError("missing or invalid field: version")

    sigalg = _req_str(src, "sigalg")
    if sigalg != HS_SIGALG:
        raise ValueError("missing or invalid field: sigalg")

    signature = _req_str(src, "signature")
    signed = _as_dict(src.get("signed"), context="signed")

    service_name = _req_str(signed, "service_name")
    service_master_public_key = _req_str(signed, "service_master_public_key")
    expected_name = derive_service_name_from_master_public_b64(service_master_public_key)
    if service_name != expected_name:
        raise ValueError("missing or invalid field: service_name")

    descriptor_signing_public_key = _req_str(signed, "descriptor_signing_public_key")
    descriptor_signing_certificate = _as_dict(signed.get("descriptor_signing_certificate"), context="descriptor_signing_certificate")

    valid_after = _req_int(signed, "valid_after")
    valid_until = _req_int(signed, "valid_until")
    if valid_after >= valid_until:
        raise ValueError("missing or invalid field: valid_until")

    revision = _req_int(signed, "revision")
    if revision < 0:
        raise ValueError("missing or invalid field: revision")

    period = _req_int(signed, "period")

    points_raw = signed.get("introduction_points")
    if not isinstance(points_raw, list) or not points_raw:
        raise ValueError("missing or invalid field: introduction_points")
    introduction_points = [_parse_intro_point(point) for point in points_raw]

    return HSDescriptorV2(
        version=version,
        sigalg=sigalg,
        signature=signature,
        service_name=service_name,
        service_master_public_key=service_master_public_key,
        descriptor_signing_public_key=descriptor_signing_public_key,
        descriptor_signing_certificate=descriptor_signing_certificate,
        valid_after=valid_after,
        valid_until=valid_until,
        revision=revision,
        period=period,
        introduction_points=introduction_points,
    )


def verify_hidden_service_descriptor_v2(obj: Any, now: int | None = None) -> HSDescriptorV2:
    parsed = parse_hidden_service_descriptor_v2(obj)
    src = _as_dict(obj, context="hidden service descriptor v2")
    signed = _as_dict(src.get("signed"), context="signed")

    cert_signed = verify_descriptor_signing_certificate(parsed.descriptor_signing_certificate, now=now)
    if cert_signed["service_name"] != parsed.service_name:
        raise ValueError("missing or invalid field: service_name")
    if cert_signed["descriptor_signing_public_key"] != parsed.descriptor_signing_public_key:
        raise ValueError("missing or invalid field: descriptor_signing_public_key")

    public_key = Ed25519PublicKey.from_public_bytes(b64d(parsed.descriptor_signing_public_key))
    public_key.verify(b64d(parsed.signature), canonical_bytes(signed))

    if parsed.valid_until > cert_signed["valid_until"]:
        raise ValueError("descriptor validity exceeds signing certificate validity")

    return parsed
