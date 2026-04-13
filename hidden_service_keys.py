from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .util import atomic_write_json, b64d, b64e, canonical_bytes, load_json, sha256_hex

HS_SIGALG = "ed25519"
HS_CERT_VERSION = 1


__all__ = [
    "HS_SIGALG",
    "HS_CERT_VERSION",
    "derive_service_name_from_master_public",
    "derive_service_name_from_master_public_b64",
    "generate_service_master",
    "load_service_master",
    "load_service_public",
    "generate_descriptor_signing_key",
    "build_descriptor_signing_certificate",
    "verify_descriptor_signing_certificate",
]


def _raw_private_key_b64(private_key: Ed25519PrivateKey) -> str:
    return b64e(private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))


def _raw_public_key_b64(public_key: Ed25519PublicKey) -> str:
    return b64e(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def derive_service_name_from_master_public(master_public_key: bytes) -> str:
    if not isinstance(master_public_key, bytes) or not master_public_key:
        raise ValueError("missing or invalid field: service_master_public_key")
    return f"{sha256_hex(master_public_key)[:32]}.lettuce"


def derive_service_name_from_master_public_b64(master_public_key_b64: str) -> str:
    if not isinstance(master_public_key_b64, str) or not master_public_key_b64:
        raise ValueError("missing or invalid field: service_master_public_key")
    try:
        raw = b64d(master_public_key_b64)
    except Exception as exc:  # pragma: no cover
        raise ValueError("missing or invalid field: service_master_public_key") from exc
    return derive_service_name_from_master_public(raw)


def generate_service_master(name: str, out_path: str | Path) -> dict[str, Any]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_b64 = _raw_public_key_b64(public_key)

    service = {
        "version": 1,
        "name": name,
        "sigalg": HS_SIGALG,
        "service_master_public_key": public_key_b64,
        "service_master_private_key": _raw_private_key_b64(private_key),
    }
    service_name = derive_service_name_from_master_public_b64(public_key_b64)
    service["service_name"] = service_name
    service["service_key_id"] = sha256_hex(b64d(public_key_b64))
    atomic_write_json(out_path, service)
    return service


def load_service_master(path: str | Path) -> dict[str, Any]:
    service = load_json(path)
    if "service_master_public_key" not in service or "service_master_private_key" not in service:
        raise ValueError("service master file missing key material")
    return service


def load_service_public(path: str | Path) -> dict[str, Any]:
    service = load_service_master(path)
    return {
        "version": service.get("version", 1),
        "name": service.get("name", "hidden-service"),
        "sigalg": service.get("sigalg", HS_SIGALG),
        "service_name": service["service_name"],
        "service_master_public_key": service["service_master_public_key"],
        "service_key_id": service.get("service_key_id") or sha256_hex(b64d(service["service_master_public_key"])),
    }


def generate_descriptor_signing_key() -> dict[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return {
        "sigalg": HS_SIGALG,
        "descriptor_signing_public_key": _raw_public_key_b64(public_key),
        "descriptor_signing_private_key": _raw_private_key_b64(private_key),
    }


def build_descriptor_signing_certificate(
    service_master: dict[str, Any],
    descriptor_signing_public_key: str,
    valid_for: int,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(valid_for, int) or valid_for <= 0:
        raise ValueError("missing or invalid field: valid_for")

    now = int(time.time()) if now is None else now
    valid_after = now
    valid_until = now + valid_for

    signed = {
        "version": HS_CERT_VERSION,
        "sigalg": HS_SIGALG,
        "service_name": service_master["service_name"],
        "service_master_public_key": service_master["service_master_public_key"],
        "descriptor_signing_public_key": descriptor_signing_public_key,
        "valid_after": valid_after,
        "valid_until": valid_until,
    }

    private_key = Ed25519PrivateKey.from_private_bytes(b64d(service_master["service_master_private_key"]))
    signature = private_key.sign(canonical_bytes(signed))

    return {
        "version": HS_CERT_VERSION,
        "signed": signed,
        "signature": b64e(signature),
    }


def verify_descriptor_signing_certificate(cert: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    if cert.get("version") != HS_CERT_VERSION:
        raise ValueError("missing or invalid field: version")

    signed = cert.get("signed")
    if not isinstance(signed, dict):
        raise ValueError("missing or invalid field: signed")

    if signed.get("sigalg") != HS_SIGALG:
        raise ValueError("missing or invalid field: sigalg")

    valid_after = signed.get("valid_after")
    valid_until = signed.get("valid_until")
    if not isinstance(valid_after, int):
        raise ValueError("missing or invalid field: valid_after")
    if not isinstance(valid_until, int) or valid_after >= valid_until:
        raise ValueError("missing or invalid field: valid_until")

    expected_service_name = derive_service_name_from_master_public_b64(signed["service_master_public_key"])
    if signed.get("service_name") != expected_service_name:
        raise ValueError("missing or invalid field: service_name")

    public_key = Ed25519PublicKey.from_public_bytes(b64d(signed["service_master_public_key"]))
    public_key.verify(b64d(cert["signature"]), canonical_bytes(signed))

    now = int(time.time()) if now is None else now
    if now < valid_after:
        raise ValueError(f"descriptor signing certificate not valid yet: valid_after={valid_after}")
    if now > valid_until:
        raise ValueError(f"descriptor signing certificate expired: valid_until={valid_until}")

    return signed
