from __future__ import annotations

from util import b64d, sha256_hex

_LETTUCE_SUFFIX = ".lettuce"
_SERVICE_ID_LEN = 32
_HEX_ALPHABET = set("0123456789abcdef")


__all__ = [
    "derive_lettuce_name",
    "derive_lettuce_name_from_b64",
    "is_valid_lettuce_name",
    "parse_lettuce_name",
]


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
