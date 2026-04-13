from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import APP_SALT
from .util import b64d, b64e, canonical_bytes


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def derive_aead_key(shared_secret: bytes, circuit_id: str, hop_name: str, direction: str) -> bytes:
    if direction not in {"forward", "reverse"}:
        raise ValueError(f"invalid direction: {direction}")
    prk = hkdf_extract(APP_SALT, shared_secret)
    info = f"circuit={circuit_id}|hop={hop_name}|purpose=aead|dir={direction}".encode("utf-8")
    return hkdf_expand(prk, info, 32)


def derive_hop_keys(shared_secret: bytes, circuit_id: str, hop_name: str) -> tuple[bytes, bytes]:
    forward_key = derive_aead_key(shared_secret, circuit_id, hop_name, "forward")
    reverse_key = derive_aead_key(shared_secret, circuit_id, hop_name, "reverse")
    return forward_key, reverse_key


def encrypt_layer(key: bytes, obj: dict[str, Any]) -> dict[str, str]:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    pt = canonical_bytes(obj)
    ct = aes.encrypt(nonce, pt, None)
    return {"nonce": b64e(nonce), "ct": b64e(ct)}


def decrypt_layer(key: bytes, wrapped: dict[str, str]) -> dict[str, Any]:
    aes = AESGCM(key)
    pt = aes.decrypt(b64d(wrapped["nonce"]), b64d(wrapped["ct"]), None)
    return json.loads(pt.decode("utf-8"))
