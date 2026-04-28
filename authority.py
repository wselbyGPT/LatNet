from __future__ import annotations

import time
import warnings
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .constants import AUTH_SIGALG
from .util import atomic_write_json, b64d, b64e, canonical_bytes, load_json, sha256_hex
from . import wire


def authority_key_id_from_public(public_key_b64: str) -> str:
    return sha256_hex(b64d(public_key_b64))


def load_authority(path: str | Path) -> dict[str, Any]:
    return load_json(path)


def load_authority_public(path: str | Path) -> dict[str, Any]:
    auth = load_authority(path)
    if "public_key" not in auth:
        raise ValueError("authority file missing public_key")
    return {
        "version": auth.get("version", 1),
        "name": auth.get("name", "lab-authority"),
        "sigalg": auth.get("sigalg", AUTH_SIGALG),
        "public_key": auth["public_key"],
        "key_id": auth.get("key_id") or authority_key_id_from_public(auth["public_key"]),
    }


def init_authority_file(name: str, out_path: str | Path) -> dict[str, Any]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    authority = {
        "version": 1,
        "name": name,
        "sigalg": AUTH_SIGALG,
        "public_key": b64e(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "private_key": b64e(private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
    }
    authority["key_id"] = authority_key_id_from_public(authority["public_key"])
    atomic_write_json(out_path, authority)
    return authority


def export_authority_pub_file(authority_path: str | Path, out_path: str | Path) -> dict[str, Any]:
    authority_pub = load_authority_public(authority_path)
    atomic_write_json(out_path, authority_pub)
    return authority_pub


def signable_descriptor_payload(relay_doc: dict[str, Any], valid_after: int, valid_until: int) -> dict[str, Any]:
    relay_section = {
        "name": relay_doc["name"],
        "host": relay_doc["host"],
        "port": relay_doc["port"],
        "kemalg": relay_doc["kemalg"],
        "public_key": relay_doc["public_key"],
    }
    descriptor_id = sha256_hex(canonical_bytes(relay_section))
    return {
        "version": 1,
        "descriptor_id": descriptor_id,
        "valid_after": valid_after,
        "valid_until": valid_until,
        "relay": relay_section,
    }


def sign_relay_file(
    relay_path: str | Path,
    authority_path: str | Path,
    valid_for: int,
    out_path: str | Path,
) -> dict[str, Any]:
    relay_doc = load_json(relay_path)
    authority = load_authority(authority_path)

    if authority.get("sigalg") != AUTH_SIGALG:
        raise ValueError(f"unsupported authority sigalg {authority.get('sigalg')}")

    valid_after = int(time.time())
    valid_until = valid_after + valid_for
    signed = signable_descriptor_payload(relay_doc, valid_after, valid_until)

    private_key = Ed25519PrivateKey.from_private_bytes(b64d(authority["private_key"]))
    signature = private_key.sign(canonical_bytes(signed))

    descriptor = {
        "version": 1,
        "sigalg": AUTH_SIGALG,
        "authority_name": authority.get("name", "lab-authority"),
        "authority_key_id": authority.get("key_id") or authority_key_id_from_public(authority["public_key"]),
        "signed": signed,
        "signature": b64e(signature),
    }
    atomic_write_json(out_path, descriptor)
    return descriptor


def descriptor_relay_view(descriptor: dict[str, Any]) -> dict[str, Any]:
    return descriptor["signed"]["relay"]


def verify_descriptor(descriptor: dict[str, Any], authority_pub: dict[str, Any], now: int | None = None) -> None:
    now = now or int(time.time())

    if descriptor.get("sigalg") != AUTH_SIGALG:
        raise ValueError(f"unsupported descriptor sigalg {descriptor.get('sigalg')}")
    if descriptor.get("authority_key_id") != authority_pub["key_id"]:
        raise ValueError("descriptor authority key id does not match trusted authority")

    signed = descriptor["signed"]
    valid_after = signed["valid_after"]
    valid_until = signed["valid_until"]

    if now < valid_after:
        raise ValueError(f"descriptor for {signed['relay']['name']} is not valid yet: valid_after={valid_after}")
    if now > valid_until:
        raise ValueError(f"descriptor for {signed['relay']['name']} expired: valid_until={valid_until}")

    public_key = Ed25519PublicKey.from_public_bytes(b64d(authority_pub["public_key"]))
    public_key.verify(b64d(descriptor["signature"]), canonical_bytes(signed))


def verify_bundle(
    bundle: dict[str, Any],
    authority_pub: dict[str, Any],
    now: int | None = None,
) -> dict[str, dict[str, Any]]:
    warnings.warn(
        "verify_bundle is deprecated; use verify_network_status instead",
        DeprecationWarning,
        stacklevel=2,
    )
    return _verify_legacy_bundle(bundle, authority_pub, now=now)


def canonical_snapshot_hash(snapshot: dict[str, Any]) -> str:
    return sha256_hex(canonical_bytes(snapshot))


def make_authority_vote(authority: dict[str, Any], snapshot_hash: str) -> dict[str, Any]:
    if authority.get("sigalg") != AUTH_SIGALG:
        raise ValueError(f"unsupported authority sigalg {authority.get('sigalg')}")

    payload = {"snapshot_hash": snapshot_hash}
    private_key = Ed25519PrivateKey.from_private_bytes(b64d(authority["private_key"]))
    signature = private_key.sign(canonical_bytes(payload))
    authority_id = authority.get("key_id") or authority_key_id_from_public(authority["public_key"])
    return {
        "authority_id": authority_id,
        "sigalg": AUTH_SIGALG,
        "signature": b64e(signature),
    }


def verify_threshold_votes(
    status_doc: dict[str, Any],
    trusted_authorities: list[dict[str, Any]],
    threshold_policy: dict[str, int],
) -> None:
    trusted_by_id = {
        (item.get("key_id") or authority_key_id_from_public(item["public_key"])): item for item in trusted_authorities
    }
    authority_set = status_doc.get("authority_set")
    if not isinstance(authority_set, list):
        raise ValueError("network status missing authority_set")
    declared_by_id: dict[str, dict[str, Any]] = {}
    for item in authority_set:
        if not isinstance(item, dict):
            raise ValueError("network status authority metadata must be objects")
        authority_id = item.get("authority_id")
        public_key = item.get("public_key")
        if not isinstance(authority_id, str) or not authority_id:
            raise ValueError("network status authority metadata missing authority_id")
        if not isinstance(public_key, str) or not public_key:
            raise ValueError("network status authority metadata missing public_key")
        declared_by_id[authority_id] = {"public_key": public_key}

    k = threshold_policy.get("k")
    n = threshold_policy.get("n")
    if not isinstance(k, int) or not isinstance(n, int) or k <= 0 or n <= 0 or k > n:
        raise ValueError("invalid threshold policy")
    if n != len(authority_set):
        raise ValueError("threshold policy n does not match declared authority set size")

    payload = {"snapshot_hash": status_doc["snapshot_hash"]}
    votes = status_doc.get("votes")
    if not isinstance(votes, list):
        raise ValueError("network status missing votes")

    seen: set[str] = set()
    valid_signers = 0
    for vote in votes:
        if not isinstance(vote, dict):
            raise ValueError("network status vote entries must be objects")
        authority_id = vote.get("authority_id")
        if not isinstance(authority_id, str) or not authority_id:
            raise ValueError("network status vote missing authority_id")
        if authority_id in seen:
            raise ValueError(f"duplicate authority vote for {authority_id}")
        seen.add(authority_id)
        if authority_id not in trusted_by_id:
            raise ValueError(f"vote signer {authority_id} not in trusted authority set")
        if authority_id not in declared_by_id:
            raise ValueError(f"vote signer {authority_id} not in declared authority set")
        if vote.get("sigalg") != AUTH_SIGALG:
            raise ValueError(f"unsupported authority sigalg {vote.get('sigalg')}")

        declared_public_key = declared_by_id[authority_id]["public_key"]
        trusted_public_key = trusted_by_id[authority_id]["public_key"]
        if declared_public_key != trusted_public_key:
            raise ValueError(f"declared authority key mismatch for {authority_id}")

        public_key = Ed25519PublicKey.from_public_bytes(b64d(declared_public_key))
        public_key.verify(b64d(vote["signature"]), canonical_bytes(payload))
        valid_signers += 1

    if valid_signers < k:
        raise ValueError(f"insufficient authority votes: have={valid_signers} need={k}")


def verify_network_status(
    status_doc: dict[str, Any],
    trusted_authorities: list[dict[str, Any]],
    threshold_policy: dict[str, int],
    now: int | None = None,
) -> dict[str, dict[str, Any]]:
    now = now or int(time.time())

    if status_doc.get("version") != 1:
        raise ValueError(f"unsupported network status version {status_doc.get('version')}")

    validity = status_doc.get("validity")
    if not isinstance(validity, dict):
        raise ValueError("network status missing validity")
    valid_after = validity.get("valid_after")
    valid_until = validity.get("valid_until")
    if not isinstance(valid_after, int) or not isinstance(valid_until, int):
        raise ValueError("network status has invalid validity interval")
    if now < valid_after:
        raise ValueError(f"network status is not valid yet: valid_after={valid_after}")
    if now > valid_until:
        raise ValueError(f"network status expired: valid_until={valid_until}")

    snapshot = status_doc.get("snapshot")
    if not isinstance(snapshot, dict):
        raise ValueError("network status missing snapshot")
    snapshot_hash = canonical_snapshot_hash(snapshot)
    if status_doc.get("snapshot_hash") != snapshot_hash:
        raise ValueError("network status snapshot hash mismatch")

    declared_threshold = status_doc.get("threshold")
    if not isinstance(declared_threshold, dict):
        raise ValueError("network status missing threshold")
    if declared_threshold.get("k") != threshold_policy.get("k") or declared_threshold.get("n") != threshold_policy.get("n"):
        raise ValueError("network status threshold does not match local threshold policy")

    verify_threshold_votes(status_doc, trusted_authorities=trusted_authorities, threshold_policy=threshold_policy)

    verified: dict[str, dict[str, Any]] = {}
    for descriptor in snapshot.get("descriptors", []):
        relay = descriptor_relay_view(descriptor)
        verified[relay["name"]] = relay
    return verified


def _verify_legacy_bundle(
    bundle: dict[str, Any],
    authority_pub: dict[str, Any],
    now: int | None = None,
) -> dict[str, dict[str, Any]]:
    if bundle.get("version") != 1:
        raise ValueError(f"unsupported bundle version {bundle.get('version')}")
    if bundle.get("authority_key_id") != authority_pub["key_id"]:
        raise ValueError("bundle authority key id does not match trusted authority")

    verified: dict[str, dict[str, Any]] = {}
    descriptors = bundle.get("descriptors", [])
    if not isinstance(descriptors, list):
        raise ValueError("bundle descriptors must be a list")
    for descriptor in descriptors:
        verify_descriptor(descriptor, authority_pub, now=now)
        relay = descriptor_relay_view(descriptor)
        verified[relay["name"]] = relay
    return verified


def make_bundle_file(authority_pub_path: str | Path, descriptor_paths: list[str], out_path: str | Path) -> dict[str, Any]:
    authority_pub = load_authority_public(authority_pub_path)
    descriptors: list[dict[str, Any]] = []

    for path in descriptor_paths:
        descriptor = load_json(path)
        verify_descriptor(descriptor, authority_pub)
        descriptors.append(descriptor)

    bundle = {
        "version": 1,
        "generated_at": int(time.time()),
        "authority_key_id": authority_pub["key_id"],
        "descriptors": descriptors,
    }
    atomic_write_json(out_path, bundle)
    return bundle


__all__ = [
    "authority_key_id_from_public",
    "load_authority",
    "load_authority_public",
    "init_authority_file",
    "export_authority_pub_file",
    "signable_descriptor_payload",
    "sign_relay_file",
    "descriptor_relay_view",
    "verify_descriptor",
    "canonical_snapshot_hash",
    "make_authority_vote",
    "verify_threshold_votes",
    "verify_network_status",
    "verify_bundle",
    "make_bundle_file",
]
