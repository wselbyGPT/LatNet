from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AuthorityMetadata:
    authority_id: str
    public_key: str


@dataclass(frozen=True)
class AuthorityVote:
    authority_id: str
    signature: str
    sigalg: str


@dataclass(frozen=True)
class ThresholdPolicy:
    k: int
    n: int


@dataclass(frozen=True)
class ValidityInterval:
    valid_after: int
    valid_until: int


@dataclass(frozen=True)
class NetworkStatusDocument:
    version: int
    snapshot: dict[str, Any]
    snapshot_hash: str
    validity: ValidityInterval
    authority_set: list[AuthorityMetadata]
    threshold: ThresholdPolicy
    votes: list[AuthorityVote]


def _as_dict(obj: Any, *, context: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError(f"{context} must be an object")
    return obj


def _req_str(src: dict[str, Any], field: str, *, context: str) -> str:
    value = src.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} missing or invalid field: {field}")
    return value


def _req_int(src: dict[str, Any], field: str, *, context: str) -> int:
    value = src.get(field)
    if not isinstance(value, int):
        raise ValueError(f"{context} missing or invalid field: {field}")
    return value


def parse_network_status_document(obj: Any) -> NetworkStatusDocument:
    src = _as_dict(obj, context="network status")
    version = _req_int(src, "version", context="network status")
    if version != 1:
        raise ValueError(f"unsupported network status version {version}")

    snapshot = _as_dict(src.get("snapshot"), context="network status snapshot")
    snapshot_hash = _req_str(src, "snapshot_hash", context="network status")

    validity_src = _as_dict(src.get("validity"), context="network status validity")
    validity = ValidityInterval(
        valid_after=_req_int(validity_src, "valid_after", context="network status validity"),
        valid_until=_req_int(validity_src, "valid_until", context="network status validity"),
    )

    threshold_src = _as_dict(src.get("threshold"), context="network status threshold")
    threshold = ThresholdPolicy(
        k=_req_int(threshold_src, "k", context="network status threshold"),
        n=_req_int(threshold_src, "n", context="network status threshold"),
    )

    authority_set_src = src.get("authority_set")
    if not isinstance(authority_set_src, list):
        raise ValueError("network status missing or invalid field: authority_set")
    authority_set = [
        AuthorityMetadata(
            authority_id=_req_str(_as_dict(item, context="authority metadata"), "authority_id", context="authority metadata"),
            public_key=_req_str(_as_dict(item, context="authority metadata"), "public_key", context="authority metadata"),
        )
        for item in authority_set_src
    ]

    votes_src = src.get("votes")
    if not isinstance(votes_src, list):
        raise ValueError("network status missing or invalid field: votes")
    votes = [
        AuthorityVote(
            authority_id=_req_str(_as_dict(item, context="authority vote"), "authority_id", context="authority vote"),
            signature=_req_str(_as_dict(item, context="authority vote"), "signature", context="authority vote"),
            sigalg=_req_str(_as_dict(item, context="authority vote"), "sigalg", context="authority vote"),
        )
        for item in votes_src
    ]

    return NetworkStatusDocument(
        version=version,
        snapshot=snapshot,
        snapshot_hash=snapshot_hash,
        validity=validity,
        authority_set=authority_set,
        threshold=threshold,
        votes=votes,
    )


__all__ = [
    "AuthorityMetadata",
    "AuthorityVote",
    "ThresholdPolicy",
    "ValidityInterval",
    "NetworkStatusDocument",
    "parse_network_status_document",
]
