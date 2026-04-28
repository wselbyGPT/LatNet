from __future__ import annotations

import json
import warnings

import pytest


def test_verify_network_status_threshold_success(tmp_path, latnet_modules):
    authority_mod = latnet_modules["authority"]

    authorities = []
    for idx in range(3):
        path = tmp_path / f"auth-{idx}.json"
        authority = authority_mod.init_authority_file(f"auth-{idx}", path)
        authority["key_id"] = f"auth-{idx}"
        authorities.append(authority)

    snapshot = {"descriptors": [{"signed": {"relay": {"name": "r1", "host": "127.0.0.1", "port": 9001}}}]}
    snapshot_hash = authority_mod.canonical_snapshot_hash(snapshot)
    votes = [
        authority_mod.make_authority_vote(authorities[0], snapshot_hash),
        authority_mod.make_authority_vote(authorities[1], snapshot_hash),
    ]
    status_doc = {
        "version": 1,
        "snapshot": snapshot,
        "snapshot_hash": snapshot_hash,
        "validity": {"valid_after": 10, "valid_until": 1000},
        "authority_set": [
            {"authority_id": a["key_id"], "public_key": a["public_key"]}
            for a in authorities
        ],
        "threshold": {"k": 2, "n": 3},
        "votes": votes,
    }

    verified = authority_mod.verify_network_status(
        status_doc,
        trusted_authorities=[{"key_id": a["key_id"], "public_key": a["public_key"]} for a in authorities],
        threshold_policy={"k": 2, "n": 3},
        now=100,
    )

    assert verified["r1"]["host"] == "127.0.0.1"


def test_verify_network_status_rejects_duplicate_signer(tmp_path, latnet_modules):
    authority_mod = latnet_modules["authority"]

    auth0 = authority_mod.init_authority_file("auth-0", tmp_path / "auth-0.json")
    auth1 = authority_mod.init_authority_file("auth-1", tmp_path / "auth-1.json")
    auth0["key_id"] = "auth-0"
    auth1["key_id"] = "auth-1"
    snapshot = {"descriptors": [{"signed": {"relay": {"name": "r1"}}}]}
    snapshot_hash = authority_mod.canonical_snapshot_hash(snapshot)
    vote = authority_mod.make_authority_vote(auth0, snapshot_hash)
    status_doc = {
        "version": 1,
        "snapshot": snapshot,
        "snapshot_hash": snapshot_hash,
        "validity": {"valid_after": 0, "valid_until": 1000},
        "authority_set": [
            {"authority_id": auth0["key_id"], "public_key": auth0["public_key"]},
            {"authority_id": auth1["key_id"], "public_key": auth1["public_key"]},
        ],
        "threshold": {"k": 2, "n": 2},
        "votes": [vote, vote],
    }

    with pytest.raises(ValueError, match="duplicate authority vote"):
        authority_mod.verify_network_status(
            status_doc,
            trusted_authorities=[
                {"key_id": auth0["key_id"], "public_key": auth0["public_key"]},
                {"key_id": auth1["key_id"], "public_key": auth1["public_key"]},
            ],
            threshold_policy={"k": 2, "n": 2},
            now=10,
        )


def test_verify_bundle_compat_wrapper(tmp_path, latnet_modules):
    authority_mod = latnet_modules["authority"]

    authority_path = tmp_path / "authority.json"
    relay_path = tmp_path / "relay.json"
    descriptor_path = tmp_path / "descriptor.json"

    authority = authority_mod.init_authority_file("auth", authority_path)
    relay_path.write_text(
        json.dumps(
            {
                "name": "relay-1",
                "host": "127.0.0.1",
                "port": 9001,
                "kemalg": "MLKEM512",
                "public_key": "ZmFrZS1rZXk=",
            }
        ),
        encoding="utf-8",
    )
    descriptor = authority_mod.sign_relay_file(relay_path, authority_path, valid_for=300, out_path=descriptor_path)

    bundle = {
        "version": 1,
        "authority_key_id": authority["key_id"],
        "descriptors": [descriptor],
    }

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        verified = authority_mod.verify_bundle(
            bundle,
            {"key_id": authority["key_id"], "public_key": authority["public_key"]},
            now=descriptor["signed"]["valid_after"] + 1,
        )

    assert verified["relay-1"]["port"] == 9001
    assert any(isinstance(item.message, DeprecationWarning) for item in caught)
