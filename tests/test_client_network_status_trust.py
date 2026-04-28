from __future__ import annotations

import pytest


def _make_authorities(authority_mod, tmp_path, count: int):
    authorities = []
    for idx in range(count):
        authority = authority_mod.init_authority_file(f"auth-{idx}", tmp_path / f"auth-{idx}.json")
        authority["key_id"] = f"auth-{idx}"
        authorities.append(authority)
    return authorities


def _make_status(authority_mod, authorities, *, signer_ids, valid_after=10, valid_until=1000):
    snapshot = {
        "descriptors": [
            {"signed": {"relay": {"name": "r1", "host": "127.0.0.1", "port": 9001, "kemalg": "ML-KEM-768", "public_key": "cA=="}}}
        ]
    }
    snapshot_hash = authority_mod.canonical_snapshot_hash(snapshot)
    votes = [authority_mod.make_authority_vote(authorities[idx], snapshot_hash) for idx in signer_ids]
    return {
        "version": 1,
        "snapshot": snapshot,
        "snapshot_hash": snapshot_hash,
        "validity": {"valid_after": valid_after, "valid_until": valid_until},
        "authority_set": [{"authority_id": item["key_id"], "public_key": item["public_key"]} for item in authorities],
        "threshold": {"k": 2, "n": len(authorities)},
        "votes": votes,
    }


def test_client_verifies_k_of_n_success(tmp_path, latnet_modules):
    authority_mod = latnet_modules["authority"]
    client = latnet_modules["client"]
    authorities = _make_authorities(authority_mod, tmp_path, 3)
    status_doc = _make_status(authority_mod, authorities, signer_ids=[0, 1])
    trust = client.ClientTrustConfig(
        trusted_authorities=[{"authority_id": item["key_id"], "public_key": item["public_key"]} for item in authorities],
        min_signers=2,
    )

    relays = client.verified_relays_from_network_status(status_doc, trust, now=100)

    assert relays["r1"]["host"] == "127.0.0.1"


def test_client_rejects_insufficient_signers(tmp_path, latnet_modules):
    authority_mod = latnet_modules["authority"]
    client = latnet_modules["client"]
    authorities = _make_authorities(authority_mod, tmp_path, 3)
    status_doc = _make_status(authority_mod, authorities, signer_ids=[0])
    trust = client.ClientTrustConfig(
        trusted_authorities=[{"authority_id": item["key_id"], "public_key": item["public_key"]} for item in authorities],
        min_signers=2,
    )

    with pytest.raises(ValueError, match="insufficient authority votes"):
        client.verified_relays_from_network_status(status_doc, trust, now=100)


def test_client_rejects_expired_snapshot(tmp_path, latnet_modules):
    authority_mod = latnet_modules["authority"]
    client = latnet_modules["client"]
    authorities = _make_authorities(authority_mod, tmp_path, 3)
    status_doc = _make_status(authority_mod, authorities, signer_ids=[0, 1], valid_after=0, valid_until=50)
    trust = client.ClientTrustConfig(
        trusted_authorities=[{"authority_id": item["key_id"], "public_key": item["public_key"]} for item in authorities],
        min_signers=2,
    )

    with pytest.raises(ValueError, match="expired"):
        client.verified_relays_from_network_status(status_doc, trust, now=100)


def test_client_rejects_unknown_and_duplicate_signers(tmp_path, latnet_modules):
    authority_mod = latnet_modules["authority"]
    client = latnet_modules["client"]
    authorities = _make_authorities(authority_mod, tmp_path, 3)
    status_doc = _make_status(authority_mod, authorities, signer_ids=[0, 1])
    status_doc["votes"][0]["authority_id"] = "unknown"
    trust = client.ClientTrustConfig(
        trusted_authorities=[{"authority_id": item["key_id"], "public_key": item["public_key"]} for item in authorities],
        min_signers=2,
    )

    with pytest.raises(ValueError, match="not in trusted authority set"):
        client.verified_relays_from_network_status(status_doc, trust, now=100)

    status_doc = _make_status(authority_mod, authorities, signer_ids=[0, 1])
    status_doc["votes"][1]["authority_id"] = status_doc["votes"][0]["authority_id"]
    with pytest.raises(ValueError, match="duplicate authority vote"):
        client.verified_relays_from_network_status(status_doc, trust, now=100)

