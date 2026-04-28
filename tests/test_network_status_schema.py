from __future__ import annotations

import pytest


def _base_status() -> dict[str, object]:
    return {
        "version": 1,
        "snapshot": {
            "descriptors": [
                {
                    "signed": {
                        "relay": {
                            "name": "r1",
                            "host": "127.0.0.1",
                            "port": 9001,
                            "kemalg": "ML-KEM-768",
                            "public_key": "cA==",
                        }
                    }
                }
            ]
        },
        "snapshot_hash": "deadbeef",
        "validity": {"valid_after": 1, "valid_until": 2},
        "authority_set": [{"authority_id": "a1", "public_key": "p1"}],
        "threshold": {"k": 1, "n": 1},
        "votes": [{"authority_id": "a1", "signature": "s1", "sigalg": "ed25519"}],
    }


def test_network_status_schema_accepts_numeric_relay_metadata(latnet_modules):
    models = latnet_modules["models"]
    status = _base_status()
    relay = status["snapshot"]["descriptors"][0]["signed"]["relay"]  # type: ignore[index]
    relay["capacity_weight"] = 42.5
    relay["reliability_score"] = 0.97

    parsed = models.parse_network_status_document(status)

    assert parsed.snapshot["descriptors"][0]["signed"]["relay"]["capacity_weight"] == 42.5


def test_network_status_schema_rejects_non_numeric_relay_metadata(latnet_modules):
    models = latnet_modules["models"]
    status = _base_status()
    relay = status["snapshot"]["descriptors"][0]["signed"]["relay"]  # type: ignore[index]
    relay["reliability_score"] = "high"

    with pytest.raises(ValueError, match="invalid field type: reliability_score"):
        models.parse_network_status_document(status)
