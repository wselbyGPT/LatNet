from __future__ import annotations

import base64

import pytest


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _descriptor(hidden_service):
    service_public_key = _b64("service-pub-key")
    service_name = hidden_service.derive_lettuce_name_from_b64(service_public_key)
    return {
        "version": 1,
        "service_name": service_name,
        "service_public_key": service_public_key,
        "valid_after": 100,
        "valid_until": 200,
        "introduction_points": [
            {
                "relay": "relay-a",
                "ntor_onion_key": _b64("ntor-key"),
                "enc_key": _b64("enc-key"),
                "auth": {"key_type": "x25519", "auth_key": _b64("auth-key")},
            }
        ],
    }


def test_parse_hidden_service_descriptor_success(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]
    doc = _descriptor(hidden_service)

    parsed = hidden_service.parse_hidden_service_descriptor(doc)

    assert parsed.version == 1
    assert parsed.service_name == doc["service_name"]
    assert len(parsed.introduction_points) == 1
    assert parsed.introduction_points[0].auth is not None


def test_parse_hidden_service_descriptor_rejects_invalid_version(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]
    doc = _descriptor(hidden_service)
    doc["version"] = 2

    with pytest.raises(ValueError, match="missing or invalid field: version"):
        hidden_service.parse_hidden_service_descriptor(doc)


def test_parse_hidden_service_descriptor_rejects_service_name_mismatch(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]
    doc = _descriptor(hidden_service)
    doc["service_name"] = hidden_service.derive_lettuce_name(b"other-key")

    with pytest.raises(ValueError, match="missing or invalid field: service_name"):
        hidden_service.parse_hidden_service_descriptor(doc)


def test_parse_hidden_service_descriptor_rejects_invalid_validity_window(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]
    doc = _descriptor(hidden_service)
    doc["valid_after"] = 500
    doc["valid_until"] = 500

    with pytest.raises(ValueError, match="missing or invalid field: valid_until"):
        hidden_service.parse_hidden_service_descriptor(doc)


def test_parse_hidden_service_descriptor_requires_introduction_points(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]
    doc = _descriptor(hidden_service)
    doc["introduction_points"] = []

    with pytest.raises(ValueError, match="missing or invalid field: introduction_points"):
        hidden_service.parse_hidden_service_descriptor(doc)


def test_parse_hidden_service_descriptor_rejects_invalid_key_encoding(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]
    doc = _descriptor(hidden_service)
    doc["introduction_points"][0]["enc_key"] = "not-b64-$$"

    with pytest.raises(ValueError, match="missing or invalid field: enc_key"):
        hidden_service.parse_hidden_service_descriptor(doc)
