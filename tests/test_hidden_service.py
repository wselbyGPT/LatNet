from __future__ import annotations

import base64

import pytest


def test_derive_lettuce_name_is_deterministic_and_hex(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]

    public_key = b"demo-service-pubkey"
    name_1 = hidden_service.derive_lettuce_name(public_key)
    name_2 = hidden_service.derive_lettuce_name(public_key)

    assert name_1 == name_2
    assert name_1.endswith(".lettuce")
    assert len(name_1.split(".", 1)[0]) == 32


def test_derive_lettuce_name_from_b64_matches_raw(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]

    public_key = b"another-key"
    public_key_b64 = base64.b64encode(public_key).decode("ascii")

    assert hidden_service.derive_lettuce_name_from_b64(public_key_b64) == hidden_service.derive_lettuce_name(public_key)


def test_parse_and_validate_lettuce_name(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]

    name = hidden_service.derive_lettuce_name(b"valid-key")
    assert hidden_service.is_valid_lettuce_name(name)
    service_id = hidden_service.parse_lettuce_name(name)
    assert service_id == name[: -len(".lettuce")]


def test_parse_lettuce_name_rejects_invalid_values(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]

    with pytest.raises(ValueError, match="missing or invalid field: lettuce_name"):
        hidden_service.parse_lettuce_name("")
    with pytest.raises(ValueError, match="missing or invalid field: lettuce_name"):
        hidden_service.parse_lettuce_name("ABCDEF0123456789ABCDEF0123456789.lettuce")
    with pytest.raises(ValueError, match="missing or invalid field: lettuce_name"):
        hidden_service.parse_lettuce_name("xyz.lettuce")


def test_derive_lettuce_name_rejects_invalid_public_key(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]

    with pytest.raises(ValueError, match="missing or invalid field: service_public_key"):
        hidden_service.derive_lettuce_name(b"")
    with pytest.raises(ValueError, match="missing or invalid field: service_public_key"):
        hidden_service.derive_lettuce_name_from_b64("not-base64%%")


def test_models_init_exports_hidden_service_symbols(latnet_modules):
    models = latnet_modules["models"]

    assert hasattr(models, "derive_lettuce_name")
    assert hasattr(models, "derive_lettuce_name_from_b64")
    assert hasattr(models, "is_valid_lettuce_name")
    assert hasattr(models, "parse_lettuce_name")
