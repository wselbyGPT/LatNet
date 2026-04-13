from __future__ import annotations

import base64

import pytest


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _valid_descriptor(hidden_service):
    service_public_key = _b64(b"fixed-service-public-key-v1")
    service_name = hidden_service.derive_lettuce_name_from_b64(service_public_key)
    return {
        "version": 1,
        "service_name": service_name,
        "service_public_key": service_public_key,
        "valid_after": 1_700_000_000,
        "valid_until": 1_700_003_600,
        "introduction_points": [
            {
                "relay": "relay-alpha",
                "ntor_onion_key": _b64(b"fixed-ntor-key-1"),
                "enc_key": _b64(b"fixed-enc-key-1"),
                "auth": {"key_type": "x25519", "auth_key": _b64(b"fixed-auth-key-1")},
            },
            {
                "relay": "relay-beta",
                "ntor_onion_key": _b64(b"fixed-ntor-key-2"),
                "enc_key": _b64(b"fixed-enc-key-2"),
            },
        ],
    }


def test_naming_same_public_key_yields_same_lettuce_name(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]

    key = b"deterministic-key-material"
    assert hidden_service.derive_lettuce_name(key) == hidden_service.derive_lettuce_name(key)


def test_naming_different_public_keys_yield_different_names(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]

    name_a = hidden_service.derive_lettuce_name(b"deterministic-key-material-a")
    name_b = hidden_service.derive_lettuce_name(b"deterministic-key-material-b")

    assert name_a != name_b


@pytest.mark.parametrize(
    "name",
    [
        "0123456789abcdef0123456789abcdef.invalid",  # bad suffix
        "0123456789ABCDEF0123456789ABCDEF.lettuce",  # uppercase
        "0123456789abcdef0123456789abcdeg.lettuce",  # non-hex char
        "0123456789abcdef0123456789abcde.lettuce",  # wrong length
    ],
)
def test_naming_invalid_names_are_rejected(latnet_modules, name):
    hidden_service = latnet_modules["models.hidden_service"]

    assert hidden_service.is_valid_lettuce_name(name) is False
    with pytest.raises(ValueError, match="missing or invalid field: lettuce_name"):
        hidden_service.parse_lettuce_name(name)


def test_descriptor_parser_success_returns_typed_dataclass(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]
    descriptor = _valid_descriptor(hidden_service)

    parsed = hidden_service.parse_hidden_service_descriptor(descriptor)

    assert isinstance(parsed, hidden_service.HiddenServiceDescriptor)
    assert parsed.service_name == descriptor["service_name"]
    assert parsed.valid_after == 1_700_000_000
    assert parsed.valid_until == 1_700_003_600


def test_descriptor_parser_success_parses_introduction_points(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]
    descriptor = _valid_descriptor(hidden_service)

    parsed = hidden_service.parse_hidden_service_descriptor(descriptor)

    assert len(parsed.introduction_points) == 2
    first = parsed.introduction_points[0]
    second = parsed.introduction_points[1]

    assert isinstance(first, hidden_service.IntroductionPoint)
    assert first.relay == "relay-alpha"
    assert first.auth is not None
    assert isinstance(first.auth, hidden_service.IntroductionPointAuth)
    assert first.auth.key_type == "x25519"

    assert isinstance(second, hidden_service.IntroductionPoint)
    assert second.relay == "relay-beta"
    assert second.auth is None


@pytest.mark.parametrize("missing_field", ["service_name", "service_public_key", "valid_after", "valid_until"])
def test_descriptor_parser_failure_missing_required_fields(latnet_modules, missing_field):
    hidden_service = latnet_modules["models.hidden_service"]
    descriptor = _valid_descriptor(hidden_service)
    descriptor.pop(missing_field)

    with pytest.raises(ValueError, match=f"missing or invalid field: {missing_field}"):
        hidden_service.parse_hidden_service_descriptor(descriptor)


def test_descriptor_parser_failure_invalid_validity_window(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]
    descriptor = _valid_descriptor(hidden_service)
    descriptor["valid_until"] = descriptor["valid_after"]

    with pytest.raises(ValueError, match="missing or invalid field: valid_until"):
        hidden_service.parse_hidden_service_descriptor(descriptor)


def test_descriptor_parser_failure_service_name_key_mismatch(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]
    descriptor = _valid_descriptor(hidden_service)
    descriptor["service_name"] = hidden_service.derive_lettuce_name(b"mismatched-public-key")

    with pytest.raises(ValueError, match="missing or invalid field: service_name"):
        hidden_service.parse_hidden_service_descriptor(descriptor)


def test_descriptor_parser_failure_empty_introduction_points(latnet_modules):
    hidden_service = latnet_modules["models.hidden_service"]
    descriptor = _valid_descriptor(hidden_service)
    descriptor["introduction_points"] = []

    with pytest.raises(ValueError, match="missing or invalid field: introduction_points"):
        hidden_service.parse_hidden_service_descriptor(descriptor)
