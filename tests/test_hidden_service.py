from __future__ import annotations

import base64
import random

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


def test_intro_point_weighted_scoring_prefers_healthy_relays(latnet_modules):
    client = latnet_modules["client"]
    now = 1_700_000_100
    healthy = {
        "relay_name": "healthy",
        "relay_addr": {"host": "h", "port": 1},
        "expires_at": now + 100,
        "relay_health": {"success_rate": 0.95, "timeout_rate": 0.01, "recent_latency_ms": 50, "measured_at": now},
    }
    unhealthy = {
        "relay_name": "unhealthy",
        "relay_addr": {"host": "u", "port": 2},
        "expires_at": now + 100,
        "relay_health": {"success_rate": 0.1, "timeout_rate": 0.8, "recent_latency_ms": 1000, "recent_failures": 5, "measured_at": now},
    }
    picks = {"healthy": 0, "unhealthy": 0}
    for seed in range(200):
        ordered = client._score_and_order_relays([healthy, unhealthy], now=now, rng_seed=seed)
        picks[ordered[0]["relay_name"]] += 1
    assert picks["healthy"] > picks["unhealthy"]


def test_intro_point_selection_has_floor_when_all_scores_low(latnet_modules):
    client = latnet_modules["client"]
    now = 1_700_000_200
    a = {"relay_name": "a", "relay_addr": {"host": "a", "port": 1}, "expires_at": now + 100, "relay_health": {"success_rate": 0.0, "timeout_rate": 1.0, "recent_latency_ms": 2000, "recent_failures": 10}}
    b = {"relay_name": "b", "relay_addr": {"host": "b", "port": 2}, "expires_at": now + 100, "relay_health": {"success_rate": 0.0, "timeout_rate": 1.0, "recent_latency_ms": 2500, "recent_failures": 10}}
    seen = set()
    for seed in range(100):
        seen.add(client._score_and_order_relays([a, b], now=now, rng_seed=seed)[0]["relay_name"])
    assert seen == {"a", "b"}


def test_weighted_selection_stability_with_seed(latnet_modules):
    client = latnet_modules["client"]
    now = 1_700_000_300
    relays = [
        {"relay_name": "r1", "relay_addr": {"host": "h1", "port": 1}, "expires_at": now + 100, "health_score": 0.9},
        {"relay_name": "r2", "relay_addr": {"host": "h2", "port": 2}, "expires_at": now + 100, "health_score": 0.6},
        {"relay_name": "r3", "relay_addr": {"host": "h3", "port": 3}, "expires_at": now + 100, "health_score": 0.4},
    ]
    first = [p["relay_name"] for p in client._score_and_order_relays(relays, now=now, rng_seed=42)]
    second = [p["relay_name"] for p in client._score_and_order_relays(relays, now=now, rng_seed=42)]
    assert first == second
