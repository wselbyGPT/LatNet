from __future__ import annotations

import pytest


def _introduce_msg():
    return {
        "type": "INTRODUCE",
        "circuit_id": "circ-1",
        "service_name": "service.lettuce",
        "rendezvous_cookie": "cookie-abc",
        "client_ephemeral": "client-ephemeral-pk",
        "rendezvous_relay": {"relay": "relay-r", "host": "127.0.0.1", "port": 9001},
    }


def _join_msg():
    return {
        "type": "RENDEZVOUS_JOIN",
        "circuit_id": "circ-2",
        "service_name": "service.lettuce",
        "rendezvous_cookie": "cookie-abc",
        "service_ephemeral": "service-ephemeral-pk",
        "rendezvous_relay": {"relay": "relay-r", "host": "127.0.0.1", "port": 9001},
    }


def test_parse_introduce_envelope_success(latnet_modules):
    models = latnet_modules["models"]

    parsed = models.parse_introduce_envelope(_introduce_msg())

    assert isinstance(parsed, models.IntroduceEnvelope)
    assert parsed.rendezvous_relay.relay == "relay-r"


def test_parse_rendezvous_join_envelope_success(latnet_modules):
    models = latnet_modules["models"]

    parsed = models.parse_rendezvous_join_envelope(_join_msg())

    assert isinstance(parsed, models.RendezvousJoinEnvelope)
    assert parsed.service_ephemeral == "service-ephemeral-pk"


def test_parse_envelope_dispatches_hs_types(latnet_modules):
    models = latnet_modules["models"]

    intro = models.parse_envelope(_introduce_msg())
    join = models.parse_envelope(_join_msg())

    assert isinstance(intro, models.IntroduceEnvelope)
    assert isinstance(join, models.RendezvousJoinEnvelope)


@pytest.mark.parametrize(
    "msg,field",
    [
        ({k: v for k, v in _introduce_msg().items() if k != "service_name"}, "service_name"),
        ({k: v for k, v in _introduce_msg().items() if k != "rendezvous_cookie"}, "rendezvous_cookie"),
        ({k: v for k, v in _introduce_msg().items() if k != "client_ephemeral"}, "client_ephemeral"),
        ({k: v for k, v in _introduce_msg().items() if k != "circuit_id"}, "circuit_id"),
    ],
)
def test_parse_introduce_envelope_required_fields(latnet_modules, msg, field):
    models = latnet_modules["models"]

    with pytest.raises(ValueError, match=f"missing or invalid field: {field}"):
        models.parse_introduce_envelope(msg)


def test_parse_introduce_envelope_requires_relay_routing_fields(latnet_modules):
    models = latnet_modules["models"]
    msg = _introduce_msg()
    msg["rendezvous_relay"] = {"relay": "relay-r", "port": 9001}

    with pytest.raises(ValueError, match="missing or invalid field: host"):
        models.parse_introduce_envelope(msg)


def test_parse_layer_hs_intro_and_rendezvous_success(latnet_modules):
    models = latnet_modules["models"]

    intro = models.parse_layer({"cmd": "HS_INTRO", **{k: v for k, v in _introduce_msg().items() if k != "type"}})
    rendezvous = models.parse_layer({"cmd": "HS_RENDEZVOUS", **{k: v for k, v in _join_msg().items() if k != "type"}})

    assert isinstance(intro, models.HSIntroLayer)
    assert isinstance(rendezvous, models.HSRendezvousLayer)


def test_parse_layer_hs_rendezvous_relay_success(latnet_modules):
    models = latnet_modules["models"]

    layer = models.parse_layer({"cmd": "HS_RENDEZVOUS_RELAY", "inner": {"nonce": "n", "ct": "c"}})

    assert isinstance(layer, models.HSRendezvousRelayLayer)


def test_parse_layer_hs_rendezvous_missing_ephemeral(latnet_modules):
    models = latnet_modules["models"]
    msg = {k: v for k, v in _join_msg().items() if k not in {"type", "service_ephemeral"}}

    with pytest.raises(ValueError, match="missing or invalid field: service_ephemeral"):
        models.parse_layer({"cmd": "HS_RENDEZVOUS", **msg})
