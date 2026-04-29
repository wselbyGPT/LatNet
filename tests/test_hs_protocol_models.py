from __future__ import annotations

import time
import hashlib
import hmac

import pytest


def _enc(mod, key: bytes, payload: dict):
    return mod.encrypt_layer(key, payload)


def _dec(mod, key: bytes, payload: dict):
    return mod.decrypt_layer(key, payload)


def _token(util, relay_doc: dict, cookie: str, side: str, *, exp_offset: int = 30, jti: str = "jti-1") -> dict:
    now = int(time.time())
    payload = {
        "jti": jti,
        "iat": now,
        "exp": now + exp_offset,
        "scope": {
            "service_name": "svc",
            "relay_name": relay_doc["name"],
            "rendezvous_cookie": cookie,
            "side": side,
        },
    }
    sig = hmac.new(util.b64d(relay_doc["secret_key"]), util.canonical_bytes(payload), hashlib.sha256).digest()
    return {"payload": payload, "sig": util.b64e(sig)}


def test_intro_messages_validate_and_poll_roundtrip(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto = latnet_modules["crypto"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    circuit_id = "intro-c-1"
    server.set_circuit_state(
        circuit_id,
        {
            "role": "intro",
            "forward_key": mock_key_material["forward_b64"],
            "reverse_key": mock_key_material["reverse_b64"],
            "streams": {},
            "lifecycle_state": "ready",
            "created_at": time.time(),
            "last_activity_at": time.time(),
        },
    )

    stored = server.handle_cell(
        {
            "type": "CELL",
            "circuit_id": circuit_id,
            "layer": _enc(
                crypto,
                mock_key_material["forward"],
                {"cmd": "INTRODUCE", "rendezvous_cookie": "cookie-1", "introduction": {"k": "v"}, "auth_token": _token(latnet_modules["util"], relay_doc_fixture, "cookie-1", "client", jti="m1")},
            ),
        }
    )
    assert stored["ok"] is True
    stored_layer = _dec(crypto, mock_key_material["reverse"], stored["reply_layer"])
    assert stored_layer["cmd"] == "INTRO_STORED"

    polled = server.handle_cell(
        {
            "type": "CELL",
            "circuit_id": circuit_id,
            "layer": _enc(crypto, mock_key_material["forward"], {"cmd": "INTRO_POLL"}),
        }
    )
    polled_layer = _dec(crypto, mock_key_material["reverse"], polled["reply_layer"])
    assert polled_layer["cmd"] == "INTRO_PENDING"
    assert polled_layer["items"][0]["rendezvous_cookie"] == "cookie-1"


def test_rendezvous_messages_validate_cookie_side_and_join_state(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto = latnet_modules["crypto"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    for cid in ("rdv-client", "rdv-service"):
        server.set_circuit_state(
            cid,
            {
                "role": "rendezvous",
                "forward_key": mock_key_material["forward_b64"],
                "reverse_key": mock_key_material["reverse_b64"],
                "streams": {},
                "lifecycle_state": "ready",
                "created_at": time.time(),
                "last_activity_at": time.time(),
            },
        )

    half = server.handle_cell(
        {
            "type": "CELL",
            "circuit_id": "rdv-client",
            "layer": _enc(
                crypto,
                mock_key_material["forward"],
                {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie-2", "side": "client", "auth_token": _token(latnet_modules["util"], relay_doc_fixture, "cookie-2", "client", jti="m2")},
            ),
        }
    )
    half_layer = _dec(crypto, mock_key_material["reverse"], half["reply_layer"])
    assert half_layer["joined"] is False

    full = server.handle_cell(
        {
            "type": "CELL",
            "circuit_id": "rdv-service",
            "layer": _enc(
                crypto,
                mock_key_material["forward"],
                {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie-2", "side": "service", "auth_token": _token(latnet_modules["util"], relay_doc_fixture, "cookie-2", "service", jti="m3")},
            ),
        }
    )
    full_layer = _dec(crypto, mock_key_material["reverse"], full["reply_layer"])
    assert full_layer["joined"] is True


def test_rejects_malformed_cookie_role_and_unknown_cmds(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto = latnet_modules["crypto"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    server.set_circuit_state(
        "intro-c",
        {
            "role": "intro",
            "forward_key": mock_key_material["forward_b64"],
            "reverse_key": mock_key_material["reverse_b64"],
            "streams": {},
            "lifecycle_state": "ready",
            "created_at": time.time(),
            "last_activity_at": time.time(),
        },
    )
    server.set_circuit_state(
        "rdv-c",
        {
            "role": "rendezvous",
            "forward_key": mock_key_material["forward_b64"],
            "reverse_key": mock_key_material["reverse_b64"],
            "streams": {},
            "lifecycle_state": "ready",
            "created_at": time.time(),
            "last_activity_at": time.time(),
        },
    )

    bad_cookie = server.handle_cell(
        {
            "type": "CELL",
            "circuit_id": "intro-c",
            "layer": _enc(crypto, mock_key_material["forward"], {"cmd": "INTRODUCE", "rendezvous_cookie": ""}),
        }
    )
    assert bad_cookie["ok"] is False
    assert "rendezvous_cookie" in bad_cookie["error"]

    bad_side = server.handle_cell(
        {
            "type": "CELL",
            "circuit_id": "rdv-c",
            "layer": _enc(
                crypto,
                mock_key_material["forward"],
                {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie", "side": "middle"},
            ),
        }
    )
    assert bad_side["ok"] is False
    assert "side" in bad_side["error"]

    wrong_role_cmd = server.handle_cell(
        {
            "type": "CELL",
            "circuit_id": "intro-c",
            "layer": _enc(crypto, mock_key_material["forward"], {"cmd": "RENDEZVOUS_RECV", "rendezvous_cookie": "c"}),
        }
    )
    assert wrong_role_cmd["ok"] is False
    assert "unknown intro cmd" in wrong_role_cmd["error"]


def test_publish_hs_descriptor_protocol_models_validate_fields(latnet_modules):
    protocol = latnet_modules["models"]

    parsed = protocol.parse_publish_hidden_service_descriptor_request(
        {
            "type": "PUBLISH_HS_DESCRIPTOR",
            "service_name": "a" * 32 + ".lettuce",
            "descriptor": {"version": 2},
            "expected_previous_revision": 1,
            "idempotency_key": "idem-1",
        }
    )
    assert parsed.service_name.endswith(".lettuce")
    assert parsed.expected_previous_revision == 1
    assert parsed.idempotency_key == "idem-1"

    with pytest.raises(ValueError, match="service_name"):
        protocol.parse_publish_hidden_service_descriptor_request(
            {"type": "PUBLISH_HS_DESCRIPTOR", "descriptor": {"version": 2}}
        )

    ok_response = protocol.parse_publish_hidden_service_descriptor_response(
        {"ok": True, "service_name": "a" * 32 + ".lettuce", "accepted_revision": 2}
    )
    assert ok_response.accepted_revision == 2

    fail_response = protocol.parse_publish_hidden_service_descriptor_response(
        {"ok": False, "error_class": "revision_conflict", "error": "bad revision"}
    )
    assert fail_response.error_class == "revision_conflict"


def test_network_status_protocol_models_validate_fields(latnet_modules):
    protocol = latnet_modules["models"]

    bundle_request = protocol.parse_get_bundle_request({"type": "GET_BUNDLE"})
    assert bundle_request.protocol_version == protocol.TRUST_BUNDLE_PROTOCOL_VERSION

    request = protocol.parse_get_network_status_request({"type": "GET_NETWORK_STATUS"})
    assert request.type == "GET_NETWORK_STATUS"
    assert request.protocol_version == protocol.TRUST_STATUS_PROTOCOL_VERSION

    ok_response = protocol.parse_get_network_status_response(
        {
            "ok": True,
            "network_status": {"version": 1},
            "protocol_version": protocol.TRUST_STATUS_PROTOCOL_VERSION,
            "status_version": 1,
            "server_time": 123,
        }
    )
    assert ok_response.ok is True
    assert ok_response.protocol_version == protocol.TRUST_STATUS_PROTOCOL_VERSION
    assert ok_response.status_version == 1

    error_response = protocol.parse_get_network_status_response(
        {
            "ok": False,
            "error_class": "network_status_unavailable",
            "error": "not found",
            "server_time": 123,
        }
    )
    assert error_response.error_class == "network_status_unavailable"

    with pytest.raises(ValueError, match="unsupported GET_NETWORK_STATUS protocol_version"):
        protocol.parse_get_network_status_response(
            {"ok": False, "protocol_version": 1, "error_class": "network_status_unavailable", "error": "not found"}
        )

def test_intro_token_expired_and_replay_rejected(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto = latnet_modules["crypto"]
    util = latnet_modules["util"]
    server = relay_mod.RelayServer(relay_doc_fixture)
    server.set_circuit_state("intro-x", {"role":"intro","forward_key":mock_key_material["forward_b64"],"reverse_key":mock_key_material["reverse_b64"],"streams":{},"lifecycle_state":"ready","created_at":time.time(),"last_activity_at":time.time()})
    expired = _token(util, relay_doc_fixture, "cookie-exp", "client", exp_offset=-1, jti="exp")
    bad = server.handle_cell({"type":"CELL","circuit_id":"intro-x","layer":_enc(crypto,mock_key_material["forward"],{"cmd":"INTRODUCE","rendezvous_cookie":"cookie-exp","introduction":{},"auth_token":expired})})
    assert bad["ok"] is False and bad.get("error_class") == "token_expired"

    tok = _token(util, relay_doc_fixture, "cookie-r", "client", jti="replay")
    first = server.handle_cell({"type":"CELL","circuit_id":"intro-x","layer":_enc(crypto,mock_key_material["forward"],{"cmd":"INTRODUCE","rendezvous_cookie":"cookie-r","introduction":{},"auth_token":tok})})
    second = server.handle_cell({"type":"CELL","circuit_id":"intro-x","layer":_enc(crypto,mock_key_material["forward"],{"cmd":"INTRODUCE","rendezvous_cookie":"cookie-r","introduction":{},"auth_token":tok})})
    assert first["ok"] is True
    assert second["ok"] is False and second.get("error_class") == "token_replay"
