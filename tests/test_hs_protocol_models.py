from __future__ import annotations

import time


def _enc(mod, key: bytes, payload: dict):
    return mod.encrypt_layer(key, payload)


def _dec(mod, key: bytes, payload: dict):
    return mod.decrypt_layer(key, payload)


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
                {"cmd": "INTRODUCE", "rendezvous_cookie": "cookie-1", "introduction": {"k": "v"}},
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
                {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie-2", "side": "client"},
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
                {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie-2", "side": "service"},
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
