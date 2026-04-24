from __future__ import annotations

import time


def _ready_state(mock_key_material: dict, role: str) -> dict:
    return {
        "role": role,
        "forward_key": mock_key_material["forward_b64"],
        "reverse_key": mock_key_material["reverse_b64"],
        "streams": {},
        "lifecycle_state": "ready",
        "created_at": time.time(),
        "last_activity_at": time.time(),
    }


def _send_hs_cell(server, crypto, key: bytes, circuit_id: str, layer: dict) -> dict:
    return server.handle_cell({"type": "CELL", "circuit_id": circuit_id, "layer": crypto.encrypt_layer(key, layer)})


def test_intro_pending_create_and_expire(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto = latnet_modules["crypto"]

    server = relay_mod.RelayServer(relay_doc_fixture, circuit_idle_seconds=1.0)
    server.set_circuit_state("intro-c", _ready_state(mock_key_material, "intro"))

    _send_hs_cell(
        server,
        crypto,
        mock_key_material["forward"],
        "intro-c",
        {"cmd": "INTRODUCE", "rendezvous_cookie": "cookie-expire", "introduction": {"a": 1}},
    )
    assert "cookie-expire" in server.pending_introductions

    ts = server.pending_introductions["cookie-expire"]["last_activity_at"] + 2.0
    server.cleanup_stale_state(now=ts)
    assert "cookie-expire" not in server.pending_introductions


def test_rendezvous_half_join_then_full_join(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto = latnet_modules["crypto"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    server.set_circuit_state("c-client", _ready_state(mock_key_material, "rendezvous"))
    server.set_circuit_state("c-service", _ready_state(mock_key_material, "rendezvous"))

    _send_hs_cell(
        server,
        crypto,
        mock_key_material["forward"],
        "c-client",
        {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie-join", "side": "client"},
    )
    assert server.pending_rendezvous["cookie-join"]["joined"] is False

    _send_hs_cell(
        server,
        crypto,
        mock_key_material["forward"],
        "c-service",
        {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie-join", "side": "service"},
    )
    joined = server.pending_rendezvous["cookie-join"]
    assert joined["joined"] is True
    assert server.rendezvous_links["c-client"]["peer_circuit_id"] == "c-service"
    assert server.rendezvous_links["c-service"]["peer_circuit_id"] == "c-client"


def test_destroy_cleans_up_rendezvous_mappings(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto = latnet_modules["crypto"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    server.set_circuit_state("d-client", _ready_state(mock_key_material, "rendezvous"))
    server.set_circuit_state("d-service", _ready_state(mock_key_material, "rendezvous"))

    _send_hs_cell(
        server,
        crypto,
        mock_key_material["forward"],
        "d-client",
        {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie-destroy", "side": "client"},
    )
    _send_hs_cell(
        server,
        crypto,
        mock_key_material["forward"],
        "d-service",
        {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie-destroy", "side": "service"},
    )

    response = server.handle_destroy({"type": "DESTROY", "circuit_id": "d-client"})

    assert response["ok"] is True
    assert "cookie-destroy" not in server.pending_rendezvous
    assert "d-client" not in server.rendezvous_links
    assert "d-service" not in server.rendezvous_links
