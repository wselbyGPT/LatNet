from __future__ import annotations

import socket
import threading


def _exit_cell_msg(crypto_mod, forward_key, circuit_id, cell):
    return {
        "type": "CELL",
        "circuit_id": circuit_id,
        "layer": crypto_mod.encrypt_layer(
            forward_key,
            {
                "cmd": "EXIT_CELL",
                "cell": cell,
            },
        ),
    }


def _decrypt_reply(crypto_mod, reverse_key, response):
    assert response["ok"] is True
    reply = crypto_mod.decrypt_layer(reverse_key, response["reply_layer"])
    assert reply["cmd"] == "REPLY_CELL"
    return reply["cell"]


def test_handle_cell_unknown_circuit(latnet_modules, relay_doc_fixture):
    relay_mod = latnet_modules["relay"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    response = server.handle_cell({"type": "CELL", "circuit_id": "missing", "layer": {}})

    assert response["ok"] is False
    assert "unknown circuit_id" in response["error"]


def test_exit_begin_data_end_transitions(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto_mod = latnet_modules["crypto"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    circuit_id = "c-1"
    server.set_circuit_state(
        circuit_id,
        {
            "role": "exit",
            "forward_key": mock_key_material["forward_b64"],
            "reverse_key": mock_key_material["reverse_b64"],
            "streams": {},
        },
    )

    begin_resp = server.handle_cell(
        _exit_cell_msg(
            crypto_mod,
            mock_key_material["forward"],
            circuit_id,
            {"stream_id": 1, "seq": 1, "cell_type": "BEGIN", "payload": "example:443"},
        )
    )
    begin_cell = _decrypt_reply(crypto_mod, mock_key_material["reverse"], begin_resp)
    assert begin_cell["cell_type"] == "CONNECTED"

    data_resp = server.handle_cell(
        _exit_cell_msg(
            crypto_mod,
            mock_key_material["forward"],
            circuit_id,
            {"stream_id": 1, "seq": 2, "cell_type": "DATA", "payload": "hello"},
        )
    )
    data_cell = _decrypt_reply(crypto_mod, mock_key_material["reverse"], data_resp)
    assert data_cell["cell_type"] == "DATA"
    assert "echo[1] hello" == data_cell["payload"]

    end_resp = server.handle_cell(
        _exit_cell_msg(
            crypto_mod,
            mock_key_material["forward"],
            circuit_id,
            {"stream_id": 1, "seq": 3, "cell_type": "END", "payload": "bye"},
        )
    )
    end_cell = _decrypt_reply(crypto_mod, mock_key_material["reverse"], end_resp)
    assert end_cell["cell_type"] == "ENDED"

    data_after_end_resp = server.handle_cell(
        _exit_cell_msg(
            crypto_mod,
            mock_key_material["forward"],
            circuit_id,
            {"stream_id": 1, "seq": 4, "cell_type": "DATA", "payload": "late"},
        )
    )
    data_after_end_cell = _decrypt_reply(crypto_mod, mock_key_material["reverse"], data_after_end_resp)
    assert data_after_end_cell["cell_type"] == "ERROR"


def test_destroy_idempotency(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    circuit_id = "c-destroy"
    server.set_circuit_state(
        circuit_id,
        {
            "role": "exit",
            "forward_key": mock_key_material["forward_b64"],
            "reverse_key": mock_key_material["reverse_b64"],
            "streams": {},
        },
    )

    first = server.handle_destroy({"type": "DESTROY", "circuit_id": circuit_id})
    second = server.handle_destroy({"type": "DESTROY", "circuit_id": circuit_id})

    assert first == {"ok": True, "status": "destroyed"}
    assert second == {"ok": True, "status": "already_gone"}


def _run_relay_handle_conn(server, conn):
    t = threading.Thread(target=server.handle_conn, args=(conn,), daemon=True)
    t.start()
    return t


def test_handle_conn_rejects_missing_required_fields(latnet_modules, relay_doc_fixture):
    relay_mod = latnet_modules["relay"]
    wire = latnet_modules["wire"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    client_sock, server_sock = socket.socketpair()
    try:
        thread = _run_relay_handle_conn(server, server_sock)
        wire.send_msg(client_sock, {"type": "BUILD", "ct": "abc", "layer": {"nonce": "n", "ct": "c"}})
        response = wire.recv_msg(client_sock)
        thread.join(timeout=1)

        assert response["ok"] is False
        assert "missing or invalid field: circuit_id" in response["error"]
    finally:
        client_sock.close()


def test_handle_conn_unknown_type_cli_compatible(latnet_modules, relay_doc_fixture):
    relay_mod = latnet_modules["relay"]
    wire = latnet_modules["wire"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    client_sock, server_sock = socket.socketpair()
    try:
        thread = _run_relay_handle_conn(server, server_sock)
        wire.send_msg(client_sock, {"type": "NOPE"})
        response = wire.recv_msg(client_sock)
        thread.join(timeout=1)

        assert response["ok"] is False
        assert response["error"] == "unknown message type NOPE"
    finally:
        client_sock.close()
