from __future__ import annotations

import socket
import threading
import time

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
    if reply["cmd"] == "REPLY_CELL":
        return reply["cell"]
    return reply


def _encrypted_cmd_msg(crypto_mod, forward_key, circuit_id, payload):
    return {
        "type": "CELL",
        "circuit_id": circuit_id,
        "layer": crypto_mod.encrypt_layer(forward_key, payload),
    }


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
            "lifecycle_state": "ready",
            "created_at": time.time(),
            "last_activity_at": time.time(),
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


def test_exit_rejects_replayed_data_and_end(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto_mod = latnet_modules["crypto"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    circuit_id = "c-replay"
    server.set_circuit_state(
        circuit_id,
        {
            "role": "exit",
            "forward_key": mock_key_material["forward_b64"],
            "reverse_key": mock_key_material["reverse_b64"],
            "streams": {},
            "lifecycle_state": "ready",
            "created_at": time.time(),
            "last_activity_at": time.time(),
        },
    )

    assert _decrypt_reply(
        crypto_mod,
        mock_key_material["reverse"],
        server.handle_cell(
            _exit_cell_msg(
                crypto_mod,
                mock_key_material["forward"],
                circuit_id,
                {"stream_id": 7, "seq": 1, "cell_type": "BEGIN", "payload": "example:443"},
            )
        ),
    )["cell_type"] == "CONNECTED"

    assert _decrypt_reply(
        crypto_mod,
        mock_key_material["reverse"],
        server.handle_cell(
            _exit_cell_msg(
                crypto_mod,
                mock_key_material["forward"],
                circuit_id,
                {"stream_id": 7, "seq": 2, "cell_type": "DATA", "payload": "hello"},
            )
        ),
    )["cell_type"] == "DATA"

    replay_data = _decrypt_reply(
        crypto_mod,
        mock_key_material["reverse"],
        server.handle_cell(
            _exit_cell_msg(
                crypto_mod,
                mock_key_material["forward"],
                circuit_id,
                {"stream_id": 7, "seq": 2, "cell_type": "DATA", "payload": "replay"},
            )
        ),
    )
    assert replay_data["cell_type"] == "ERROR"
    assert "duplicate seq" in replay_data["payload"]

    assert _decrypt_reply(
        crypto_mod,
        mock_key_material["reverse"],
        server.handle_cell(
            _exit_cell_msg(
                crypto_mod,
                mock_key_material["forward"],
                circuit_id,
                {"stream_id": 7, "seq": 3, "cell_type": "END", "payload": "bye"},
            )
        ),
    )["cell_type"] == "ENDED"

    replay_end = _decrypt_reply(
        crypto_mod,
        mock_key_material["reverse"],
        server.handle_cell(
            _exit_cell_msg(
                crypto_mod,
                mock_key_material["forward"],
                circuit_id,
                {"stream_id": 7, "seq": 3, "cell_type": "END", "payload": "replay-end"},
            )
        ),
    )
    assert replay_end["cell_type"] == "ERROR"
    assert "duplicate seq" in replay_end["payload"]


def test_exit_rejects_skipped_sequence_values(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto_mod = latnet_modules["crypto"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    circuit_id = "c-skipped"
    server.set_circuit_state(
        circuit_id,
        {
            "role": "exit",
            "forward_key": mock_key_material["forward_b64"],
            "reverse_key": mock_key_material["reverse_b64"],
            "streams": {},
            "lifecycle_state": "ready",
            "created_at": time.time(),
            "last_activity_at": time.time(),
        },
    )

    _decrypt_reply(
        crypto_mod,
        mock_key_material["reverse"],
        server.handle_cell(
            _exit_cell_msg(
                crypto_mod,
                mock_key_material["forward"],
                circuit_id,
                {"stream_id": 9, "seq": 1, "cell_type": "BEGIN", "payload": "example:443"},
            )
        ),
    )
    skipped = _decrypt_reply(
        crypto_mod,
        mock_key_material["reverse"],
        server.handle_cell(
            _exit_cell_msg(
                crypto_mod,
                mock_key_material["forward"],
                circuit_id,
                {"stream_id": 9, "seq": 3, "cell_type": "DATA", "payload": "jump"},
            )
        ),
    )
    assert skipped["cell_type"] == "ERROR"
    assert "skipped seq 3" in skipped["payload"]


def test_exit_sequence_tracking_is_per_stream_id(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto_mod = latnet_modules["crypto"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    circuit_id = "c-mixed-streams"
    server.set_circuit_state(
        circuit_id,
        {
            "role": "exit",
            "forward_key": mock_key_material["forward_b64"],
            "reverse_key": mock_key_material["reverse_b64"],
            "streams": {},
            "lifecycle_state": "ready",
            "created_at": time.time(),
            "last_activity_at": time.time(),
        },
    )

    begin_stream_1 = _decrypt_reply(
        crypto_mod,
        mock_key_material["reverse"],
        server.handle_cell(
            _exit_cell_msg(
                crypto_mod,
                mock_key_material["forward"],
                circuit_id,
                {"stream_id": 1, "seq": 1, "cell_type": "BEGIN", "payload": "a:1"},
            )
        ),
    )
    begin_stream_2 = _decrypt_reply(
        crypto_mod,
        mock_key_material["reverse"],
        server.handle_cell(
            _exit_cell_msg(
                crypto_mod,
                mock_key_material["forward"],
                circuit_id,
                {"stream_id": 2, "seq": 1, "cell_type": "BEGIN", "payload": "b:2"},
            )
        ),
    )
    assert begin_stream_1["cell_type"] == "CONNECTED"
    assert begin_stream_2["cell_type"] == "CONNECTED"

    data_stream_1 = _decrypt_reply(
        crypto_mod,
        mock_key_material["reverse"],
        server.handle_cell(
            _exit_cell_msg(
                crypto_mod,
                mock_key_material["forward"],
                circuit_id,
                {"stream_id": 1, "seq": 2, "cell_type": "DATA", "payload": "s1"},
            )
        ),
    )
    data_stream_2 = _decrypt_reply(
        crypto_mod,
        mock_key_material["reverse"],
        server.handle_cell(
            _exit_cell_msg(
                crypto_mod,
                mock_key_material["forward"],
                circuit_id,
                {"stream_id": 2, "seq": 2, "cell_type": "DATA", "payload": "s2"},
            )
        ),
    )
    assert data_stream_1["cell_type"] == "DATA"
    assert data_stream_2["cell_type"] == "DATA"


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
            "lifecycle_state": "ready",
            "created_at": time.time(),
            "last_activity_at": time.time(),
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


def test_persistent_channel_reuse_and_reconnect_fallback(latnet_modules, relay_doc_fixture, monkeypatch):
    relay_mod = latnet_modules["relay"]

    class _Sock:
        def __init__(self, name):
            self.name = name
            self.closed = False

        def close(self):
            self.closed = True

    server = relay_mod.RelayServer(relay_doc_fixture, use_persistent_channels=True)
    state = {"next": {"host": "127.0.0.1", "port": 9101}}
    first = _Sock("first")
    second = _Sock("second")

    create_calls = []

    def _create_connection(addr, timeout):
        create_calls.append((addr, timeout))
        return first if len(create_calls) == 1 else second

    send_calls = []

    def _send_msg(sock, _msg):
        send_calls.append(sock.name)
        if sock is first and len(send_calls) == 2:
            raise OSError("broken pipe")

    recv_calls = []

    def _recv_msg(sock):
        recv_calls.append(sock.name)
        return {"ok": True, "reply_layer": {"nonce": "n", "ct": "c"}}

    monkeypatch.setattr(relay_mod.socket, "create_connection", _create_connection)
    monkeypatch.setattr(relay_mod, "send_msg", _send_msg)
    monkeypatch.setattr(relay_mod, "recv_msg", _recv_msg)

    first_resp = server.forward_to_next(state, {"type": "CELL"})
    second_resp = server.forward_to_next(state, {"type": "CELL"})

    assert first_resp["ok"] is True
    assert second_resp["ok"] is True
    assert len(create_calls) == 2
    assert send_calls == ["first", "first", "second"]
    assert recv_calls == ["first", "second"]
    assert first.closed is True


def test_cleanup_removes_idle_streams_and_circuits(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    server = relay_mod.RelayServer(
        relay_doc_fixture,
        circuit_ttl_seconds=10,
        circuit_idle_seconds=5,
        stream_idle_seconds=3,
    )
    now = 100.0
    server.set_circuit_state(
        "c-live",
        {
            "role": "exit",
            "forward_key": mock_key_material["forward_b64"],
            "reverse_key": mock_key_material["reverse_b64"],
            "lifecycle_state": "ready",
            "created_at": now - 1,
            "last_activity_at": now - 1,
            "streams": {
                "1": {"stream_id": 1, "last_activity_at": now - 4},
                "2": {"stream_id": 2, "last_activity_at": now - 1},
            },
        },
    )
    server.set_circuit_state(
        "c-expired",
        {
            "role": "exit",
            "forward_key": mock_key_material["forward_b64"],
            "reverse_key": mock_key_material["reverse_b64"],
            "lifecycle_state": "ready",
            "created_at": now - 11,
            "last_activity_at": now - 11,
            "streams": {},
        },
    )

    server.cleanup_stale_state(now=now)

    live = server.circuit_snapshot("c-live")
    assert live is not None
    assert "1" not in live["streams"]
    assert "2" in live["streams"]
    assert server.circuit_snapshot("c-expired") is None


def test_destroy_clears_local_state_when_remote_destroy_fails(
    latnet_modules, relay_doc_fixture, mock_key_material, monkeypatch
):
    relay_mod = latnet_modules["relay"]
    server = relay_mod.RelayServer(relay_doc_fixture)
    circuit_id = "c-forward-destroy"
    server.set_circuit_state(
        circuit_id,
        {
            "role": "forward",
            "forward_key": mock_key_material["forward_b64"],
            "reverse_key": mock_key_material["reverse_b64"],
            "next": {"host": "127.0.0.1", "port": 9102},
            "streams": {"1": {"stream_id": 1}},
            "lifecycle_state": "ready",
            "created_at": time.time(),
            "last_activity_at": time.time(),
        },
    )
    def _raise_remote_failure(_state, _msg):
        raise RuntimeError("network down")

    monkeypatch.setattr(server, "forward_to_next", _raise_remote_failure)

    response = server.handle_destroy({"type": "DESTROY", "circuit_id": circuit_id})

    assert response == {"ok": True, "status": "destroyed"}
    assert server.circuit_snapshot(circuit_id) is None


def test_intro_relay_stores_pending_introduction(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto_mod = latnet_modules["crypto"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    circuit_id = "c-intro"
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

    response = server.handle_cell(
        _encrypted_cmd_msg(
            crypto_mod,
            mock_key_material["forward"],
            circuit_id,
            {"cmd": "INTRODUCE", "rendezvous_cookie": "cookie-1", "introduction": {"service": "alpha"}},
        )
    )

    reply = _decrypt_reply(crypto_mod, mock_key_material["reverse"], response)
    assert reply["cmd"] == "INTRO_STORED"
    assert server.pending_introductions["cookie-1"]["intro_circuit_id"] == circuit_id


def test_rendezvous_join_creates_bidirectional_mapping(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    crypto_mod = latnet_modules["crypto"]

    server = relay_mod.RelayServer(relay_doc_fixture)
    client_circuit = "c-rdv-client"
    service_circuit = "c-rdv-service"
    for cid in (client_circuit, service_circuit):
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

    client_resp = server.handle_cell(
        _encrypted_cmd_msg(
            crypto_mod,
            mock_key_material["forward"],
            client_circuit,
            {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie-2", "side": "client"},
        )
    )
    client_reply = _decrypt_reply(crypto_mod, mock_key_material["reverse"], client_resp)
    assert client_reply["joined"] is False

    service_resp = server.handle_cell(
        _encrypted_cmd_msg(
            crypto_mod,
            mock_key_material["forward"],
            service_circuit,
            {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie-2", "side": "service"},
        )
    )
    service_reply = _decrypt_reply(crypto_mod, mock_key_material["reverse"], service_resp)
    assert service_reply["joined"] is True
    assert server.pending_rendezvous["cookie-2"]["joined"] is True
    assert server.rendezvous_links[client_circuit]["peer_circuit_id"] == service_circuit
    assert server.rendezvous_links[service_circuit]["peer_circuit_id"] == client_circuit


def test_cleanup_and_destroy_remove_hs_pending_state(latnet_modules, relay_doc_fixture, mock_key_material):
    relay_mod = latnet_modules["relay"]
    server = relay_mod.RelayServer(relay_doc_fixture, circuit_idle_seconds=5)
    now = time.time()
    intro_circuit = "c-intro-stale"
    rdv_circuit = "c-rdv-live"
    peer_circuit = "c-rdv-peer"
    for cid, role, created in (
        (intro_circuit, "intro", now - 10),
        (rdv_circuit, "rendezvous", now - 1),
        (peer_circuit, "rendezvous", now - 1),
    ):
        server.set_circuit_state(
            cid,
            {
                "role": role,
                "forward_key": mock_key_material["forward_b64"],
                "reverse_key": mock_key_material["reverse_b64"],
                "streams": {},
                "lifecycle_state": "ready",
                "created_at": created,
                "last_activity_at": created,
            },
        )
    server.pending_introductions["cookie-stale"] = {
        "intro_circuit_id": intro_circuit,
        "created_at": now - 10,
        "last_activity_at": now - 10,
    }
    server.pending_rendezvous["cookie-live"] = {
        "created_at": now - 1,
        "last_activity_at": now - 1,
        "client_circuit_id": rdv_circuit,
        "service_circuit_id": peer_circuit,
        "joined": True,
        "relay_map": {
            "client": {"circuit_id": rdv_circuit, "peer_circuit_id": peer_circuit},
            "service": {"circuit_id": peer_circuit, "peer_circuit_id": rdv_circuit},
        },
    }
    server.rendezvous_links[rdv_circuit] = {"cookie": "cookie-live", "peer_circuit_id": peer_circuit}
    server.rendezvous_links[peer_circuit] = {"cookie": "cookie-live", "peer_circuit_id": rdv_circuit}

    server.cleanup_stale_state(now=now)
    assert "cookie-stale" not in server.pending_introductions
    assert "cookie-live" in server.pending_rendezvous

    destroy_response = server.handle_destroy({"type": "DESTROY", "circuit_id": rdv_circuit})
    assert destroy_response == {"ok": True, "status": "destroyed"}
    assert "cookie-live" not in server.pending_rendezvous
    assert rdv_circuit not in server.rendezvous_links
    assert peer_circuit not in server.rendezvous_links
