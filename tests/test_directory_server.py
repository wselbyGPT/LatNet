from __future__ import annotations

import json
import socket
import struct
import threading


def _run_handle_conn(server, conn):
    t = threading.Thread(target=server.handle_conn, args=(conn,), daemon=True)
    t.start()
    return t


def test_get_bundle_success_path(tmp_path, latnet_modules):
    wire = latnet_modules["wire"]
    directory_mod = latnet_modules["directory"]

    bundle = {"version": 1, "authority_key_id": "kid", "descriptors": []}
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    server = directory_mod.DirectoryServer(str(bundle_path))
    client_sock, server_sock = socket.socketpair()

    try:
        thread = _run_handle_conn(server, server_sock)
        wire.send_msg(client_sock, {"type": "GET_BUNDLE"})
        response = wire.recv_msg(client_sock)
        thread.join(timeout=1)

        assert response["ok"] is True
        assert response["bundle"] == bundle
    finally:
        client_sock.close()


def test_unknown_message_type_error_path(tmp_path, latnet_modules):
    wire = latnet_modules["wire"]
    directory_mod = latnet_modules["directory"]

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text('{"version":1,"descriptors":[]}', encoding="utf-8")
    server = directory_mod.DirectoryServer(str(bundle_path))

    client_sock, server_sock = socket.socketpair()
    try:
        thread = _run_handle_conn(server, server_sock)
        wire.send_msg(client_sock, {"type": "NOPE"})
        response = wire.recv_msg(client_sock)
        thread.join(timeout=1)

        assert response["ok"] is False
        assert "unknown message type" in response["error"]
    finally:
        client_sock.close()


def test_invalid_json_and_disconnect_handling(tmp_path, latnet_modules):
    directory_mod = latnet_modules["directory"]

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text('{"version":1,"descriptors":[]}', encoding="utf-8")
    server = directory_mod.DirectoryServer(str(bundle_path))

    client_sock, server_sock = socket.socketpair()
    try:
        thread = _run_handle_conn(server, server_sock)
        bad = b"invalid-json"
        client_sock.sendall(struct.pack("!I", len(bad)))
        client_sock.sendall(bad)

        raw_len = client_sock.recv(4)
        n = struct.unpack("!I", raw_len)[0]
        response = json.loads(client_sock.recv(n).decode("utf-8"))
        thread.join(timeout=1)

        assert response["ok"] is False
        assert "Expecting value" in response["error"]
    finally:
        client_sock.close()

    client_sock2, server_sock2 = socket.socketpair()
    try:
        thread2 = _run_handle_conn(server, server_sock2)
        client_sock2.close()
        thread2.join(timeout=1)
        assert not thread2.is_alive()
    finally:
        if client_sock2.fileno() != -1:
            client_sock2.close()


def test_missing_type_field_returns_error(tmp_path, latnet_modules):
    wire = latnet_modules["wire"]
    directory_mod = latnet_modules["directory"]

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text('{"version":1,"descriptors":[]}', encoding="utf-8")
    server = directory_mod.DirectoryServer(str(bundle_path))

    client_sock, server_sock = socket.socketpair()
    try:
        thread = _run_handle_conn(server, server_sock)
        wire.send_msg(client_sock, {"oops": 1})
        response = wire.recv_msg(client_sock)
        thread.join(timeout=1)

        assert response["ok"] is False
        assert response["error"] == "unknown message type None"
    finally:
        client_sock.close()


def test_non_object_wire_message_returns_error(tmp_path, latnet_modules):
    directory_mod = latnet_modules["directory"]

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text('{"version":1,"descriptors":[]}', encoding="utf-8")
    server = directory_mod.DirectoryServer(str(bundle_path))

    client_sock, server_sock = socket.socketpair()
    try:
        thread = _run_handle_conn(server, server_sock)
        bad = b'[]'
        client_sock.sendall(struct.pack("!I", len(bad)))
        client_sock.sendall(bad)

        raw_len = client_sock.recv(4)
        n = struct.unpack("!I", raw_len)[0]
        response = json.loads(client_sock.recv(n).decode("utf-8"))
        thread.join(timeout=1)

        assert response["ok"] is False
        assert "wire message must be an object" in response["error"]
    finally:
        client_sock.close()
