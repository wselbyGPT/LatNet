from __future__ import annotations

import json
import socket
import struct
import threading
import time


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


def _make_hs_descriptor_doc(latnet_modules, tmp_path):
    hs_keys = latnet_modules["hidden_service_keys"]
    hs_desc = latnet_modules["models.hidden_service_descriptor"]
    util = latnet_modules["util"]

    now = int(time.time())
    service = hs_keys.generate_service_master("svc", tmp_path / "service_master.json")
    desc_signing = hs_keys.generate_descriptor_signing_key()
    cert = hs_keys.build_descriptor_signing_certificate(
        service,
        desc_signing["descriptor_signing_public_key"],
        valid_for=100,
        now=now - 10,
    )
    signed = {
        "service_name": service["service_name"],
        "service_master_public_key": service["service_master_public_key"],
        "descriptor_signing_public_key": desc_signing["descriptor_signing_public_key"],
        "descriptor_signing_certificate": cert,
        "valid_after": now - 5,
        "valid_until": now + 60,
        "revision": 1,
        "period": 1,
        "introduction_points": [
            {
                "relay_name": "relay-a",
                "relay_addr": {"host": "127.0.0.1", "port": 9101},
                "intro_auth_pub": util.b64e(b"intro-auth-pub"),
                "intro_key_id": "intro-key-1",
                "expires_at": now + 60,
            }
        ],
    }
    payload = util.canonical_bytes(signed)
    signer = hs_keys.Ed25519PrivateKey.from_private_bytes(util.b64d(desc_signing["descriptor_signing_private_key"]))
    signature = util.b64e(signer.sign(payload))
    doc = {"version": 2, "signed": signed, "sigalg": "ed25519", "signature": signature}
    hs_desc.verify_hidden_service_descriptor_v2(doc, now=now)
    return doc


def test_get_hidden_service_descriptor_success_path(tmp_path, latnet_modules):
    wire = latnet_modules["wire"]
    directory_mod = latnet_modules["directory"]
    hs_doc = _make_hs_descriptor_doc(latnet_modules, tmp_path)
    service_name = hs_doc["signed"]["service_name"]

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text('{"version":1,"descriptors":[]}', encoding="utf-8")
    hs_store_path = tmp_path / "hs_store.json"
    hs_store_path.write_text(json.dumps({"version": 1, "descriptors": [hs_doc]}), encoding="utf-8")

    server = directory_mod.DirectoryServer(str(bundle_path), hidden_service_store_path=str(hs_store_path))
    client_sock, server_sock = socket.socketpair()
    try:
        thread = _run_handle_conn(server, server_sock)
        wire.send_msg(client_sock, {"type": "GET_HS_DESCRIPTOR", "service_name": service_name})
        response = wire.recv_msg(client_sock)
        thread.join(timeout=1)

        assert response["ok"] is True
        assert response["service_name"] == service_name
        assert response["descriptor"] == hs_doc
    finally:
        client_sock.close()


def test_get_hidden_service_descriptor_not_found(tmp_path, latnet_modules):
    wire = latnet_modules["wire"]
    directory_mod = latnet_modules["directory"]

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text('{"version":1,"descriptors":[]}', encoding="utf-8")
    hs_store_path = tmp_path / "hs_store.json"
    hs_store_path.write_text(json.dumps({"version": 1, "descriptors": []}), encoding="utf-8")

    server = directory_mod.DirectoryServer(str(bundle_path), hidden_service_store_path=str(hs_store_path))
    client_sock, server_sock = socket.socketpair()
    try:
        thread = _run_handle_conn(server, server_sock)
        wire.send_msg(client_sock, {"type": "GET_HS_DESCRIPTOR", "service_name": "0" * 32 + ".lettuce"})
        response = wire.recv_msg(client_sock)
        thread.join(timeout=1)

        assert response["ok"] is False
        assert "hidden service descriptor not found" in response["error"]
    finally:
        client_sock.close()
