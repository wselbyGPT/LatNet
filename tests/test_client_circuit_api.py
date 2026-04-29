from __future__ import annotations

import time


def _make_hs_descriptor_doc(latnet_modules, tmp_path, *, valid_until_offset: int = 60, intro_offsets: list[int] | None = None):
    hs_keys = latnet_modules["hidden_service_keys"]
    util = latnet_modules["util"]

    now = int(time.time())
    service = hs_keys.generate_service_master("svc", tmp_path / "service_master.json")
    desc_signing = hs_keys.generate_descriptor_signing_key()
    cert = hs_keys.build_descriptor_signing_certificate(
        service,
        desc_signing["descriptor_signing_public_key"],
        valid_for=500,
        now=now - 10,
    )
    intro_offsets = intro_offsets or [60]
    intro_names = ["relay-z", "relay-a", "relay-b"]
    signed = {
        "service_name": service["service_name"],
        "service_master_public_key": service["service_master_public_key"],
        "descriptor_signing_public_key": desc_signing["descriptor_signing_public_key"],
        "descriptor_signing_certificate": cert,
        "valid_after": now - 5,
        "valid_until": now + valid_until_offset,
        "revision": 1,
        "period": 1,
        "introduction_points": [
            {
                "relay_name": intro_names[idx],
                "relay_addr": {"host": "127.0.0.1", "port": 9101 + idx},
                "intro_auth_pub": util.b64e(f"intro-auth-{idx}".encode("utf-8")),
                "intro_key_id": f"intro-key-{idx}",
                "expires_at": now + offset,
            }
            for idx, offset in enumerate(intro_offsets)
        ],
    }
    payload = util.canonical_bytes(signed)
    signer = hs_keys.Ed25519PrivateKey.from_private_bytes(util.b64d(desc_signing["descriptor_signing_private_key"]))
    signature = util.b64e(signer.sign(payload))
    return {"version": 2, "signed": signed, "sigalg": "ed25519", "signature": signature}


def test_build_open_data_end_destroy_flow(monkeypatch, latnet_modules):
    client = latnet_modules["client"]

    class _KEM:
        def __init__(self, _alg):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def encap_secret(self, pub):
            return (b"ct-" + pub, b"ss-" + pub)

    monkeypatch.setattr(client.oqs, "KeyEncapsulation", _KEM)

    captured = {"build": None, "cell_types": [], "destroy": None}

    def fake_send(host, port, msg):
        assert host == "127.0.0.1"
        assert port == 9001
        if msg["type"] == "BUILD":
            captured["build"] = msg
            return {"ok": True, "status": "circuit_built"}
        if msg["type"] == "CELL":
            layer = msg["layer"]
            for hop in [0, 1]:
                plain = client.decrypt_layer(circuit.hops[hop].forward_key, layer)
                assert plain["cmd"] == "FORWARD_CELL"
                layer = plain["inner"]
            exit_plain = client.decrypt_layer(circuit.hops[2].forward_key, layer)
            cell = exit_plain["cell"]
            captured["cell_types"].append(cell["cell_type"])

            if cell["cell_type"] == "BEGIN":
                reply_cell = {"stream_id": cell["stream_id"], "seq": cell["seq"], "cell_type": "CONNECTED", "payload": "ok"}
            elif cell["cell_type"] == "DATA":
                reply_cell = {
                    "stream_id": cell["stream_id"],
                    "seq": cell["seq"],
                    "cell_type": "DATA",
                    "payload": f"echo {cell['payload']}",
                }
            else:
                reply_cell = {"stream_id": cell["stream_id"], "seq": cell["seq"], "cell_type": "ENDED", "payload": "bye"}

            reply_layer = client.encrypt_layer(circuit.hops[2].reverse_key, {"cmd": "REPLY_CELL", "cell": reply_cell})
            reply_layer = client.encrypt_layer(circuit.hops[1].reverse_key, {"cmd": "RELAY_BACK", "inner": reply_layer})
            reply_layer = client.encrypt_layer(circuit.hops[0].reverse_key, {"cmd": "RELAY_BACK", "inner": reply_layer})
            return {"ok": True, "reply_layer": reply_layer}
        if msg["type"] == "DESTROY":
            captured["destroy"] = msg
            return {"ok": True, "status": "destroyed"}
        raise AssertionError("unexpected message")

    monkeypatch.setattr(client, "_send_guard_message", fake_send)

    path = [
        {"name": "g", "host": "127.0.0.1", "port": 9001, "kemalg": "ML-KEM-768", "public_key": "Zw=="},
        {"name": "m", "host": "127.0.0.1", "port": 9002, "kemalg": "ML-KEM-768", "public_key": "bQ=="},
        {"name": "e", "host": "127.0.0.1", "port": 9003, "kemalg": "ML-KEM-768", "public_key": "ZQ=="},
    ]

    circuit = client.build_circuit(path, circuit_id="cid-1")

    opened = client.open_stream(circuit, stream_id=4, target="example:443")
    echoed = client.send_stream_data(circuit, stream_id=4, payload="hello")
    ended = client.end_stream(circuit, stream_id=4, payload="done")
    destroyed = client.destroy_circuit(circuit)

    assert captured["build"]["type"] == "BUILD"
    assert captured["cell_types"] == ["BEGIN", "DATA", "END"]
    assert captured["destroy"]["type"] == "DESTROY"
    assert opened["cell_type"] == "CONNECTED"
    assert echoed["payload"] == "echo hello"
    assert ended["cell_type"] == "ENDED"
    assert destroyed["status"] == "destroyed"


def test_send_requires_open_stream(latnet_modules):
    client = latnet_modules["client"]
    circuit = client.CircuitSession(circuit_id="c", guard_host="127.0.0.1", guard_port=1, hops=[])

    try:
        client.send_stream_data(circuit, stream_id=7, payload="nope")
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "not open" in str(exc)


def test_select_intro_point_prefers_first_then_sorted_fallbacks(latnet_modules, tmp_path):
    client = latnet_modules["client"]
    descriptor = _make_hs_descriptor_doc(latnet_modules, tmp_path, intro_offsets=[90, 80, 70])

    ordered = client.order_intro_points_for_phase1(descriptor, now=int(time.time()))
    selected = client.select_intro_point_for_phase1(descriptor, now=int(time.time()))

    assert selected["relay_name"] == "relay-z"
    assert [point["relay_name"] for point in ordered] == ["relay-z", "relay-a", "relay-b"]


def test_select_intro_point_rejects_expired_descriptor(latnet_modules, tmp_path):
    client = latnet_modules["client"]
    descriptor = _make_hs_descriptor_doc(latnet_modules, tmp_path, valid_until_offset=-1, intro_offsets=[30])

    try:
        client.select_intro_point_for_phase1(descriptor, now=int(time.time()))
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert str(exc) == client.EXPIRED_DESCRIPTOR_ERROR


def test_select_intro_point_rejects_all_intro_points_expired_or_unreachable(latnet_modules, tmp_path):
    client = latnet_modules["client"]
    descriptor = _make_hs_descriptor_doc(latnet_modules, tmp_path, intro_offsets=[-1, -5, -10])

    try:
        client.order_intro_points_for_phase1(descriptor, now=int(time.time()))
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert str(exc) == client.NO_REACHABLE_INTRO_POINTS_ERROR


def test_fetch_hidden_service_descriptor_surfaces_no_descriptor_error(monkeypatch, latnet_modules):
    client = latnet_modules["client"]
    service_name = "a" * 32 + ".lettuce"

    class _FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr("socket.create_connection", lambda *_args, **_kwargs: _FakeSocket())
    monkeypatch.setattr(client, "send_msg", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(client, "recv_msg", lambda *_args, **_kwargs: {"ok": False, "error": "hidden service descriptor not found: nope"})

    try:
        client.fetch_hidden_service_descriptor_from_directory("127.0.0.1", service_name)
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert str(exc) == client.NO_DESCRIPTOR_ERROR


def test_client_flushes_cell_batch_and_maps_replies(monkeypatch, latnet_modules):
    client = latnet_modules["client"]
    circuit = client.CircuitSession(circuit_id="cid-batch", guard_host="127.0.0.1", guard_port=9001, hops=[])

    monkeypatch.setattr(client, "_wrap_forward_cell", lambda _c, cell: {"wrapped": cell})

    def fake_unwrap(_c, response):
        wrapped = response["reply_layer"]["wrapped"]
        return {"stream_id": wrapped["stream_id"], "seq": wrapped["seq"], "cell_type": "DATA", "payload": "ok"}

    monkeypatch.setattr(client, "_unwrap_reply_cell", fake_unwrap)

    def fake_send(_host, _port, msg):
        if msg["type"] != "CELL_BATCH":
            raise AssertionError("expected CELL_BATCH")
        return {
            "ok": True,
            "replies": [
                {"ok": True, "reply_layer": {"wrapped": layer["wrapped"]}}
                for layer in msg["layers"]
            ],
        }

    monkeypatch.setattr(client, "_send_guard_message", fake_send)

    circuit.cell_batcher = client.CircuitCellBatcher(flush_window_ms=9999, max_batch_size=8)
    reply_cells = client._send_batched_cells(
        circuit,
        include_current={"stream_id": 1, "seq": 1, "cell_type": "DATA", "payload": "a"},
    )
    assert reply_cells == []
    reply_cells = client._send_batched_cells(
        circuit,
        include_current={"stream_id": 1, "seq": 2, "cell_type": "DATA", "payload": "b"},
        force_flush=True,
    )
    assert [cell["seq"] for cell in reply_cells] == [1, 2]
