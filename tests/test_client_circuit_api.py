from __future__ import annotations


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
