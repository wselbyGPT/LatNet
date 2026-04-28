from __future__ import annotations

import json


def test_cli_circuit_build_writes_session(tmp_path, latnet_modules, monkeypatch, capsys):
    cli = latnet_modules["cli"]
    client = latnet_modules["client"]

    relay_path = tmp_path / "relay.json"
    relay_path.write_text(json.dumps({"name": "r1", "host": "127.0.0.1", "port": 9001, "kemalg": "ML-KEM-768", "public_key": "cA=="}))
    session_path = tmp_path / "session.json"

    def _fake_build(path_of_relays, circuit_id=None):
        assert path_of_relays[0]["name"] == "r1"
        return client.CircuitSession(
            circuit_id=circuit_id or "cid-1",
            guard_host="127.0.0.1",
            guard_port=9001,
            hops=[
                client.HopSession(
                    name="r1",
                    host="127.0.0.1",
                    port=9001,
                    forward_key=b"f" * 32,
                    reverse_key=b"r" * 32,
                )
            ],
        )

    monkeypatch.setattr(cli, "build_circuit", _fake_build)

    rc = cli.main(["circuit", "build", str(relay_path), "--session", str(session_path)])

    assert rc == 0
    session_json = json.loads(session_path.read_text())
    assert session_json["circuit_id"] == "cid-1"
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is True


def test_cli_stream_send_updates_session(tmp_path, latnet_modules, monkeypatch, capsys):
    cli = latnet_modules["cli"]

    session_path = tmp_path / "session.json"
    session_path.write_text(
        json.dumps(
            {
                "circuit_id": "cid-1",
                "guard_host": "127.0.0.1",
                "guard_port": 9001,
                "hops": [
                    {
                        "name": "r1",
                        "host": "127.0.0.1",
                        "port": 9001,
                        "forward_key": "ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY=",
                        "reverse_key": "cnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnI=",
                    }
                ],
                "stream_next_seq": {"5": 9},
            }
        )
    )

    def _fake_send(circuit, stream_id, payload):
        assert stream_id == 5
        assert payload == "hello"
        circuit.stream_next_seq[stream_id] = 10
        return {"cell_type": "DATA", "payload": "ok"}

    monkeypatch.setattr(cli, "send_stream_data", _fake_send)

    rc = cli.main(["stream", "send", "--session", str(session_path), "--stream-id", "5", "hello"])

    assert rc == 0
    session_json = json.loads(session_path.read_text())
    assert session_json["stream_next_seq"]["5"] == 10
    output = json.loads(capsys.readouterr().out)
    assert output["cell_type"] == "DATA"


def test_cli_hs_fetch_to_file(tmp_path, latnet_modules, monkeypatch, capsys):
    cli = latnet_modules["cli"]

    out_path = tmp_path / "desc.json"

    expected = {"version": 2, "service_name": "abcdabcdabcdabcdabcdabcdabcdabcd.lettuce"}

    def _fake_fetch(*, host, port, service_name):
        assert host == "10.1.1.1"
        assert port == 9300
        assert service_name == expected["service_name"]
        return expected

    monkeypatch.setattr(cli, "fetch_hidden_service_descriptor_from_directory", _fake_fetch)

    rc = cli.main(
        [
            "hs",
            "fetch",
            expected["service_name"],
            "--host",
            "10.1.1.1",
            "--port",
            "9300",
            "--out",
            str(out_path),
        ]
    )

    assert rc == 0
    assert json.loads(out_path.read_text()) == expected
    assert json.loads(capsys.readouterr().out) == expected


def test_cli_hs_connect_persists_session(tmp_path, latnet_modules, monkeypatch, capsys):
    cli = latnet_modules["cli"]

    service_name = "abcdabcdabcdabcdabcdabcdabcdabcd.lettuce"
    relay_path = tmp_path / "relay.json"
    relay_doc = {"name": "rdv", "host": "127.0.0.1", "port": 9010, "kemalg": "ML-KEM-768", "public_key": "cA=="}
    relay_path.write_text(json.dumps(relay_doc))
    session_path = tmp_path / "hs-session.json"

    monkeypatch.setattr(
        cli,
        "fetch_hidden_service_descriptor_from_directory",
        lambda **_kwargs: {
            "signed": {
                "introduction_points": [
                    {"relay_name": "intro", "relay_addr": {"host": "127.0.0.1", "port": 9009}, "expires_at": 9999999999}
                ]
            }
        },
    )
    monkeypatch.setattr(
        cli,
        "select_intro_point_for_phase1",
        lambda _descriptor: {"relay_name": "intro", "relay_addr": {"host": "127.0.0.1", "port": 9009}},
    )

    class _Circuit:
        def __init__(self, circuit_id):
            self.circuit_id = circuit_id
            self.guard_host = "127.0.0.1"
            self.guard_port = 9009
            self.forward_keys = [b"f" * 32]
            self.reverse_keys = [b"r" * 32]

    calls = {"i": 0}

    def _fake_build(_path, terminal_cmd):
        calls["i"] += 1
        return _Circuit(f"c-{terminal_cmd}-{calls['i']}")

    monkeypatch.setattr(cli, "build_service_circuit", _fake_build)

    runtime = latnet_modules["hidden_service_runtime"]
    monkeypatch.setattr(runtime, "_send_circuit_cmd", lambda *_args, **_kwargs: {"cmd": "ok"})

    rc = cli.main(
        [
            "hs",
            "connect",
            service_name,
            str(relay_path),
            "--session",
            str(session_path),
            "--allow-legacy-single-authority",
        ]
    )

    assert rc == 0
    session_json = json.loads(session_path.read_text())
    assert session_json["service_name"] == service_name
    assert session_json["mode"] == "client"
    output = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert output["event"] == "hs.runtime_stopped"
    assert output["status"] == "ok"


def test_cli_hs_send_and_end_use_session(tmp_path, latnet_modules, monkeypatch, capsys):
    cli = latnet_modules["cli"]

    session_path = tmp_path / "hs-session.json"
    session_path.write_text(
        json.dumps(
            {
                "mode": "client",
                "service_name": "abcdabcdabcdabcdabcdabcdabcdabcd.lettuce",
                "rendezvous_cookie": "cookie-1",
                "circuit": {
                    "circuit_id": "c-1",
                    "guard_host": "127.0.0.1",
                    "guard_port": 9010,
                    "forward_keys": ["ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY="],
                    "reverse_keys": ["cnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnI="],
                },
            }
        )
    )

    monkeypatch.setattr(cli, "rendezvous_send", lambda *_args, **_kwargs: {"cmd": "RENDEZVOUS_RELAYED"})
    monkeypatch.setattr(cli, "rendezvous_close", lambda *_args, **_kwargs: {"cmd": "RENDEZVOUS_RELAYED"})

    rc_send = cli.main(["hs", "send", "--session", str(session_path), "hello"])
    rc_end = cli.main(["hs", "end", "--session", str(session_path), "--payload", "done"])

    assert rc_send == 0
    assert rc_end == 0
    session_json = json.loads(session_path.read_text())
    assert "ended_at" in session_json
    outputs = capsys.readouterr().out.strip().splitlines()
    assert "RENDEZVOUS_RELAYED" in "\n".join(outputs)
