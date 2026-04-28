from __future__ import annotations

import json
import time


def test_cli_hs_serve_once_invokes_runtime_and_exits(tmp_path, latnet_modules, monkeypatch, capsys):
    cli = latnet_modules["cli"]

    svc = tmp_path / "service.json"
    desc = tmp_path / "descriptor.json"
    relay_path = tmp_path / "relay.json"
    svc.write_text(json.dumps({"service_name": "dummy"}), encoding="utf-8")
    desc.write_text(json.dumps({"signed": {"service_name": "dummy"}}), encoding="utf-8")
    relay_path.write_text(
        json.dumps({"name": "intro", "host": "127.0.0.1", "port": 9001, "kemalg": "ML-KEM-768", "public_key": "YQ=="}),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        cli,
        "load_service_material",
        lambda *_args, **_kwargs: {
            "descriptor": {"signed": {"service_name": "abcdabcdabcdabcdabcdabcdabcdabcd.lettuce"}},
            "parsed_descriptor": type("Parsed", (), {"service_name": "abcdabcdabcdabcdabcdabcdabcdabcd.lettuce"})(),
        },
    )
    monkeypatch.setattr(
        cli,
        "build_intro_circuits",
        lambda *_args, **_kwargs: [{"circuit": "intro-c-1"}],
    )
    monkeypatch.setattr(cli, "poll_intro_requests", lambda *_args, **_kwargs: [])

    rc = cli.main(["hs", "serve", "--service-master", str(svc), "--descriptor", str(desc), str(relay_path), "--once"])

    assert rc == 0
    output_lines = capsys.readouterr().out.strip().splitlines()
    assert any("runtime_started" in line for line in output_lines)
    assert any("runtime_stopped" in line for line in output_lines)


def test_cli_hs_connect_send_recv_roundtrip(tmp_path, latnet_modules, monkeypatch, capsys):
    cli = latnet_modules["cli"]

    service_name = "abcdabcdabcdabcdabcdabcdabcdabcd.lettuce"
    relay_doc = {"name": "rdv", "host": "127.0.0.1", "port": 9015, "kemalg": "ML-KEM-768", "public_key": "Yg=="}
    relay_path = tmp_path / "relay.json"
    relay_path.write_text(json.dumps(relay_doc), encoding="utf-8")
    session_path = tmp_path / "hs-session.json"

    monkeypatch.setattr(
        cli,
        "fetch_hidden_service_descriptor_from_directory",
        lambda **_kwargs: {"signed": {"introduction_points": [{"relay_name": "intro", "relay_addr": {"host": "127.0.0.1", "port": 9014}, "expires_at": 9_999_999_999}]}}
    )
    monkeypatch.setattr(
        cli,
        "select_intro_point_for_phase1",
        lambda _desc: {"relay_name": "intro", "relay_addr": {"host": "127.0.0.1", "port": 9014}},
    )

    class _Circuit:
        def __init__(self, circuit_id):
            self.circuit_id = circuit_id
            self.guard_host = "127.0.0.1"
            self.guard_port = 9014
            self.forward_keys = [b"f" * 32]
            self.reverse_keys = [b"r" * 32]

    calls = {"count": 0}

    def _fake_build(_path, terminal_cmd):
        calls["count"] += 1
        return _Circuit(f"c-{terminal_cmd}-{calls['count']}")

    monkeypatch.setattr(cli, "build_service_circuit", _fake_build)
    runtime = latnet_modules["hidden_service_runtime"]
    monkeypatch.setattr(runtime, "_send_circuit_cmd", lambda *_args, **_kwargs: {"cmd": "ok", "joined": True})
    monkeypatch.setattr(cli, "rendezvous_send", lambda *_args, **_kwargs: {"cmd": "RENDEZVOUS_RELAYED"})
    monkeypatch.setattr(cli, "rendezvous_recv", lambda *_args, **_kwargs: "hello-back")

    assert (
        cli.main(
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
        == 0
    )
    assert cli.main(["hs", "send", "--session", str(session_path), "hello"]) == 0
    assert cli.main(["hs", "recv", "--session", str(session_path)]) == 0

    saved = json.loads(session_path.read_text(encoding="utf-8"))
    assert saved["service_name"] == service_name
    assert "ended_at" not in saved
    out = capsys.readouterr().out
    assert "RENDEZVOUS_RELAYED" in out
    assert '"payload": "hello-back"' in out


def test_cli_hs_end_marks_session_and_rejects_future_send(tmp_path, latnet_modules, monkeypatch):
    cli = latnet_modules["cli"]

    session_path = tmp_path / "hs-session.json"
    session_path.write_text(
        json.dumps(
            {
                "service_name": "svc.lettuce",
                "rendezvous_cookie": "cookie-1",
                "circuit": {
                    "circuit_id": "c-1",
                    "guard_host": "127.0.0.1",
                    "guard_port": 9014,
                    "forward_keys": ["Zg=="],
                    "reverse_keys": ["cg=="],
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "rendezvous_close", lambda *_args, **_kwargs: {"cmd": "RENDEZVOUS_RELAYED"})

    assert cli.main(["hs", "end", "--session", str(session_path), "--payload", "bye"]) == 0
    saved = json.loads(session_path.read_text(encoding="utf-8"))
    assert saved["end_reason"] == "user_end"
    assert saved["final_payload"] == "bye"
    assert "ended_at" in saved

    assert cli.main(["hs", "send", "--session", str(session_path), "later"]) == 1


def test_cli_hs_recv_follow_exits_on_timeout_and_interruption(tmp_path, latnet_modules, monkeypatch):
    cli = latnet_modules["cli"]
    session_path = tmp_path / "hs-session.json"
    session_path.write_text(
        json.dumps(
            {
                "service_name": "svc.lettuce",
                "rendezvous_cookie": "cookie-1",
                "circuit": {
                    "circuit_id": "c-1",
                    "guard_host": "127.0.0.1",
                    "guard_port": 9014,
                    "forward_keys": ["Zg=="],
                    "reverse_keys": ["cg=="],
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(cli, "rendezvous_recv", lambda *_args, **_kwargs: None)
    assert cli.main(["hs", "recv", "--session", str(session_path), "--follow", "--timeout", "0.01"]) == 1

    calls = {"count": 0}

    def _interrupt_after_first(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] > 1:
            raise KeyboardInterrupt()
        return None

    monkeypatch.setattr(cli, "rendezvous_recv", _interrupt_after_first)
    monkeypatch.setattr(time, "sleep", lambda *_args, **_kwargs: None)
    assert cli.main(["hs", "recv", "--session", str(session_path), "--follow", "--timeout", "5"]) == 130


def test_cli_hs_publish_invokes_client_helper(tmp_path, latnet_modules, monkeypatch, capsys):
    cli = latnet_modules["cli"]

    service = tmp_path / "service.json"
    descriptor = tmp_path / "descriptor.json"
    service_name = "abcdabcdabcdabcdabcdabcdabcdabcd.lettuce"
    service.write_text(json.dumps({"service_name": service_name}), encoding="utf-8")
    descriptor.write_text(json.dumps({"version": 2}), encoding="utf-8")

    monkeypatch.setattr(
        cli,
        "publish_hidden_service_descriptor_to_directory",
        lambda **kwargs: {"ok": True, "service_name": kwargs["service_name"], "accepted_revision": 2},
    )

    rc = cli.main(
        [
            "hs",
            "publish",
            "--service-master",
            str(service),
            "--descriptor",
            str(descriptor),
            "--host",
            "127.0.0.1",
            "--port",
            "9200",
            "--expected-revision",
            "1",
        ]
    )
    assert rc == 0
    assert '"accepted_revision": 2' in capsys.readouterr().out


def test_cli_hs_recv_outputs_structured_runtime_error(tmp_path, latnet_modules, monkeypatch, capsys):
    cli = latnet_modules["cli"]
    runtime = latnet_modules["hidden_service_runtime"]
    session_path = tmp_path / "hs-session.json"
    session_path.write_text(
        json.dumps(
            {
                "service_name": "svc.lettuce",
                "rendezvous_cookie": "cookie-1",
                "circuit": {
                    "circuit_id": "c-1",
                    "guard_host": "127.0.0.1",
                    "guard_port": 9014,
                    "forward_keys": ["Zg=="],
                    "reverse_keys": ["cg=="],
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(cli, "rendezvous_recv", lambda *_args, **_kwargs: (_ for _ in ()).throw(runtime.ProtocolMismatchError("bad")))

    rc = cli.main(["hs", "recv", "--session", str(session_path), "--follow", "--timeout", "1"])
    assert rc == 1
    out = capsys.readouterr().out
    assert '"code": "protocol_mismatch"' in out
    assert '"retriable": false' in out
