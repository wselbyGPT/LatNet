from __future__ import annotations

import json


def _json_lines(blob: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in blob.strip().splitlines() if line.strip()]


def test_event_emitter_has_stable_envelope(latnet_modules, capsys):
    obs = latnet_modules["observability"]
    emitter = obs.EventEmitter(
        component="hs.client",
        service_name="svc.lettuce",
        circuit_id="c-1",
        rendezvous_cookie="cookie-1",
    )

    emitter.emit("hs.message_sent", status="ok", payload_size=5)
    event = _json_lines(capsys.readouterr().out)[0]

    assert event["event"] == "hs.message_sent"
    assert event["status"] == "ok"
    for key in (
        "event",
        "ts",
        "component",
        "service_name",
        "circuit_id",
        "rendezvous_cookie",
        "status",
        "error_code",
    ):
        assert key in event


def test_cli_connect_emits_success_and_failure_observability(tmp_path, latnet_modules, monkeypatch, capsys):
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

    assert cli.main(["hs", "connect", service_name, str(relay_path), "--session", str(session_path)]) == 0
    events = _json_lines(capsys.readouterr().out)
    assert any(event["event"] == "hs.rdv_join_attempt" for event in events)
    joined = next(event for event in events if event["event"] == "hs.rdv_joined")
    assert joined["status"] == "ok"
    assert "join_latency_ms" in joined

    monkeypatch.setattr(runtime, "_send_circuit_cmd", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("join failed")))
    assert cli.main(["hs", "connect", service_name, str(relay_path), "--session", str(session_path)]) == 1
    failure_events = _json_lines(capsys.readouterr().out)
    error_joined = next(event for event in failure_events if event["event"] == "hs.rdv_joined")
    assert error_joined["status"] == "error"
    assert error_joined["error_code"]
    hs_error = next(event for event in failure_events if event["event"] == "hs.error")
    assert hs_error["status"] == "error"
    assert "metrics" in hs_error
