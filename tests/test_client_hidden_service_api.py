from __future__ import annotations

import time

import pytest


def _make_descriptor(latnet_modules, service_name: str | None = None, intro_expiry_offset: int = 60) -> tuple[str, dict]:
    hs_keys = latnet_modules["hidden_service_keys"]
    hidden_service = latnet_modules["models.hidden_service"]
    util = latnet_modules["util"]

    service_master_public_key = util.b64e(b"service-master-pub-32-bytes-value")
    derived_name = hidden_service.derive_lettuce_name_from_b64(service_master_public_key)
    service_name = service_name or derived_name
    descriptor_signing = hs_keys.generate_descriptor_signing_key()
    now = int(time.time())
    cert = hs_keys.build_descriptor_signing_certificate(
        {
            "service_name": service_name,
            "service_master_public_key": service_master_public_key,
            "service_master_private_key": util.b64e(b"s" * 32),
        },
        descriptor_signing["descriptor_signing_public_key"],
        valid_for=120,
        now=now - 1,
    )
    signed = {
        "service_name": service_name,
        "service_master_public_key": service_master_public_key,
        "descriptor_signing_public_key": descriptor_signing["descriptor_signing_public_key"],
        "descriptor_signing_certificate": cert,
        "valid_after": now - 1,
        "valid_until": now + 60,
        "revision": 1,
        "period": 1,
        "introduction_points": [
            {
                "relay_name": "intro-a",
                "relay_addr": {"host": "127.0.0.1", "port": 9150},
                "intro_auth_pub": util.b64e(b"intro-auth-pub-1"),
                "intro_key_id": "intro-key-1",
                "expires_at": now + intro_expiry_offset,
            }
        ],
    }
    signer = hs_keys.Ed25519PrivateKey.from_private_bytes(util.b64d(descriptor_signing["descriptor_signing_private_key"]))
    descriptor = {
        "version": 2,
        "sigalg": hs_keys.HS_SIGALG,
        "signed": signed,
        "signature": util.b64e(signer.sign(util.canonical_bytes(signed))),
    }
    return service_name, descriptor


def test_descriptor_intro_selection_and_orchestration_with_monkeypatched_transport(monkeypatch, latnet_modules):
    client = latnet_modules["client"]
    runtime = latnet_modules["hidden_service_runtime"]

    service_name, descriptor = _make_descriptor(latnet_modules)

    class _FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    sent = {"msg": None}

    monkeypatch.setattr("socket.create_connection", lambda *_args, **_kwargs: _FakeSocket())
    monkeypatch.setattr(client, "send_msg", lambda _sock, msg: sent.__setitem__("msg", msg))
    monkeypatch.setattr(client, "recv_msg", lambda *_args, **_kwargs: {"ok": True, "descriptor": descriptor})

    fetched = client.fetch_hidden_service_descriptor_from_directory("127.0.0.1", service_name)
    intro = client.select_intro_point_for_phase1(fetched)

    assert sent["msg"]["type"] == "GET_HS_DESCRIPTOR"
    assert intro["relay_name"] == "intro-a"

    calls = []
    monkeypatch.setattr(runtime, "build_service_circuit", lambda *_args, **_kwargs: object())

    def _fake_send(_circuit, cmd):
        calls.append(cmd)
        if cmd["cmd"] == "RENDEZVOUS_ESTABLISH":
            return {"cmd": "RENDEZVOUS_STATE", "joined": True}
        return {"cmd": "INTRO_STORED"}

    monkeypatch.setattr(runtime, "_send_circuit_cmd", _fake_send)
    intro_circuit = runtime.build_service_circuit([{"name": "intro-a", "host": "127.0.0.1", "port": 9150, "kemalg": "ML-KEM-768", "public_key": "YQ=="}], terminal_cmd="INTRO_READY")
    rdv_circuit = runtime.build_service_circuit([{"name": "rdv", "host": "127.0.0.1", "port": 9160, "kemalg": "ML-KEM-768", "public_key": "Yg=="}], terminal_cmd="RENDEZVOUS_READY")
    runtime._send_circuit_cmd(intro_circuit, {"cmd": "INTRODUCE", "rendezvous_cookie": "cookie", "introduction": {"rendezvous_relay": {}}})
    state = runtime._send_circuit_cmd(rdv_circuit, {"cmd": "RENDEZVOUS_ESTABLISH", "rendezvous_cookie": "cookie", "side": "client"})

    assert state["joined"] is True
    assert [item["cmd"] for item in calls] == ["INTRODUCE", "RENDEZVOUS_ESTABLISH"]


def test_failure_branches_descriptor_missing_and_intro_timeout(latnet_modules):
    client = latnet_modules["client"]

    valid_name = "0123456789abcdef0123456789abcdef.lettuce"

    class _FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("socket.create_connection", lambda *_args, **_kwargs: _FakeSocket())
    monkeypatch.setattr(client, "send_msg", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(client, "recv_msg", lambda *_args, **_kwargs: {"ok": False, "error": "hidden service descriptor not found: nope"})
    try:
        with pytest.raises(ValueError, match=client.NO_DESCRIPTOR_ERROR):
            client.fetch_hidden_service_descriptor_from_directory("127.0.0.1", valid_name)
    finally:
        monkeypatch.undo()

    _service_name, descriptor = _make_descriptor(latnet_modules, intro_expiry_offset=-1)

    with pytest.raises(ValueError, match=client.NO_REACHABLE_INTRO_POINTS_ERROR):
        client.select_intro_point_for_phase1(descriptor, now=int(time.time()))


def test_failure_branch_join_timeout_returns_no_payload(monkeypatch, latnet_modules):
    runtime = latnet_modules["hidden_service_runtime"]

    fake_circuit = type("C", (), {"circuit_id": "c-timeout"})()
    monkeypatch.setattr(runtime, "establish_service_rendezvous", lambda *_args, **_kwargs: (fake_circuit, False))
    monkeypatch.setattr(runtime, "rendezvous_recv", lambda *_args, **_kwargs: None)

    result = runtime.handle_intro_request_with_echo(
        {"rendezvous_cookie": "cookie-timeout", "introduction": {"rendezvous_relay": {"name": "rdv"}}}
    )

    assert result["joined"] is False
    assert result["received_payload"] is None
    assert result["echoed_payload"] is None


def test_publish_hidden_service_descriptor_maps_error_classes(monkeypatch, latnet_modules):
    client = latnet_modules["client"]

    class _FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr("socket.create_connection", lambda *_args, **_kwargs: _FakeSocket())
    monkeypatch.setattr(client, "send_msg", lambda *_args, **_kwargs: None)

    descriptor = {
        "version": 2,
        "sigalg": "ed25519",
        "signed": {"service_name": "a" * 32 + ".lettuce"},
        "signature": "c2ln",
    }

    cases = [
        ("revision_conflict", client.PublishDescriptorRevisionConflictError),
        ("expired_descriptor", client.PublishDescriptorExpiredError),
        ("invalid_signature", client.PublishDescriptorInvalidSignatureError),
        ("unauthorized", client.PublishDescriptorUnauthorizedError),
    ]
    for error_class, exc_type in cases:
        monkeypatch.setattr(client, "recv_msg", lambda *_args, **_kwargs: {"ok": False, "error_class": error_class, "error": "nope"})
        with pytest.raises(exc_type):
            client.publish_hidden_service_descriptor_to_directory(
                "127.0.0.1",
                "a" * 32 + ".lettuce",
                descriptor,
            )
