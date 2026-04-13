from __future__ import annotations


def test_service_name_derivation_from_master_public_is_stable(latnet_modules):
    hs_keys = latnet_modules["hidden_service_keys"]

    private_key = hs_keys.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(hs_keys.Encoding.Raw, hs_keys.PublicFormat.Raw)

    name_a = hs_keys.derive_service_name_from_master_public(public_key)
    name_b = hs_keys.derive_service_name_from_master_public(public_key)

    assert name_a == name_b
    assert name_a.endswith(".lettuce")


def test_descriptor_signing_certificate_verify_success(latnet_modules, tmp_path):
    hs_keys = latnet_modules["hidden_service_keys"]

    service = hs_keys.generate_service_master("svc", tmp_path / "service_master.json")
    desc_key = hs_keys.generate_descriptor_signing_key()

    cert = hs_keys.build_descriptor_signing_certificate(
        service,
        desc_key["descriptor_signing_public_key"],
        valid_for=60,
        now=1_000,
    )
    signed = hs_keys.verify_descriptor_signing_certificate(cert, now=1_010)

    assert signed["service_name"] == service["service_name"]
    assert signed["descriptor_signing_public_key"] == desc_key["descriptor_signing_public_key"]


def test_hidden_service_descriptor_v2_verify_success(latnet_modules, tmp_path):
    hs_keys = latnet_modules["hidden_service_keys"]
    hs_desc = latnet_modules["models.hidden_service_descriptor"]

    service = hs_keys.generate_service_master("svc", tmp_path / "service_master.json")
    desc_key = hs_keys.generate_descriptor_signing_key()
    cert = hs_keys.build_descriptor_signing_certificate(
        service,
        desc_key["descriptor_signing_public_key"],
        valid_for=120,
        now=5_000,
    )

    signed = {
        "service_name": service["service_name"],
        "service_master_public_key": service["service_master_public_key"],
        "descriptor_signing_public_key": desc_key["descriptor_signing_public_key"],
        "descriptor_signing_certificate": cert,
        "valid_after": 5_000,
        "valid_until": 5_060,
        "revision": 1,
        "period": 5,
        "introduction_points": [
            {
                "relay_name": "relay-a",
                "relay_addr": {"host": "127.0.0.1", "port": 9001},
                "intro_auth_pub": latnet_modules["util"].b64e(b"intro-auth-pub"),
                "intro_key_id": "intro-key-1",
                "expires_at": 5_060,
            }
        ],
    }

    signer = hs_keys.Ed25519PrivateKey.from_private_bytes(
        latnet_modules["util"].b64d(desc_key["descriptor_signing_private_key"])
    )
    doc = {
        "version": 2,
        "sigalg": hs_keys.HS_SIGALG,
        "signed": signed,
        "signature": latnet_modules["util"].b64e(signer.sign(latnet_modules["util"].canonical_bytes(signed))),
    }

    parsed = hs_desc.verify_hidden_service_descriptor_v2(doc, now=5_010)

    assert parsed.service_name == service["service_name"]
    assert parsed.revision == 1


def test_hidden_service_descriptor_v2_rejects_mismatched_service_name(latnet_modules, tmp_path):
    import pytest

    hs_keys = latnet_modules["hidden_service_keys"]
    hs_desc = latnet_modules["models.hidden_service_descriptor"]

    service = hs_keys.generate_service_master("svc", tmp_path / "service_master.json")
    desc_key = hs_keys.generate_descriptor_signing_key()
    cert = hs_keys.build_descriptor_signing_certificate(
        service,
        desc_key["descriptor_signing_public_key"],
        valid_for=120,
        now=10_000,
    )

    signed = {
        "service_name": "0" * 32 + ".lettuce",
        "service_master_public_key": service["service_master_public_key"],
        "descriptor_signing_public_key": desc_key["descriptor_signing_public_key"],
        "descriptor_signing_certificate": cert,
        "valid_after": 10_000,
        "valid_until": 10_060,
        "revision": 1,
        "period": 10,
        "introduction_points": [
            {
                "relay_name": "relay-a",
                "relay_addr": {"host": "127.0.0.1", "port": 9001},
                "intro_auth_pub": latnet_modules["util"].b64e(b"intro-auth-pub"),
                "intro_key_id": "intro-key-1",
                "expires_at": 10_060,
            }
        ],
    }

    signer = hs_keys.Ed25519PrivateKey.from_private_bytes(
        latnet_modules["util"].b64d(desc_key["descriptor_signing_private_key"])
    )
    doc = {
        "version": 2,
        "sigalg": hs_keys.HS_SIGALG,
        "signed": signed,
        "signature": latnet_modules["util"].b64e(signer.sign(latnet_modules["util"].canonical_bytes(signed))),
    }

    with pytest.raises(ValueError, match="missing or invalid field: service_name"):
        hs_desc.verify_hidden_service_descriptor_v2(doc, now=10_010)
