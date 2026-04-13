from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]





def _install_cryptography_stub() -> None:
    cryptography = types.ModuleType("cryptography")
    hazmat = types.ModuleType("cryptography.hazmat")
    primitives = types.ModuleType("cryptography.hazmat.primitives")
    ciphers = types.ModuleType("cryptography.hazmat.primitives.ciphers")
    aead = types.ModuleType("cryptography.hazmat.primitives.ciphers.aead")
    asymmetric = types.ModuleType("cryptography.hazmat.primitives.asymmetric")
    ed25519 = types.ModuleType("cryptography.hazmat.primitives.asymmetric.ed25519")
    serialization = types.ModuleType("cryptography.hazmat.primitives.serialization")

    class AESGCM:
        def __init__(self, key: bytes):
            self.key = key

        def encrypt(self, nonce: bytes, pt: bytes, _aad):
            return pt

        def decrypt(self, nonce: bytes, ct: bytes, _aad):
            return ct

    class _Pub:
        def __init__(self, data: bytes = b"p" * 32):
            self.data = data

        def public_bytes(self, _encoding, _format):
            return self.data

        def verify(self, _sig: bytes, _msg: bytes):
            return None

    class _Priv:
        def __init__(self, data: bytes = b"s" * 32):
            self.data = data

        @classmethod
        def generate(cls):
            return cls()

        @classmethod
        def from_private_bytes(cls, data: bytes):
            return cls(data)

        def private_bytes(self, _encoding, _format, _encryption):
            return self.data

        def public_key(self):
            return _Pub()

        def sign(self, msg: bytes):
            return b"sig:" + msg[:8]

    class Ed25519PublicKey:
        @classmethod
        def from_public_bytes(cls, data: bytes):
            return _Pub(data)

    class Ed25519PrivateKey:
        generate = _Priv.generate
        from_private_bytes = _Priv.from_private_bytes

    aead.AESGCM = AESGCM
    ed25519.Ed25519PrivateKey = Ed25519PrivateKey
    ed25519.Ed25519PublicKey = Ed25519PublicKey

    serialization.Encoding = types.SimpleNamespace(Raw=object())
    serialization.PublicFormat = types.SimpleNamespace(Raw=object())
    serialization.PrivateFormat = types.SimpleNamespace(Raw=object())
    serialization.NoEncryption = lambda: object()

    sys.modules.setdefault("cryptography", cryptography)
    sys.modules.setdefault("cryptography.hazmat", hazmat)
    sys.modules.setdefault("cryptography.hazmat.primitives", primitives)
    sys.modules.setdefault("cryptography.hazmat.primitives.ciphers", ciphers)
    sys.modules.setdefault("cryptography.hazmat.primitives.ciphers.aead", aead)
    sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric", asymmetric)
    sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric.ed25519", ed25519)
    sys.modules.setdefault("cryptography.hazmat.primitives.serialization", serialization)


class _DummyKeyEncapsulation:
    def __init__(self, *_args, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def generate_keypair(self):
        return b"dummy-public"

    def export_secret_key(self):
        return b"dummy-secret"


def _load_module(module_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def latnet_modules():
    pkg_name = "latnet"
    pkg = types.ModuleType(pkg_name)
    pkg.__path__ = [str(REPO_ROOT)]
    sys.modules[pkg_name] = pkg

    _install_cryptography_stub()

    oqs_stub = types.ModuleType("oqs")
    oqs_stub.KeyEncapsulation = _DummyKeyEncapsulation
    sys.modules.setdefault("oqs", oqs_stub)

    constants = _load_module("latnet.constants", REPO_ROOT / "constants.py")
    util = _load_module("latnet.util", REPO_ROOT / "util.py")
    wire = _load_module("latnet.wire", REPO_ROOT / "wire.py")
    crypto = _load_module("latnet.crypto", REPO_ROOT / "crypto.py")
    authority = _load_module("latnet.authority", REPO_ROOT / "authority.py")
    directory = _load_module("latnet.directory", REPO_ROOT / "directory.py")
    client = _load_module("latnet.client", REPO_ROOT / "client.py")
    relay = _load_module("latnet.relay", REPO_ROOT / "relay.py")
    cli = _load_module("latnet.cli", REPO_ROOT / "cli.py")

    return {
        "constants": constants,
        "util": util,
        "wire": wire,
        "crypto": crypto,
        "authority": authority,
        "directory": directory,
        "client": client,
        "relay": relay,
        "cli": cli,
    }


@pytest.fixture
def relay_doc_fixture():
    return {
        "name": "relay-test",
        "host": "127.0.0.1",
        "port": 9999,
        "kemalg": "ML-KEM-768",
        "public_key": "ZmFrZS1wdWJsaWMta2V5",
        "secret_key": "ZmFrZS1zZWNyZXQta2V5",
    }


@pytest.fixture
def mock_key_material(latnet_modules):
    b64e = latnet_modules["util"].b64e
    return {
        "forward": b"F" * 32,
        "reverse": b"R" * 32,
        "forward_b64": b64e(b"F" * 32),
        "reverse_b64": b64e(b"R" * 32),
    }
