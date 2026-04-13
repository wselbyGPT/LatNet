from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


class _DummyKeyEncapsulation:
    def __init__(self, *_args, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _TestCryptoModule(types.ModuleType):
    @staticmethod
    def encrypt_layer(_key: bytes, obj: dict):
        blob = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return {"nonce": "", "ct": blob.decode("utf-8")}

    @staticmethod
    def decrypt_layer(_key: bytes, wrapped: dict):
        return json.loads(wrapped["ct"])

    @staticmethod
    def derive_hop_keys(_shared_secret: bytes, _circuit_id: str, _hop_name: str):
        return (b"F" * 32, b"R" * 32)


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

    oqs_stub = types.ModuleType("oqs")
    oqs_stub.KeyEncapsulation = _DummyKeyEncapsulation
    sys.modules.setdefault("oqs", oqs_stub)

    constants = _load_module("latnet.constants", REPO_ROOT / "wire.py")
    util = _load_module("latnet.util", REPO_ROOT / "crypto.py")
    wire = _load_module("latnet.wire", REPO_ROOT / "authority.py")

    crypto_stub = _TestCryptoModule("latnet.crypto")
    sys.modules["latnet.crypto"] = crypto_stub

    directory_server = _load_module("latnet.client", REPO_ROOT / "client.py")
    relay = _load_module("latnet.cli", REPO_ROOT / "cli.py")

    return {
        "constants": constants,
        "util": util,
        "wire": wire,
        "crypto": crypto_stub,
        "directory": directory_server,
        "relay": relay,
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
