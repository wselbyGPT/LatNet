from __future__ import annotations


def test_canonical_import_surface(latnet_modules):
    expected = {
        "authority": {"sign_relay_file", "verify_descriptor", "make_bundle_file"},
        "relay": {"RelayServer", "run_relay_server", "init_relay_file"},
        "wire": {"send_msg", "recv_msg"},
        "crypto": {"encrypt_layer", "decrypt_layer", "derive_hop_keys"},
        "directory": {"DirectoryServer", "run_directory_server"},
        "client": {"fetch_bundle_from_directory", "fetch_bundle_to_file"},
        "cli": {"run_relay_server", "run_directory_server", "sign_relay_file"},
    }

    for module_name, symbols in expected.items():
        module = latnet_modules[module_name]
        for symbol in symbols:
            assert hasattr(module, symbol), f"{module_name} missing {symbol}"


def test_removed_deprecated_import_paths(latnet_modules):
    assert not hasattr(latnet_modules["wire"], "KEMALG")
    assert not hasattr(latnet_modules["authority"], "send_msg")
    assert not hasattr(latnet_modules["directory"], "encrypt_layer")
    assert not hasattr(latnet_modules["client"], "DirectoryServer")
    assert hasattr(latnet_modules["cli"], "RelayServer")
