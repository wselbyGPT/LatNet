# Import surface map

Expected top-level symbols by logical module for this milestone:

- `authority`
  - `authority_key_id_from_public`
  - `load_authority`, `load_authority_public`
  - `init_authority_file`, `export_authority_pub_file`
  - `signable_descriptor_payload`, `sign_relay_file`
  - `descriptor_relay_view`, `verify_descriptor`, `verify_bundle`, `make_bundle_file`
- `relay`
  - `init_relay_file`, `RelayServer`, `run_relay_server`
- `wire`
  - `send_msg`, `recv_msg`
- `crypto`
  - `hkdf_extract`, `hkdf_expand`, `derive_aead_key`, `derive_hop_keys`
  - `encrypt_layer`, `decrypt_layer`
- `directory`
  - `DirectoryServer`, `run_directory_server`
- `client`
  - `fetch_bundle_from_directory`, `fetch_bundle_to_file`
- `cli`
  - re-exported operational entrypoints from authority, relay, directory, and client modules
