# Milestone import migration note

This milestone aligns modules with their canonical responsibility.

## Canonical modules

- `constants`: protocol and runtime constants.
- `wire`: framing helpers (`send_msg`, `recv_msg`).
- `authority`: authority signing and verification.
- `relay`: relay server state machine and relay bootstrap helpers.
- `crypto`: hop key derivation and AEAD layer wrapping.
- `directory`: directory server runtime.
- `client`: directory client fetch helpers.
- `cli`: consolidated public CLI-facing entrypoint exports.

## Backward compatibility

Legacy compatibility re-exports were temporary for migration and have now been removed.
Callers should import from canonical modules listed above.
