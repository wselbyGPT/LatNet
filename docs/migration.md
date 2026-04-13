# Milestone import migration note

This milestone aligns modules with their canonical responsibility while keeping legacy
import paths available via re-exports.

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

Legacy paths continue to work for this milestone through compatibility shims:

- constants still available from `wire`.
- wire helpers still available from `authority`.
- crypto helpers still available from `directory`.
- directory server symbols still available from `client`.
- relay server symbols remain exported by `cli`.

These shims are intentionally temporary and should be removed in a future cleanup release.
