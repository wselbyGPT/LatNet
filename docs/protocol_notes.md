# Protocol notes

## Directory trust protocol versions

Directory trust transport has two protocol modes:

- **Legacy mode**: `GET_BUNDLE` returning a legacy authority bundle (**bundle v1**).
- **Consensus mode**: `GET_NETWORK_STATUS` returning signed threshold consensus (**status v2**).

### Version markers

Clients and servers use explicit trust protocol markers on trust-related directory messages:

- `GET_BUNDLE` request uses `protocol_version = 1` (`TRUST_BUNDLE_PROTOCOL_VERSION`).
- `GET_NETWORK_STATUS` request/response use `protocol_version = 2` (`TRUST_STATUS_PROTOCOL_VERSION`).

For compatibility during rollout, parsers currently treat omitted `protocol_version` as the command default (`1` for `GET_BUNDLE`, `2` for `GET_NETWORK_STATUS`).

### Client behavior matrix

| Client trust config present | Primary request | Expected mode | Fallback to legacy v1 |
| --- | --- | --- | --- |
| Yes (`trusted_authorities`, `min_signers`) | `GET_NETWORK_STATUS` | status v2 | **No** (fail closed) |
| No, but explicit legacy opt-in (`allow_legacy_single_authority = true`) | `GET_BUNDLE` | bundle v1 | N/A (already legacy path) |
| No trust config and no legacy opt-in | none | reject locally | none |

Recommended behavior:

1. Prefer `GET_NETWORK_STATUS` (v2) whenever trust config is available.
2. Only use `GET_BUNDLE` (v1) under explicit, controlled operator opt-in.
3. Treat v2 trust-validation failures as hard failures (do not silently downgrade to v1).

### Trust failure error classes

Directory/client trust verification should normalize failures into structured `error_class` values:

- `insufficient_quorum`: not enough trusted authority votes/signatures to satisfy threshold policy.
- `expired_status`: network status validity interval has elapsed.
- `unknown_authority`: signer identity is not in the trusted authority set.
- `invalid_signature_set`: malformed/duplicate/inconsistent signatures or signer key material mismatch.

## Stream sequence numbers (`seq`)

Exit relays apply sequence validation independently per `(circuit_id, stream_id)`.

- `BEGIN` MUST start a new stream with `seq = 1`.
- After `BEGIN`, accepted cells (`DATA` / `END`) MUST increase by exactly `+1` each time.
- A repeated sequence number is treated as a replay and rejected.
- A lower-than-expected sequence number is treated as stale / out-of-order and rejected.
- A higher-than-expected sequence number is treated as skipped / out-of-order and rejected.
- Sequence validation state is retained after `END` so replayed `END` or `DATA` cells are still rejected explicitly.
- Sequence windows are tracked per stream, so interleaving multiple stream IDs on the same circuit is valid as long as each stream is monotonic.

On sequence violations, exit relays return an explicit `ERROR` reply cell with the offending `stream_id` and `seq`.

## Cell command constraints in forward relays

Forward relays only accept decrypted cell layers with `cmd = FORWARD_CELL` and require a wrapped inner encrypted layer containing `nonce` and `ct`. Invalid command forms are rejected before forwarding to the next hop.

## Hidden-service observability events

The CLI hidden-service flows now emit JSON lines with a standard envelope:
`event`, `ts`, `component`, `service_name`, `circuit_id`, `rendezvous_cookie`, `status`, `error_code`.

| Event name | Typical status | Extra fields |
| --- | --- | --- |
| `hs.runtime_started` | `ok` | `mode`, `intro_circuits` |
| `hs.intro_polled` | `ok` | `mode`, `poll_count` |
| `hs.intro_request_handled` | `ok` | `mode`, `result` |
| `hs.rdv_join_attempt` | `ok` | `side` |
| `hs.rdv_joined` | `ok` / `error` | `side`, `join_latency_ms` |
| `hs.message_sent` | `ok` | `command_reply`, `metrics` |
| `hs.message_received` | `ok` | `payload`, `received_at` |
| `hs.runtime_stopped` | `ok` | `mode`, `metrics` |
| `hs.error` | `error` | `error`, `metrics` |

Runtime summary metrics are emitted in the `metrics` field on shutdown events, including intro request counts, rendezvous join success/failure and latency stats, and relay command failures by error type.

## Operations documentation

- `docs/operator_playbook.md` is the primary operator runbook for hidden service bootstrap, publish/rotation, troubleshooting, and alert thresholds.

## Fixed-size stream cell payload format

Stream cells now carry a protocol-level encoded payload envelope:

- `padded_len`: required fixed payload budget in bytes (`CELL_PAYLOAD_BYTES`).
- `payload_b64`: base64 representation of the unpadded payload bytes.
- `is_padding` (optional): marks intentionally empty/padding-only payloads.

Compatibility behavior:

- Parsers accept legacy cells that only include `payload` and synthesize `payload_b64` for backward compatibility.
- Parsers reject any `padded_len` other than the configured `CELL_PAYLOAD_BYTES`.
- Clients/relays enforce payload byte budget pre-encryption and reject oversize payloads.
- Padding is stripped only at the terminal consumer when decoding `payload_b64` into application `payload` text.
