# Protocol notes

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

