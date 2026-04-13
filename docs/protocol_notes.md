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
