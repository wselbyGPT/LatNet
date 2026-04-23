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

## Minimal hidden-service relay-local flow (v0)

### New layer commands

`parse_layer` supports three HS-specific commands:

- `HS_INTRO`: intro relay receives a client introduction payload and forwards rendezvous routing metadata.
- `HS_RENDEZVOUS`: rendezvous relay receives service-side join payload and binds to a cookie.
- `HS_RENDEZVOUS_RELAY`: relay-local wrapper for encrypted relay-to-relay payload (`inner`).

### New relay-local envelope types

The typed envelope parser now accepts:

- `INTRODUCE`
- `RENDEZVOUS_JOIN`

These are validated with the same `type`-discriminated behavior as `BUILD` / `CELL` / `DESTROY` (`unknown message type` on mismatches).

### Field-level contract

All required fields are mandatory and must be non-empty strings unless noted.

#### `INTRODUCE` envelope

```json
{
  "type": "INTRODUCE",
  "circuit_id": "<str>",
  "service_name": "<str>",
  "rendezvous_cookie": "<str>",
  "client_ephemeral": "<str>",
  "rendezvous_relay": {
    "relay": "<str>",
    "host": "<str>",
    "port": "<int>"
  }
}
```

#### `RENDEZVOUS_JOIN` envelope

```json
{
  "type": "RENDEZVOUS_JOIN",
  "circuit_id": "<str>",
  "service_name": "<str>",
  "rendezvous_cookie": "<str>",
  "service_ephemeral": "<str>",
  "rendezvous_relay": {
    "relay": "<str>",
    "host": "<str>",
    "port": "<int>"
  }
}
```

#### HS layer payload requirements

- `HS_INTRO` requires `circuit_id`, `service_name`, `rendezvous_cookie`, `client_ephemeral`, `rendezvous_relay`.
- `HS_RENDEZVOUS` requires `circuit_id`, `service_name`, `rendezvous_cookie`, `service_ephemeral`, `rendezvous_relay`.
- `HS_RENDEZVOUS_RELAY` requires `inner` object.

Validation failures preserve parser error style: `missing or invalid field: <field>`.

### Allowed command transitions (minimal)

- Client-side intro path: `INTRODUCE` envelope -> `HS_INTRO` layer -> `HS_RENDEZVOUS_RELAY` (relay-local encapsulation).
- Service-side rendezvous path: `RENDEZVOUS_JOIN` envelope -> `HS_RENDEZVOUS` layer.
- After cookie match, relays resume regular payload forwarding via existing cell flow (`FORWARD_CELL` / `REPLY_CELL`) on bound circuits.
