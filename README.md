# LatNet

## Running tests

```bash
pytest
```

## Demo command (end-to-end circuit client)

Run a full client flow (`BUILD -> BEGIN -> DATA -> END -> DESTROY`) against a relay path:

```bash
python -m latnet.demo_circuit_client relay1.json relay2.json relay3.json --stream-id 1 --target example:443 --payload hello
```

Relay JSON files must be provided in path order (guard to exit).

## Protocol documentation

- `docs/protocol_notes.md` describes stream `seq` monotonicity, relay cell command constraints, and HS event reference notes.

## Operations documentation

- `docs/operator_playbook.md` provides hidden-service bootstrap, descriptor publish/rotation, troubleshooting, and observability guidance.

## Hidden service runtime reliability tuning

The hidden service runtime now uses a reliability policy with these defaults:

- `join_timeout_s=5.0`
- `poll_interval_s=0.05`
- `max_retries=3`
- `retry_backoff_base_s=0.05`
- `retry_backoff_max_s=0.5`

Operator guidance:

- Raise `join_timeout_s` when rendezvous peer setup is slow.
- Raise `max_retries` and `retry_backoff_max_s` for unstable relay availability.
- Lower `poll_interval_s` only when you need lower latency and can tolerate higher control traffic.
- CLI commands `latnet hs serve` and `latnet hs recv` expose retry/backoff knobs for tuning in production.
