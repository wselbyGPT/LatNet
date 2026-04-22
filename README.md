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

- `docs/protocol_notes.md` describes stream `seq` monotonicity and relay cell command constraints.
