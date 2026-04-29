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


## HS SLO summary utility

Use `scripts/hs_slo_summary.py` to parse newline-delimited JSON observability events with `docs/hs_slo_contract.json` and emit SLO summary metrics.

```bash
python scripts/hs_slo_summary.py --events artifacts/hs_events_last_24h.jsonl --contract docs/hs_slo_contract.json --format text
```

CI example (fail build when rendezvous join success rate drops below 99%):

```bash
python scripts/hs_slo_summary.py --events artifacts/hs_events_last_24h.jsonl --contract docs/hs_slo_contract.json --format json   | python -c 'import json,sys; d=json.load(sys.stdin); s=d["rdv_join_success_rate"] or 0; sys.exit(0 if s>=0.99 else 1)'
```

## Guard state persistence

LatNet now persists client guard-selection state in `.latnet-guards.json` (override with `--guard-state`). The file tracks pinned guards, first_seen/last_success timestamps, failure/quarantine metadata, and the active guard pointer. During `circuit build --policy first_valid`, hop 0 prefers healthy pinned guards before admitting new candidates.

Policy parameters are stored in the guard state under `policy`: `max_pinned_guards`, `rotation_interval_s`, `failure_threshold`, `cooldown_s`, and `forced_refresh_s`.

Admin operations:
- `latnet admin guard-state view [--guard-state PATH]`
- `latnet admin guard-state reset [--guard-state PATH]`


## WSL deploy dependency note (OQS bindings)

`deploy_wsl.sh` expects the liboqs-backed Python module that exposes `oqs.KeyEncapsulation`.
If deploy fails with `AttributeError: module 'oqs' has no attribute 'KeyEncapsulation'`, your venv usually has the wrong package.

Typical fix inside your active venv:

```bash
pip uninstall -y oqs
pip install oqs-python
```

Then rerun:

```bash
./deploy_wsl.sh
```
