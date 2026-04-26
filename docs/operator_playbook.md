# Operator playbook

This playbook documents day-2 operations for LatNet hidden services: bootstrap, descriptor lifecycle, rotation, incident response, and observability.

## Prerequisites and environment assumptions

- Python environment with the LatNet package available (for `python -m latnet.cli ...`).
- Running directory service reachable at `--host/--port` (defaults: `127.0.0.1:9200`).
- Signed relay descriptor JSON files for all relays referenced by hidden service descriptors.
- Hidden service material:
  - service master JSON (`--service-master`) containing `service_name`.
  - hidden service descriptor JSON (`--descriptor`) containing intro points/revision/expiry.
- Clock synchronization on operators and participating nodes (descriptor expiry handling is time-based).

Optional shell convenience alias used in examples below:

```bash
alias hs='python -m latnet.cli hs'
```

If you do not use the alias, replace `hs ...` with `python -m latnet.cli hs ...`.

## Initial service bootstrap

1. Validate descriptor availability from directory (read path):

```bash
python -m latnet.cli hs fetch my-service.lettuce --host 127.0.0.1 --port 9200
```

2. Publish descriptor (write path) before serving:

```bash
hs publish \
  --service-master ./secrets/my-service-master.json \
  --descriptor ./descriptors/my-service-descriptor.json \
  --host 127.0.0.1 --port 9200
```

3. Start service runtime with intro relays:

```bash
hs serve \
  --service-master ./secrets/my-service-master.json \
  --descriptor ./descriptors/my-service-descriptor.json \
  ./relays/guard.json ./relays/middle.json ./relays/intro.json
```

4. Client bootstrap and first message flow:

```bash
# Build rendezvous and persist client session
hs connect my-service.lettuce ./relays/rendezvous.json --session .latnet-hs.json

# Send payload
hs send --session .latnet-hs.json 'ping'

# Receive payload (single attempt)
hs recv --session .latnet-hs.json --timeout 5

# Graceful close
hs end --session .latnet-hs.json --payload 'client shutdown'
```

## Descriptor publish flow

Recommended publish sequence:

1. Prepare next descriptor with updated revision and valid expiry window.
2. Publish with optimistic concurrency using previous revision:

```bash
hs publish \
  --service-master ./secrets/my-service-master.json \
  --descriptor ./descriptors/my-service-descriptor.v2.json \
  --expected-revision 41 \
  --idempotency-key "publish-2026-04-26T1200Z" \
  --host 127.0.0.1 --port 9200
```

3. Confirm read visibility:

```bash
hs fetch my-service.lettuce --host 127.0.0.1 --port 9200
```

4. Restart/roll traffic to instances serving the new descriptor.

## Rotation cadence and safe rollout steps

Suggested regular cadence (tune for your operational risk):

- **Weekly**: review intro/rendezvous relay health and error trends.
- **Bi-weekly or monthly**: rotate descriptor revision and intro point set.
- **Quarterly**: rotate service master material per org security policy.

Safe rollout:

1. Stage and validate next descriptor in pre-prod.
2. Publish descriptor with `--expected-revision`.
3. Roll one service instance (`hs serve`) with new descriptor and observe join/message events.
4. Roll remaining instances gradually.
5. Keep previous descriptor material available for bounded rollback window.
6. Verify client flows (`hs connect/send/recv/end`) after each batch.

## Expiry windows and emergency rotation

Expiry guidance:

- Keep descriptor expiry sufficiently ahead of worst-case rollout latency.
- Avoid operating close to expiry boundary; refresh before expiry enters alert threshold.
- Monitor for fetch failures and expiry-related runtime errors.

Emergency rotation triggers:

- Suspected key compromise.
- Repeated rendezvous failures tied to specific intro/rendezvous relays.
- Imminent descriptor expiry with failed normal publish attempts.

Emergency steps:

1. Generate/prepare emergency descriptor and, if needed, new key material.
2. Publish immediately with a unique idempotency key.
3. Restart service runtimes with new descriptor.
4. Force client reconnect path (`hs connect`) where applicable.
5. Verify recovery via health checks and observability counters.

## Health checks and shutdown

### Health checks

- Read-path descriptor health:

```bash
hs fetch my-service.lettuce --host 127.0.0.1 --port 9200
```

- Runtime liveness (single service poll cycle):

```bash
hs serve \
  --service-master ./secrets/my-service-master.json \
  --descriptor ./descriptors/my-service-descriptor.json \
  ./relays/guard.json ./relays/middle.json ./relays/intro.json \
  --once
```

- End-to-end probe:

```bash
hs connect my-service.lettuce ./relays/rendezvous.json --session .latnet-hs.health.json
hs send --session .latnet-hs.health.json 'health-check'
hs recv --session .latnet-hs.health.json --timeout 5
hs end --session .latnet-hs.health.json --payload 'health-check complete'
```

### Shutdown

- Client side graceful shutdown:

```bash
hs end --session .latnet-hs.json --payload 'scheduled shutdown'
```

- Service side shutdown: stop the running `hs serve` process with SIGINT/SIGTERM and confirm final `hs.runtime_stopped` event in logs.

## Troubleshooting matrix

| Symptom | Likely cause | Remediation |
| --- | --- | --- |
| Descriptor not found | Descriptor never published; wrong `service_name`; wrong directory host/port. | Re-run `hs publish`; verify `service_name` in service master and descriptor; validate directory endpoint and retry `hs fetch`. |
| Revision conflict | `--expected-revision` is stale due to concurrent publish. | Fetch current descriptor revision, rebuild descriptor with next revision, re-run `hs publish --expected-revision <current>`. Use `--idempotency-key` for retries. |
| Expired descriptor | Descriptor expiry timestamp passed before clients fetched/used it. | Publish fresh descriptor immediately; restart `hs serve` instances on new descriptor; tighten expiry alerts and rotation lead time. |
| Rendezvous join timeout | Relay instability; too-low `join_timeout`; transient network delay. | Increase `--join-timeout`; tune `--max-retries`, `--retry-backoff-base`, `--retry-backoff-max`; rotate away from unhealthy relay descriptors. |

## Observability

LatNet hidden-service CLI emits JSON events with envelope fields:

- Required envelope fields: `event`, `ts`, `component`, `service_name`, `status`.
- Context fields (when available): `circuit_id`, `rendezvous_cookie`, `error_code`, `metrics`.

### Event names and required fields

| Event | Required fields | Notes |
| --- | --- | --- |
| `hs.runtime_started` | `event`, `ts`, `component`, `service_name`, `status`, `mode` | Runtime/process start marker. |
| `hs.intro_polled` | envelope + `mode`, `poll_count` | Intro polling progress. |
| `hs.intro_request_handled` | envelope + `mode`, `result` | Introduction handling result. |
| `hs.rdv_join_attempt` | envelope + `side` | Join initiation marker. |
| `hs.rdv_joined` | envelope + `side`, `join_latency_ms` | `status=ok|error`; include `error_code` on failures. |
| `hs.message_sent` | envelope + `command_reply` | Client send confirmation. |
| `hs.message_received` | envelope + `payload`, `received_at` | Receive confirmation. |
| `hs.runtime_stopped` | envelope + `mode`, `metrics` | Graceful stop/summary. |
| `hs.error` | envelope + `error_code`, `error` | Error surface for alerting. |

### Alert rule semantics (source-of-truth: SLO contract)

Alert definitions are versioned in `docs/hs_slo_contract.json` under `alert_rules`; treat that file as source of truth for automation and CI checks.

- **Join failure windows**
  - `join_failure_rate_warning_10m`: warning when `rdv_join_failure_rate > 0.05` in 10 minutes.
  - `join_failure_rate_critical_5m`: critical when `rdv_join_failure_rate > 0.10` in 5 minutes.
- **Intro poll failures**
  - `intro_poll_failures_consecutive_critical`: critical when one service reaches `>=3` consecutive `intro_poll` errors.
  - `intro_poll_failure_rate_warning_15m`: warning when intro-poll failures exceed `2%` of `hs.intro_polled` events in 15 minutes.
- **Repeated timeout errors per service**
  - `timeout_errors_repeated_warning_10m`: warning when one service logs `>=5` timeout errors in 10 minutes.
  - `timeout_errors_repeated_critical_10m`: critical when one service logs `>=10` timeout errors in 10 minutes.

The summarizer (`scripts/hs_slo_summary.py`) evaluates these contract rules and returns:

- `alert_evaluation.status`: overall `ok` / `warning` / `critical`.
- `alert_evaluation.rule_statuses`: status per rule name.
- `alert_evaluation.breached_rules`: breached rule-name list.

## Operational quick reference commands

```bash
# Serve
hs serve --service-master ./secrets/svc.json --descriptor ./descriptors/svc.json ./relays/a.json ./relays/b.json ./relays/c.json

# Publish
hs publish --service-master ./secrets/svc.json --descriptor ./descriptors/svc.json --expected-revision 12

# Connect / send / recv / end
hs connect my-service.lettuce ./relays/rendezvous.json --session .latnet-hs.json
hs send --session .latnet-hs.json 'hello'
hs recv --session .latnet-hs.json --timeout 5 --follow
hs end --session .latnet-hs.json --payload 'bye'
```
