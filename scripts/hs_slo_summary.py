#!/usr/bin/env python3
"""Summarize hidden-service SLO signals from JSONL events.

Reads newline-delimited JSON events either from a file path or stdin,
loads an SLO contract mapping JSON file, and computes:

- rendezvous join success rate
- join latency p95 from successful ``hs.rdv_joined`` samples
- timeout counts grouped by ``error_code``

Examples:
    # Human-readable output from a JSONL file artifact.
    python scripts/hs_slo_summary.py \
      --events artifacts/hs_events_last_24h.jsonl \
      --contract docs/hs_slo_contract.json \
      --format text

    # Machine-readable JSON for CI gate checks.
    python scripts/hs_slo_summary.py \
      --events artifacts/hs_events_last_24h.jsonl \
      --contract docs/hs_slo_contract.json \
      --format json > hs_slo_summary.json

    # Example CI threshold gate: fail if join success rate < 99%.
    python scripts/hs_slo_summary.py --events artifacts/hs_events_last_24h.jsonl \
      --contract docs/hs_slo_contract.json --format json \
      | python -c 'import json,sys; d=json.load(sys.stdin); s=d["rdv_join_success_rate"] or 0; sys.exit(0 if s>=0.99 else 1)'
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


Event = dict[str, Any]


def _load_contract(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _iter_events(events_path: str | None) -> Iterable[Event]:
    stream = sys.stdin if events_path in (None, "-") else Path(events_path).open("r", encoding="utf-8")
    with stream:
        for line_no, raw_line in enumerate(stream, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at line {line_no}: {exc}") from exc
            if isinstance(event, dict):
                yield event


def _matches(event: Event, selector: dict[str, Any]) -> bool:
    for key, expected in selector.items():
        if event.get(key) != expected:
            return False
    return True


def _p95(samples: list[float]) -> float | None:
    if not samples:
        return None
    values = sorted(samples)
    rank = max(1, math.ceil(0.95 * len(values)))
    return values[rank - 1]


def _parse_ts(raw_ts: Any) -> datetime | None:
    if not isinstance(raw_ts, str) or not raw_ts:
        return None

    value = raw_ts
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _in_window(event_ts: datetime | None, window_start: datetime | None, window_end: datetime | None) -> bool:
    if window_start is None or window_end is None:
        return True
    if event_ts is None:
        return False
    return window_start <= event_ts <= window_end


def _compare(actual: float, operator: str, threshold: float) -> bool:
    if operator == ">":
        return actual > threshold
    if operator == ">=":
        return actual >= threshold
    if operator == "<":
        return actual < threshold
    if operator == "<=":
        return actual <= threshold
    raise ValueError(f"Unsupported operator: {operator}")


def summarize(events: Iterable[Event], contract: dict[str, Any]) -> dict[str, Any]:
    events_list = list(events)
    selectors = contract.get("event_selectors", {})
    success_selector = selectors.get("rdv_join_success", {"event": "hs.rdv_joined", "status": "ok"})
    failure_selector = selectors.get("rdv_join_failure", {"event": "hs.rdv_joined", "status": "error"})

    success_total = 0
    failure_total = 0
    join_latency_samples: list[float] = []
    timeout_counts: Counter[str] = Counter()

    for event in events_list:
        if _matches(event, success_selector):
            success_total += 1
            latency = event.get("join_latency_ms")
            if isinstance(latency, (int, float)):
                join_latency_samples.append(float(latency))

        if _matches(event, failure_selector):
            failure_total += 1

        if event.get("event") == "hs.error" and event.get("status") == "error":
            error_code = event.get("error_code")
            if isinstance(error_code, str) and error_code:
                timeout_counts[error_code] += 1

    attempts = success_total + failure_total
    success_rate = None if attempts == 0 else success_total / attempts

    summary = {
        "contract_version": contract.get("contract_version"),
        "rdv_join_success_total": success_total,
        "rdv_join_failure_total": failure_total,
        "rdv_join_success_rate": success_rate,
        "rdv_join_latency_p95_ms": _p95(join_latency_samples),
        "rdv_join_latency_samples": len(join_latency_samples),
        "timeout_counts_by_error_code": dict(sorted(timeout_counts.items())),
    }
    summary["alert_evaluation"] = _evaluate_alert_rules(events_list, contract)
    return summary


def _evaluate_alert_rules(events: list[Event], contract: dict[str, Any]) -> dict[str, Any]:
    alert_rules: dict[str, dict[str, Any]] = contract.get("alert_rules", {})
    if not alert_rules:
        return {"status": "ok", "breached_rules": [], "rule_statuses": {}}

    parsed_events: list[tuple[Event, datetime | None]] = [(event, _parse_ts(event.get("ts"))) for event in events]
    known_ts = [parsed for _, parsed in parsed_events if parsed is not None]
    window_end = max(known_ts) if known_ts else None

    rule_statuses: dict[str, str] = {}
    breached_rules: list[str] = []

    for rule_name, rule in alert_rules.items():
        window_minutes = int(rule.get("window_minutes", 0))
        window_start = None if window_end is None else window_end - timedelta(minutes=window_minutes)
        metric = str(rule.get("metric"))
        operator = str(rule.get("operator", ">"))
        threshold = float(rule.get("threshold", 0))

        metric_value = _metric_value(metric, parsed_events, window_start, window_end)
        breached = _compare(metric_value, operator, threshold)
        if breached:
            severity = str(rule.get("severity", "warning"))
            rule_statuses[rule_name] = severity
            breached_rules.append(rule_name)
        else:
            rule_statuses[rule_name] = "ok"

    overall_status = "ok"
    if any(status == "critical" for status in rule_statuses.values()):
        overall_status = "critical"
    elif any(status == "warning" for status in rule_statuses.values()):
        overall_status = "warning"

    return {
        "status": overall_status,
        "breached_rules": sorted(breached_rules),
        "rule_statuses": dict(sorted(rule_statuses.items())),
    }


def _metric_value(
    metric: str,
    events: list[tuple[Event, datetime | None]],
    window_start: datetime | None,
    window_end: datetime | None,
) -> float:
    window_events = [event for event, ts in events if _in_window(ts, window_start, window_end)]

    if metric == "rdv_join_failure_rate":
        success = sum(1 for event in window_events if event.get("event") == "hs.rdv_joined" and event.get("status") == "ok")
        failure = sum(1 for event in window_events if event.get("event") == "hs.rdv_joined" and event.get("status") == "error")
        attempts = success + failure
        return 0.0 if attempts == 0 else failure / attempts

    if metric == "intro_poll_failures_consecutive_max":
        max_streak_by_service: dict[str, int] = {}
        streak_by_service: dict[str, int] = {}
        ordered = sorted(events, key=lambda item: item[1] or datetime.min.replace(tzinfo=timezone.utc))
        for event, ts in ordered:
            if not _in_window(ts, window_start, window_end):
                continue
            service = str(event.get("service_name", "unknown"))
            if event.get("event") == "hs.error" and event.get("status") == "error" and event.get("error_code") == "intro_poll":
                streak_by_service[service] = streak_by_service.get(service, 0) + 1
                max_streak_by_service[service] = max(max_streak_by_service.get(service, 0), streak_by_service[service])
            elif event.get("event") == "hs.intro_polled" and event.get("status") == "ok":
                streak_by_service[service] = 0
        return float(max(max_streak_by_service.values(), default=0))

    if metric == "intro_poll_failure_rate":
        failures = sum(
            1
            for event in window_events
            if event.get("event") == "hs.error" and event.get("status") == "error" and event.get("error_code") == "intro_poll"
        )
        polls = sum(1 for event in window_events if event.get("event") == "hs.intro_polled")
        return 0.0 if polls == 0 else failures / polls

    if metric == "timeout_error_count_max_per_service":
        counter: Counter[str] = Counter()
        for event in window_events:
            if event.get("event") == "hs.error" and event.get("status") == "error" and event.get("error_code") == "timeout":
                service = str(event.get("service_name", "unknown"))
                counter[service] += 1
        return float(max(counter.values(), default=0))

    raise ValueError(f"Unsupported alert metric: {metric}")


def _format_text(summary: dict[str, Any]) -> str:
    lines = [
        "HS SLO Summary",
        f"contract_version: {summary.get('contract_version')}",
        f"rdv_join_success_total: {summary['rdv_join_success_total']}",
        f"rdv_join_failure_total: {summary['rdv_join_failure_total']}",
    ]

    success_rate = summary["rdv_join_success_rate"]
    success_pct = "n/a" if success_rate is None else f"{success_rate * 100:.2f}%"
    lines.append(f"rdv_join_success_rate: {success_pct}")

    p95 = summary["rdv_join_latency_p95_ms"]
    p95_text = "n/a" if p95 is None else f"{p95:.2f}"
    lines.append(f"rdv_join_latency_p95_ms: {p95_text}")

    lines.append("timeout_counts_by_error_code:")
    timeout_counts = summary["timeout_counts_by_error_code"]
    if timeout_counts:
        for error_code, count in timeout_counts.items():
            lines.append(f"  - {error_code}: {count}")
    else:
        lines.append("  - (none)")

    alert_eval = summary.get("alert_evaluation", {})
    lines.append(f"alert_status: {alert_eval.get('status', 'ok')}")
    lines.append("breached_rules:")
    breached_rules = alert_eval.get("breached_rules", [])
    if breached_rules:
        for rule in breached_rules:
            lines.append(f"  - {rule}")
    else:
        lines.append("  - (none)")

    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--events",
        default="-",
        help="Path to newline-delimited JSON event file; use '-' (default) for stdin.",
    )
    parser.add_argument(
        "--contract",
        default="docs/hs_slo_contract.json",
        help="Path to SLO contract mapping JSON file.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        contract = _load_contract(Path(args.contract))
        summary = summarize(_iter_events(args.events), contract)
    except Exception as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(summary, sort_keys=True))
    else:
        print(_format_text(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
