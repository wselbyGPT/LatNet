import json
import subprocess
import sys
from pathlib import Path


def test_hs_slo_summary_json_output(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    events_path.write_text(
        "\n".join(
            [
                json.dumps({"event": "hs.rdv_joined", "status": "ok", "join_latency_ms": 100.0}),
                json.dumps({"event": "hs.rdv_joined", "status": "ok", "join_latency_ms": 200.0}),
                json.dumps({"event": "hs.rdv_joined", "status": "error", "error_code": "timeout"}),
                json.dumps({"event": "hs.error", "status": "error", "error_code": "timeout"}),
                json.dumps({"event": "hs.error", "status": "error", "error_code": "intro_poll"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/hs_slo_summary.py",
            "--events",
            str(events_path),
            "--contract",
            "docs/hs_slo_contract.json",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    summary = json.loads(completed.stdout)
    assert summary["rdv_join_success_total"] == 2
    assert summary["rdv_join_failure_total"] == 1
    assert summary["rdv_join_success_rate"] == 2 / 3
    assert summary["rdv_join_latency_p95_ms"] == 200.0
    assert summary["timeout_counts_by_error_code"] == {"intro_poll": 1, "timeout": 1}


def test_hs_slo_summary_text_output_from_stdin() -> None:
    stdin_payload = "\n".join(
        [
            json.dumps({"event": "hs.rdv_joined", "status": "ok", "join_latency_ms": 123.0}),
            json.dumps({"event": "hs.error", "status": "error", "error_code": "timeout"}),
        ]
    )

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/hs_slo_summary.py",
            "--contract",
            "docs/hs_slo_contract.json",
            "--format",
            "text",
        ],
        input=stdin_payload,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "rdv_join_success_rate: 100.00%" in completed.stdout
    assert "rdv_join_latency_p95_ms: 123.00" in completed.stdout
    assert "timeout: 1" in completed.stdout
    assert "alert_status: ok" in completed.stdout


def test_hs_slo_summary_alert_rule_breaches(tmp_path: Path) -> None:
    events_path = tmp_path / "alerts.jsonl"
    events_path.write_text(
        "\n".join(
            [
                json.dumps({"event": "hs.rdv_joined", "status": "error", "ts": "2026-04-26T12:00:00Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.rdv_joined", "status": "error", "ts": "2026-04-26T12:00:30Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.rdv_joined", "status": "error", "ts": "2026-04-26T12:01:00Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.rdv_joined", "status": "ok", "ts": "2026-04-26T12:01:30Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.error", "status": "error", "error_code": "intro_poll", "ts": "2026-04-26T12:02:00Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.error", "status": "error", "error_code": "intro_poll", "ts": "2026-04-26T12:02:20Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.error", "status": "error", "error_code": "intro_poll", "ts": "2026-04-26T12:02:40Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.intro_polled", "status": "error", "ts": "2026-04-26T12:03:00Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.intro_polled", "status": "ok", "ts": "2026-04-26T12:03:10Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.error", "status": "error", "error_code": "timeout", "ts": "2026-04-26T12:04:00Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.error", "status": "error", "error_code": "timeout", "ts": "2026-04-26T12:04:10Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.error", "status": "error", "error_code": "timeout", "ts": "2026-04-26T12:04:20Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.error", "status": "error", "error_code": "timeout", "ts": "2026-04-26T12:04:30Z", "service_name": "svc-a"}),
                json.dumps({"event": "hs.error", "status": "error", "error_code": "timeout", "ts": "2026-04-26T12:04:40Z", "service_name": "svc-a"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/hs_slo_summary.py",
            "--events",
            str(events_path),
            "--contract",
            "docs/hs_slo_contract.json",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    summary = json.loads(completed.stdout)
    assert summary["alert_evaluation"]["status"] == "critical"
    assert "join_failure_rate_critical_5m" in summary["alert_evaluation"]["breached_rules"]
    assert "intro_poll_failures_consecutive_critical" in summary["alert_evaluation"]["breached_rules"]
    assert "timeout_errors_repeated_warning_10m" in summary["alert_evaluation"]["breached_rules"]
