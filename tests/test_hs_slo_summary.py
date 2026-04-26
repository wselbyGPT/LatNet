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
