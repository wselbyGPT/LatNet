from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Metrics:
    intro_requests_handled: int = 0
    rendezvous_join_success: int = 0
    rendezvous_join_failure: int = 0
    join_latency_ms: list[float] = field(default_factory=list)
    relay_command_failures_by_type: dict[str, int] = field(default_factory=dict)
    descriptor_fetch_rate_limited: int = 0
    intro_poll_rate_limited: int = 0
    rate_limit_windows: dict[str, int] = field(default_factory=dict)

    def record_intro_request(self) -> None:
        self.intro_requests_handled += 1

    def record_join(self, *, success: bool, latency_ms: float | None = None) -> None:
        if success:
            self.rendezvous_join_success += 1
        else:
            self.rendezvous_join_failure += 1
        if latency_ms is not None:
            self.join_latency_ms.append(float(latency_ms))

    def record_relay_failure(self, error_code: str) -> None:
        key = str(error_code or "unknown_error")
        self.relay_command_failures_by_type[key] = self.relay_command_failures_by_type.get(key, 0) + 1

    def record_rate_limited(self, counter: str, *, window_label: str) -> None:
        if counter == "descriptor_fetch_rate_limited":
            self.descriptor_fetch_rate_limited += 1
        elif counter == "intro_poll_rate_limited":
            self.intro_poll_rate_limited += 1
        self.rate_limit_windows[window_label] = self.rate_limit_windows.get(window_label, 0) + 1

    def as_dict(self) -> dict[str, Any]:
        avg_join_latency_ms = (
            sum(self.join_latency_ms) / len(self.join_latency_ms) if self.join_latency_ms else None
        )
        return {
            "intro_requests_handled": self.intro_requests_handled,
            "rendezvous_join_success": self.rendezvous_join_success,
            "rendezvous_join_failure": self.rendezvous_join_failure,
            "join_latency_count": len(self.join_latency_ms),
            "join_latency_avg_ms": avg_join_latency_ms,
            "relay_command_failures_by_type": dict(sorted(self.relay_command_failures_by_type.items())),
            "descriptor_fetch_rate_limited": self.descriptor_fetch_rate_limited,
            "intro_poll_rate_limited": self.intro_poll_rate_limited,
            "rate_limit_windows": dict(sorted(self.rate_limit_windows.items())),
        }


class EventEmitter:
    def __init__(
        self,
        *,
        component: str,
        service_name: str | None = None,
        circuit_id: str | None = None,
        rendezvous_cookie: str | None = None,
    ) -> None:
        self.component = component
        self.service_name = service_name
        self.circuit_id = circuit_id
        self.rendezvous_cookie = rendezvous_cookie

    def emit(self, event: str, *, status: str, error_code: str | None = None, **fields: Any) -> dict[str, Any]:
        payload = {
            "event": event,
            "ts": int(time.time()),
            "component": self.component,
            "service_name": self.service_name,
            "circuit_id": self.circuit_id,
            "rendezvous_cookie": self.rendezvous_cookie,
            "status": status,
            "error_code": error_code,
        }
        payload.update(fields)
        print(json.dumps(payload, sort_keys=True))
        return payload
