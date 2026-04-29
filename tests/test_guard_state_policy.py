from __future__ import annotations

import json


def test_first_valid_prefers_healthy_pinned_guard(tmp_path, latnet_modules):
    policy = latnet_modules["selection.policy"]
    guard_state = tmp_path / "guards.json"
    guard_state.write_text(
        json.dumps(
            {
                "version": 1,
                "policy": {"max_pinned_guards": 3},
                "active_guard": "g2",
                "guards": {
                    "g2": {"first_seen": 1, "last_success": 2, "failures": 0, "quarantine_until": 0}
                },
            }
        )
    )
    relays = [
        {"name": "g1", "guard_eligible": True, "middle_eligible": True, "exit_eligible": False},
        {"name": "g2", "guard_eligible": True, "middle_eligible": True, "exit_eligible": False},
        {"name": "m1", "guard_eligible": False, "middle_eligible": True, "exit_eligible": False},
        {"name": "x1", "guard_eligible": False, "middle_eligible": True, "exit_eligible": True},
    ]

    selected = policy.select_path(
        relays,
        policy="first_valid",
        state={"middle_count": 1, "guard_state_path": str(guard_state), "rng_seed": 7, "now": 100},
    )

    assert selected[0]["name"] == "g2"
    data = json.loads(guard_state.read_text())
    assert data["active_guard"] == "g2"

