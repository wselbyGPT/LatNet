from __future__ import annotations

import json

import pytest


def _names(path):
    return [relay["name"] for relay in path]


def test_role_constraints_hold_by_hop_position(latnet_modules):
    policy = latnet_modules["selection.policy"]

    relays = [
        {"name": "guard-alpha", "guard_eligible": True, "middle_eligible": True, "exit_eligible": False},
        {"name": "middle-bravo", "guard_eligible": False, "middle_eligible": True, "exit_eligible": False},
        {"name": "exit-charlie", "guard_eligible": False, "middle_eligible": True, "exit_eligible": True},
    ]

    selected = policy.select_path(relays, policy="first_valid", state={"middle_count": 1, "rng_seed": 11})
    assert _names(selected) == ["guard-alpha", "middle-bravo", "exit-charlie"]

    with pytest.raises(ValueError, match="not guard-eligible"):
        policy.select_path(
            [
                {"name": "bad-guard", "guard_eligible": False, "middle_eligible": True, "exit_eligible": False},
                {"name": "ok-middle", "middle_eligible": True, "exit_eligible": False},
                {"name": "ok-exit", "middle_eligible": True, "exit_eligible": True},
            ],
            policy="ordered",
            state={"relay_names": ["bad-guard", "ok-middle", "ok-exit"]},
        )


def test_family_and_subnet_conflicts_strict_vs_relaxed_modes(latnet_modules):
    policy = latnet_modules["selection.policy"]
    relays = [
        {
            "name": "guard-fam-a-subnet-a",
            "guard_eligible": True,
            "middle_eligible": True,
            "exit_eligible": False,
            "family_id": "family-a",
            "subnet_key": "198.51.100.0/24",
        },
        {
            "name": "middle-fam-a-subnet-a",
            "guard_eligible": False,
            "middle_eligible": True,
            "exit_eligible": False,
            "family_id": "family-a",
            "subnet_key": "198.51.100.0/24",
        },
        {
            "name": "exit-fam-a-subnet-a",
            "guard_eligible": False,
            "middle_eligible": True,
            "exit_eligible": True,
            "family_id": "family-a",
            "subnet_key": "198.51.100.0/24",
        },
    ]

    strict_state = {"middle_count": 1, "policy_config": {"diversity_mode": "strict"}}
    with pytest.raises(ValueError, match="diversity policy"):
        policy.select_path(relays, policy="first_valid", state=strict_state)
    strict_reasons = {entry["reason"] for entry in strict_state["selection_diagnostics"]["filtered"]}
    assert "family_conflict" in strict_reasons
    assert "subnet_conflict" in strict_reasons

    relaxed_state = {"middle_count": 1, "rng_seed": 2, "policy_config": {"diversity_mode": "relaxed"}}
    relaxed = policy.select_path(relays, policy="first_valid", state=relaxed_state)
    assert _names(relaxed) == ["guard-fam-a-subnet-a", "middle-fam-a-subnet-a", "exit-fam-a-subnet-a"]
    assert [r["relaxed"] for r in relaxed_state["selection_diagnostics"]["relaxations"]] == ["subnet", "family"]


def test_guard_pinning_reuse_and_rotation_with_simulated_time_and_failures(tmp_path, latnet_modules):
    policy = latnet_modules["selection.policy"]
    guard_state = tmp_path / "guards.json"

    relays = [
        {"name": "guard-pinned-primary", "guard_eligible": True, "middle_eligible": True, "exit_eligible": False, "capacity_weight": 100, "reliability_score": 1.0},
        {"name": "guard-backup-secondary", "guard_eligible": True, "middle_eligible": True, "exit_eligible": False, "capacity_weight": 1, "reliability_score": 1.0},
        {"name": "middle-delta", "guard_eligible": False, "middle_eligible": True, "exit_eligible": False},
        {"name": "exit-echo", "guard_eligible": False, "middle_eligible": True, "exit_eligible": True},
    ]

    first = policy.select_path(relays, policy="first_valid", state={"middle_count": 1, "rng_seed": 5, "guard_state_path": str(guard_state), "now": 1_000})
    assert first[0]["name"] == "guard-pinned-primary"

    reused = policy.select_path(relays, policy="first_valid", state={"middle_count": 1, "rng_seed": 999, "guard_state_path": str(guard_state), "now": 1_100})
    assert reused[0]["name"] == "guard-pinned-primary"

    state_doc = json.loads(guard_state.read_text())
    state_doc["guards"]["guard-pinned-primary"]["quarantine_until"] = 2_500
    guard_state.write_text(json.dumps(state_doc))

    relays_after_failures = [dict(relay) for relay in relays]
    relays_after_failures[0]["guard_eligible"] = False

    rotated = policy.select_path(relays_after_failures, policy="first_valid", state={"middle_count": 1, "rng_seed": 1, "guard_state_path": str(guard_state), "now": 2_000})
    assert rotated[0]["name"] == "guard-backup-secondary"


def test_weighted_sampling_distribution_and_seed_determinism(latnet_modules):
    policy = latnet_modules["selection.policy"]
    relays = [
        {"name": "guard-heavy", "guard_eligible": True, "middle_eligible": True, "exit_eligible": False, "capacity_weight": 9.0, "reliability_score": 1.0},
        {"name": "guard-light", "guard_eligible": True, "middle_eligible": True, "exit_eligible": False, "capacity_weight": 1.0, "reliability_score": 1.0},
        {"name": "middle-fixed", "guard_eligible": False, "middle_eligible": True, "exit_eligible": False},
        {"name": "exit-fixed", "guard_eligible": False, "middle_eligible": True, "exit_eligible": True},
    ]

    draws = 3000
    picks = []
    heavy = 0
    for idx in range(draws):
        selected = policy.select_path(relays, policy="first_valid", state={"middle_count": 1, "rng_seed": idx})
        picks.append(selected[0]["name"])
        if selected[0]["name"] == "guard-heavy":
            heavy += 1

    expected = 0.9
    observed = heavy / draws
    assert abs(observed - expected) < 0.05

    picks_repeated = [
        policy.select_path(relays, policy="first_valid", state={"middle_count": 1, "rng_seed": idx})[0]["name"]
        for idx in range(draws)
    ]
    assert picks == picks_repeated
