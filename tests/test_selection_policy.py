from __future__ import annotations

import pytest


def test_select_path_first_valid_enforces_roles_and_uniqueness(latnet_modules):
    policy = latnet_modules["selection.policy"]
    relays = [
        {"name": "g1", "guard_eligible": True, "middle_eligible": True, "exit_eligible": False},
        {"name": "m1", "guard_eligible": False, "middle_eligible": True, "exit_eligible": False},
        {"name": "x1", "guard_eligible": False, "middle_eligible": True, "exit_eligible": True},
    ]

    selected = policy.select_path(relays, policy="first_valid", state={"middle_count": 1})

    assert [relay["name"] for relay in selected] == ["g1", "m1", "x1"]


def test_select_path_ordered_rejects_duplicate_names(latnet_modules):
    policy = latnet_modules["selection.policy"]
    relays = [
        {"name": "same", "guard_eligible": True, "middle_eligible": True, "exit_eligible": True},
        {"name": "same", "guard_eligible": True, "middle_eligible": True, "exit_eligible": True},
    ]

    with pytest.raises(ValueError, match="duplicate relay names"):
        policy.select_path(relays, policy="ordered", state={"relay_names": ["same", "same"]})


def test_select_path_first_valid_supports_weighted_selection_and_seed(latnet_modules):
    policy = latnet_modules["selection.policy"]
    relays = [
        {"name": "g1", "guard_eligible": True, "middle_eligible": True, "exit_eligible": False, "capacity_weight": 10.0, "reliability_score": 0.9},
        {"name": "g2", "guard_eligible": True, "middle_eligible": True, "exit_eligible": False, "capacity_weight": 1.0, "reliability_score": 0.2},
        {"name": "m1", "guard_eligible": False, "middle_eligible": True, "exit_eligible": False, "capacity_weight": 3.0, "reliability_score": 0.8},
        {"name": "x1", "guard_eligible": False, "middle_eligible": True, "exit_eligible": True, "capacity_weight": 4.0, "reliability_score": 0.95},
    ]

    state = {
        "middle_count": 1,
        "rng_seed": 7,
        "policy_config": {
            "guard_weight_multiplier": 1.0,
            "middle_weight_multiplier": 1.0,
            "exit_weight_multiplier": 1.0,
            "min_reliability_cutoff": 0.5,
        },
    }
    selected = policy.select_path(relays, policy="first_valid", state=state)

    assert [relay["name"] for relay in selected] == ["g1", "m1", "x1"]
