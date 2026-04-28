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
