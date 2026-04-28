from __future__ import annotations

import random
from typing import Any, Callable

Relay = dict[str, Any]
RoleConstraint = Callable[[Relay], bool]



def _default_eligible(relay: Relay, role: str) -> bool:
    key = f"{role}_eligible"
    value = relay.get(key)
    if isinstance(value, bool):
        return value
    return True


ROLE_CONSTRAINTS: dict[str, RoleConstraint] = {
    "guard": lambda relay: _default_eligible(relay, "guard"),
    "middle": lambda relay: _default_eligible(relay, "middle"),
    "exit": lambda relay: _default_eligible(relay, "exit"),
}

DEFAULT_POLICY_CONFIG: dict[str, float] = {
    "guard_weight_multiplier": 1.0,
    "middle_weight_multiplier": 1.0,
    "exit_weight_multiplier": 1.0,
    "min_reliability_cutoff": 0.0,
}


def _validate_no_duplicate_names(path: list[Relay]) -> None:
    names = [str(relay.get("name", "")) for relay in path]
    if len(set(names)) != len(names):
        raise ValueError("path must not contain duplicate relay names")


def _enforce_role_constraints(path: list[Relay]) -> None:
    if not path:
        raise ValueError("path must contain at least one relay")

    if not ROLE_CONSTRAINTS["guard"](path[0]):
        raise ValueError(f"relay {path[0].get('name', '<unknown>')} is not guard-eligible")

    if not ROLE_CONSTRAINTS["exit"](path[-1]):
        raise ValueError(f"relay {path[-1].get('name', '<unknown>')} is not exit-eligible")

    for relay in path[1:-1]:
        if not ROLE_CONSTRAINTS["middle"](relay):
            raise ValueError(f"relay {relay.get('name', '<unknown>')} is not middle-eligible")


def _ordered_policy(relays: list[Relay], state: dict[str, Any]) -> list[Relay]:
    relay_names = state.get("relay_names")
    if not isinstance(relay_names, list) or not relay_names:
        raise ValueError("ordered policy requires relay_names")

    by_name = {str(relay.get("name", "")): relay for relay in relays}
    selected: list[Relay] = []
    for name in relay_names:
        relay = by_name.get(str(name))
        if relay is None:
            raise ValueError(f"relay {name} missing from candidate set")
        selected.append(relay)
    return selected


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _num_or_default(value: Any, default: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return float(value)


def _effective_weight(relay: Relay, role: str, *, policy_config: dict[str, Any]) -> float:
    capacity = max(0.0, _num_or_default(relay.get("capacity_weight"), 1.0))
    reliability = _clamp(_num_or_default(relay.get("reliability_score"), 1.0), 0.0, 1.0)
    min_reliability = _clamp(_num_or_default(policy_config.get("min_reliability_cutoff"), 0.0), 0.0, 1.0)
    if reliability < min_reliability:
        return 0.0
    multiplier = max(0.0, _num_or_default(policy_config.get(f"{role}_weight_multiplier"), 1.0))
    return capacity * reliability * multiplier


def _weighted_pick(candidates: list[Relay], role: str, *, policy_config: dict[str, Any], rng: random.Random) -> Relay:
    weighted = [(relay, _effective_weight(relay, role, policy_config=policy_config)) for relay in candidates]
    total = sum(weight for _relay, weight in weighted)
    if total <= 0:
        return sorted(candidates, key=lambda relay: str(relay.get("name", "")))[0]
    target = rng.random() * total
    cumulative = 0.0
    for relay, weight in weighted:
        cumulative += weight
        if target <= cumulative:
            return relay
    return weighted[-1][0]


def _first_valid_policy(relays: list[Relay], state: dict[str, Any]) -> list[Relay]:
    if len(relays) < 2:
        raise ValueError("policy selection requires at least two relays")

    middle_count = int(state.get("middle_count", 1))
    if middle_count < 0:
        raise ValueError("middle_count must be non-negative")

    relays_sorted = sorted(relays, key=lambda relay: str(relay.get("name", "")))
    policy_config = dict(DEFAULT_POLICY_CONFIG)
    if isinstance(state.get("policy_config"), dict):
        policy_config.update(state["policy_config"])
    rng = state.get("rng")
    if rng is None:
        rng = random.Random(state.get("rng_seed"))
    guard_candidates = [relay for relay in relays_sorted if ROLE_CONSTRAINTS["guard"](relay)]
    if not guard_candidates:
        raise ValueError("no guard-eligible relay available")
    guard = _weighted_pick(guard_candidates, "guard", policy_config=policy_config, rng=rng)

    selected = [guard]

    middle_candidates = [relay for relay in relays_sorted if relay is not guard and ROLE_CONSTRAINTS["middle"](relay)]
    if len(middle_candidates) < middle_count:
        raise ValueError("insufficient middle-eligible relays for requested path")
    for idx in range(middle_count):
        remaining_needed = middle_count - idx - 1
        viable_candidates = []
        for candidate in middle_candidates:
            future_selected = selected + [candidate]
            future_middles = [relay for relay in middle_candidates if relay is not candidate]
            if len(future_middles) < remaining_needed:
                continue
            future_exits = [relay for relay in relays_sorted if relay not in future_selected and ROLE_CONSTRAINTS["exit"](relay)]
            if not future_exits:
                continue
            viable_candidates.append(candidate)
        if not viable_candidates:
            raise ValueError("insufficient middle-eligible relays for requested path")
        middle = _weighted_pick(viable_candidates, "middle", policy_config=policy_config, rng=rng)
        selected.append(middle)
        middle_candidates = [relay for relay in middle_candidates if relay is not middle]

    exit_candidates = [relay for relay in relays_sorted if relay not in selected and ROLE_CONSTRAINTS["exit"](relay)]
    if not exit_candidates:
        raise ValueError("no exit-eligible relay available")
    exit_relay = _weighted_pick(exit_candidates, "exit", policy_config=policy_config, rng=rng)

    selected.append(exit_relay)
    return selected


def select_path(relays: list[Relay], policy: str, state: dict[str, Any] | None = None) -> list[Relay]:
    if not isinstance(relays, list):
        raise ValueError("relays must be a list")

    state = state or {}

    if policy == "ordered":
        path = _ordered_policy(relays, state)
    elif policy == "first_valid":
        path = _first_valid_policy(relays, state)
    else:
        raise ValueError(f"unknown selection policy: {policy}")

    _validate_no_duplicate_names(path)
    _enforce_role_constraints(path)
    return path


__all__ = ["DEFAULT_POLICY_CONFIG", "ROLE_CONSTRAINTS", "select_path"]
