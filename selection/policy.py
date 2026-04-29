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

DEFAULT_POLICY_CONFIG: dict[str, float | int | str] = {
    "guard_weight_multiplier": 1.0,
    "middle_weight_multiplier": 1.0,
    "exit_weight_multiplier": 1.0,
    "min_reliability_cutoff": 0.0,
    "diversity_mode": "strict",
    "tiny_relay_threshold": 0,
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


def _record_filter(diagnostics: dict[str, Any], role: str, relay: Relay, reason: str) -> None:
    diagnostics.setdefault("filtered", []).append(
        {"role": role, "relay": str(relay.get("name", "<unknown>")), "reason": reason}
    )


def _conflicts(candidate: Relay, selected: list[Relay], *, check_family: bool, check_subnet: bool) -> list[str]:
    reasons: list[str] = []
    if check_family:
        family = candidate.get("family_id")
        if family is not None and any(other.get("family_id") == family for other in selected):
            reasons.append("family_conflict")
    if check_subnet:
        subnet = candidate.get("subnet_key")
        if subnet is not None and any(other.get("subnet_key") == subnet for other in selected):
            reasons.append("subnet_conflict")
    return reasons


def _candidate_pool(
    relays: list[Relay],
    selected: list[Relay],
    role: str,
    *,
    diagnostics: dict[str, Any],
    check_family: bool,
    check_subnet: bool,
) -> list[Relay]:
    candidates: list[Relay] = []
    for relay in relays:
        if relay in selected:
            continue
        if not ROLE_CONSTRAINTS[role](relay):
            _record_filter(diagnostics, role, relay, "role_ineligible")
            continue
        conflict_reasons = _conflicts(relay, selected, check_family=check_family, check_subnet=check_subnet)
        if conflict_reasons:
            for reason in conflict_reasons:
                _record_filter(diagnostics, role, relay, reason)
            continue
        candidates.append(relay)
    return candidates


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
    diagnostics: dict[str, Any] = {
        "mode": str(policy_config.get("diversity_mode", "strict")),
        "relaxations": [],
        "filtered": [],
    }
    state["selection_diagnostics"] = diagnostics

    tiny_threshold = int(policy_config.get("tiny_relay_threshold", 0))
    enforce_diversity = len(relays_sorted) > tiny_threshold
    check_family = enforce_diversity
    check_subnet = enforce_diversity

    rng = state.get("rng")
    if rng is None:
        rng = random.Random(state.get("rng_seed"))

    diversity_mode = str(policy_config.get("diversity_mode", "strict")).lower()
    if diversity_mode not in {"strict", "relaxed"}:
        raise ValueError("diversity_mode must be strict or relaxed")

    def pick_with_policy(role: str, selected: list[Relay]) -> list[Relay]:
        nonlocal check_subnet, check_family
        candidates = _candidate_pool(
            relays_sorted,
            selected,
            role,
            diagnostics=diagnostics,
            check_family=check_family,
            check_subnet=check_subnet,
        )
        if candidates or diversity_mode == "strict":
            return candidates

        if check_subnet:
            diagnostics["relaxations"].append({"role": role, "relaxed": "subnet", "reason": "no_candidates_after_subnet_filter"})
            check_subnet = False
            candidates = _candidate_pool(
                relays_sorted,
                selected,
                role,
                diagnostics=diagnostics,
                check_family=check_family,
                check_subnet=check_subnet,
            )
            if candidates:
                return candidates

        if check_family:
            diagnostics["relaxations"].append({"role": role, "relaxed": "family", "reason": "no_candidates_after_family_filter"})
            check_family = False
            candidates = _candidate_pool(
                relays_sorted,
                selected,
                role,
                diagnostics=diagnostics,
                check_family=check_family,
                check_subnet=check_subnet,
            )
        return candidates

    guard_candidates = pick_with_policy("guard", [])
    if not guard_candidates:
        raise ValueError("no guard-eligible relay available under diversity policy")
    guard = _weighted_pick(guard_candidates, "guard", policy_config=policy_config, rng=rng)

    selected = [guard]

    for _idx in range(middle_count):
        viable_candidates: list[Relay] = []
        middle_pool = pick_with_policy("middle", selected)
        for candidate in middle_pool:
            future_selected = selected + [candidate]
            if pick_with_policy("exit", future_selected):
                viable_candidates.append(candidate)
        if not viable_candidates:
            raise ValueError("insufficient middle-eligible relays for requested path under diversity policy")
        middle = _weighted_pick(viable_candidates, "middle", policy_config=policy_config, rng=rng)
        selected.append(middle)

    exit_candidates = pick_with_policy("exit", selected)
    if not exit_candidates:
        raise ValueError("no exit-eligible relay available under diversity policy")
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
