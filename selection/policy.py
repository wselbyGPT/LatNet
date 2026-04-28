from __future__ import annotations

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


def _first_valid_policy(relays: list[Relay], state: dict[str, Any]) -> list[Relay]:
    if len(relays) < 2:
        raise ValueError("policy selection requires at least two relays")

    middle_count = int(state.get("middle_count", 1))
    if middle_count < 0:
        raise ValueError("middle_count must be non-negative")

    relays_sorted = sorted(relays, key=lambda relay: str(relay.get("name", "")))

    guard = next((relay for relay in relays_sorted if ROLE_CONSTRAINTS["guard"](relay)), None)
    if guard is None:
        raise ValueError("no guard-eligible relay available")

    selected = [guard]

    for relay in relays_sorted:
        if len(selected) >= middle_count + 1:
            break
        if relay is guard:
            continue
        if ROLE_CONSTRAINTS["middle"](relay):
            selected.append(relay)

    if len(selected) != middle_count + 1:
        raise ValueError("insufficient middle-eligible relays for requested path")

    exit_relay = next(
        (
            relay
            for relay in relays_sorted
            if relay not in selected and ROLE_CONSTRAINTS["exit"](relay)
        ),
        None,
    )
    if exit_relay is None:
        raise ValueError("no exit-eligible relay available")

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


__all__ = ["ROLE_CONSTRAINTS", "select_path"]
