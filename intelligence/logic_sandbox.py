"""Bounded, local state-transition sandbox for red-team hypotheses.

World and plan files are data. No Python from them is evaluated, and this module
does not perform network I/O, launch processes, or execute exploit payloads.
"""

from __future__ import annotations

import argparse
from collections import deque
import json
from pathlib import Path
import re
import sys
from typing import Any


MAX_FILE_BYTES = 128_000
MAX_FACTS = 64
MAX_ACTIONS = 32
MAX_CASES = 16
MAX_STEPS = 32
MAX_EXPRESSION_NODES = 128
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
MISSING = object()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load_document(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"Input must be a JSON file under {MAX_FILE_BYTES} bytes: {path}")
    data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    if not isinstance(data, dict):
        raise ValueError("Top-level JSON value must be an object")
    return data


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase identifier (up to 64 characters)")
    return value


def _scalar(value: Any, label: str) -> Any:
    if type(value) not in (bool, int, str) or (isinstance(value, str) and len(value) > 256):
        raise ValueError(f"{label} must be a boolean, integer, or short string")
    return value


def _facts(value: Any, label: str, *, allow_empty: bool = False, allow_unknown: bool = False) -> dict:
    if not isinstance(value, dict) or len(value) > MAX_FACTS or (not value and not allow_empty):
        raise ValueError(f"{label} must contain 1-{MAX_FACTS} facts")
    return {_id(key, f"{label} fact"): (None if item is None and allow_unknown else _scalar(item, f"{label}.{key}"))
            for key, item in value.items()}


def _expression(value: Any, facts: set[str], count: list[int]) -> None:
    count[0] += 1
    if count[0] > MAX_EXPRESSION_NODES:
        raise ValueError("Expression is too large")
    if not isinstance(value, dict):
        raise ValueError("Condition must be an object")
    if set(value) == {"fact", "equals"}:
        fact = _id(value["fact"], "Condition fact")
        if fact not in facts:
            raise ValueError(f"Condition uses undeclared fact: {fact}")
        _scalar(value["equals"], "Condition value")
        return
    if set(value) in ({"all"}, {"any"}):
        operands = value[next(iter(value))]
        if not isinstance(operands, list) or not 1 <= len(operands) <= 16:
            raise ValueError("all/any requires 1-16 conditions")
        for operand in operands:
            _expression(operand, facts, count)
        return
    if set(value) == {"not"}:
        _expression(value["not"], facts, count)
        return
    raise ValueError("Condition must use fact+equals, all, any, or not")


def validate_world(world: dict) -> tuple[dict, dict]:
    if world.get("schema_version") != "1.0":
        raise ValueError("Unsupported world schema_version")
    _id(world.get("world_id"), "world_id")
    state = _facts(world.get("initial_state"), "initial_state", allow_unknown=True)
    known = set(state)
    actions = world.get("actions")
    cases = world.get("cases")
    if not isinstance(actions, list) or not 1 <= len(actions) <= MAX_ACTIONS:
        raise ValueError(f"actions must contain 1-{MAX_ACTIONS} entries")
    if not isinstance(cases, list) or not 2 <= len(cases) <= MAX_CASES:
        raise ValueError(f"cases must contain 2-{MAX_CASES} entries")
    if not isinstance(world.get("assumptions"), list) or not world["assumptions"] or not all(
        isinstance(item, str) and 0 < len(item) <= 500 for item in world["assumptions"]
    ):
        raise ValueError("assumptions must list the unverified model assumptions")
    parsed_actions = {}
    for action in actions:
        if not isinstance(action, dict) or set(action) != {"id", "requires", "sets"}:
            raise ValueError("Each action needs id, requires, and sets")
        action_id = _id(action["id"], "Action id")
        if action_id in parsed_actions:
            raise ValueError(f"Duplicate action: {action_id}")
        effects = _facts(action["sets"], f"Action {action_id} sets")
        if not set(effects) <= known:
            raise ValueError(f"Action {action_id} sets undeclared facts: {sorted(set(effects) - known)}")
        _expression(action["requires"], known, [0])
        parsed_actions[action_id] = action
    _expression(world.get("goal"), known, [0])
    parsed_cases = {}
    kinds = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"id", "kind", "overrides"}:
            raise ValueError("Each case needs id, kind, and overrides")
        case_id = _id(case["id"], "Case id")
        if case_id in parsed_cases:
            raise ValueError(f"Duplicate case: {case_id}")
        kind = case["kind"]
        if kind not in ("hypothesis", "negative_control"):
            raise ValueError("Case kind must be hypothesis or negative_control")
        overrides = _facts(case["overrides"], f"Case {case_id} overrides", allow_empty=True, allow_unknown=True)
        if not set(overrides) <= known:
            raise ValueError(f"Case {case_id} overrides undeclared facts")
        parsed_cases[case_id] = case
        kinds.add(kind)
    if kinds != {"hypothesis", "negative_control"}:
        raise ValueError("World needs a hypothesis case and a negative control")
    return parsed_actions, parsed_cases


def validate_plan(plan: dict, world: dict, actions: dict, cases: dict) -> None:
    if plan.get("schema_version") != "1.0" or plan.get("world_id") != world["world_id"]:
        raise ValueError("Plan schema or world_id does not match the world")
    _id(plan.get("plan_id"), "plan_id")
    steps = plan.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise ValueError(f"steps must contain 1-{MAX_STEPS} action ids")
    for step in steps:
        if step not in actions:
            raise ValueError(f"Unknown action in plan: {step}")
    expected = plan.get("expect_goal")
    if not isinstance(expected, dict) or set(expected) != set(cases) or not all(type(value) is bool for value in expected.values()):
        raise ValueError("expect_goal must specify a boolean for every world case")
    if not any(expected[name] for name, case in cases.items() if case["kind"] == "hypothesis"):
        raise ValueError("At least one hypothesis case must expect the goal")
    if any(expected[name] for name, case in cases.items() if case["kind"] == "negative_control"):
        raise ValueError("Negative controls must expect the goal to remain false")


def evaluate(condition: dict, state: dict) -> bool | None:
    if "fact" in condition:
        value = state.get(condition["fact"], MISSING)
        return None if value is MISSING or value is None else type(value) is type(condition["equals"]) and value == condition["equals"]
    if "not" in condition:
        value = evaluate(condition["not"], state)
        return None if value is None else not value
    if "all" in condition:
        results = [evaluate(item, state) for item in condition["all"]]
        return False if False in results else None if None in results else True
    results = [evaluate(item, state) for item in condition["any"]]
    return True if True in results else None if None in results else False


def failed_leaves(condition: dict, state: dict) -> list[dict]:
    if "fact" in condition:
        actual = state.get(condition["fact"], MISSING)
        return [] if evaluate(condition, state) is True else [{
            "fact": condition["fact"], "expected": condition["equals"],
            "actual": "unknown" if actual is MISSING or actual is None else actual,
        }]
    if "not" in condition:
        return [] if evaluate(condition, state) is True else [{"condition": condition, "actual": evaluate(condition, state)}]
    key = "all" if "all" in condition else "any"
    if evaluate(condition, state) is True:
        return []
    result = []
    for item in condition[key]:
        result.extend(failed_leaves(item, state))
    return result


def simulate(world: dict, plan: dict) -> dict:
    actions, cases = validate_world(world)
    validate_plan(plan, world, actions, cases)
    results = []
    for case in world["cases"]:
        state = dict(world["initial_state"])
        state.update(case["overrides"])
        trace = []
        for action_id in plan["steps"]:
            action = actions[action_id]
            permitted = evaluate(action["requires"], state)
            if permitted is not True:
                trace.append({"action": action_id, "result": "blocked" if permitted is False else "unknown",
                              "unmet": failed_leaves(action["requires"], state)})
                break
            changes = {key: {"before": state.get(key), "after": value} for key, value in action["sets"].items() if state.get(key) != value}
            state.update(action["sets"])
            trace.append({"action": action_id, "result": "applied", "changes": changes})
        goal = evaluate(world["goal"], state)
        expected = plan["expect_goal"][case["id"]]
        results.append({"case": case["id"], "kind": case["kind"], "goal": goal,
                        "expected_goal": expected, "matches_expectation": goal is expected,
                        "trace": trace, "final_state": state,
                        "unmet_goal": failed_leaves(world["goal"], state) if goal is not True else []})
    return {"world_id": world["world_id"], "plan_id": plan["plan_id"],
            "result": "supported_in_model" if all(item["matches_expectation"] for item in results) else "not_supported_in_model",
            "cases": results, "assumptions": world["assumptions"],
            "interpretation": "A symbolic model result. It does not establish that a real product is vulnerable or authorize live testing."}


def explore(world: dict, *, max_depth: int = 6, max_states: int = 500) -> dict:
    """Find shortest modeled paths while bounding search time and memory."""
    actions, _ = validate_world(world)
    if not 1 <= max_depth <= 12 or not 1 <= max_states <= 2_000:
        raise ValueError("max_depth must be 1-12 and max_states must be 1-2000")
    results = []
    for case in world["cases"]:
        initial = dict(world["initial_state"])
        initial.update(case["overrides"])
        queue = deque([(initial, [])])
        visited = {tuple(sorted(initial.items()))}
        found = [] if evaluate(world["goal"], initial) is True else None
        truncated = False
        while queue and found is None:
            state, path = queue.popleft()
            if len(path) >= max_depth:
                continue
            for action_id, action in actions.items():
                if evaluate(action["requires"], state) is not True:
                    continue
                next_state = dict(state)
                next_state.update(action["sets"])
                signature = tuple(sorted(next_state.items()))
                if signature in visited:
                    continue
                if len(visited) >= max_states:
                    truncated = True
                    break
                visited.add(signature)
                next_path = path + [action_id]
                if evaluate(world["goal"], next_state) is True:
                    found = next_path
                    break
                queue.append((next_state, next_path))
            if truncated:
                break
        results.append({"case": case["id"], "kind": case["kind"], "shortest_goal_path": found,
                        "states_examined": len(visited), "search_truncated": truncated,
                        "depth_limit": max_depth, "state_limit": max_states})
    control_path = any(item["kind"] == "negative_control" and item["shortest_goal_path"] is not None for item in results)
    hypothesis_path = any(item["kind"] == "hypothesis" and item["shortest_goal_path"] is not None for item in results)
    return {"world_id": world["world_id"],
            "result": "control_counterexample" if control_path else "hypothesis_path_found" if hypothesis_path else "no_path_found_within_limits",
            "cases": results, "assumptions": world["assumptions"],
            "interpretation": "Shortest paths in the supplied symbolic model only. No path found within limits is not proof of safety."}


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a red-team plan against a local symbolic world")
    parser.add_argument("world", type=Path, help="JSON world with facts, actions, and control cases")
    parser.add_argument("plan", type=Path, nargs="?", help="JSON plan with steps and expected goals")
    parser.add_argument("--explore", action="store_true", help="Search bounded shortest paths without a plan")
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--max-states", type=int, default=500)
    args = parser.parse_args()
    if args.explore == bool(args.plan):
        parser.error("Supply a plan, or use --explore without a plan")
    try:
        world = load_document(args.world)
        result = explore(world, max_depth=args.max_depth, max_states=args.max_states) if args.explore else simulate(world, load_document(args.plan))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(2, f"Invalid sandbox input: {exc}\n")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
