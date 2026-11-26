#!/usr/bin/env python3
"""Deterministic exhaustive bounded models of the proposed PACT protocol, not its API."""
from __future__ import annotations
import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
from typing import Callable, Iterable


@dataclass(frozen=True)
class Action:
    time: int = 0
    closed: bool = False
    epoch: int = 0
    connected: bool = True
    # Two one-shot callers: idle, checked, reserved, authorized, sent, complete.
    stages: tuple[int, int] = (0, 0)
    checked_epochs: tuple[int, int] = (-1, -1)
    reservation_epochs: tuple[int, int] = (-1, -1)


def put(values: tuple, index: int, value) -> tuple:
    return values[:index] + (value,) + values[index + 1:]


def action_edges(s: Action, mutation: str = ""):
    live = not s.closed and s.time < 2 and s.connected
    if s.time < 2:
        yield "advance time", replace(s, time=s.time + 1)
    yield "partition" if s.connected else "reconnect", replace(s, connected=not s.connected)
    if not s.closed:
        yield "close root and advance epoch", replace(s, closed=True, epoch=s.epoch + 1)
    for i, stage in enumerate(s.stages):
        if stage == 0 and live:
            yield f"caller {i} checks authority", replace(s, stages=put(s.stages, i, 1), checked_epochs=put(s.checked_epochs, i, s.epoch))
        reserve_allowed = live and s.checked_epochs[i] == s.epoch
        if mutation == "check_then_reserve":
            reserve_allowed = s.checked_epochs[i] >= 0  # stale precheck used as authorization
        if mutation == "missing_close_guard":
            reserve_allowed = s.connected and s.time < 2
        if mutation == "missing_expiry_guard":
            reserve_allowed = s.connected and not s.closed
        if stage == 1 and reserve_allowed:
            yield f"caller {i} reserves", replace(s, stages=put(s.stages, i, 2), reservation_epochs=put(s.reservation_epochs, i, s.epoch))
        if stage == 2 and live and s.reservation_epochs[i] == s.epoch:
            yield f"caller {i} revalidates dispatch", replace(s, stages=put(s.stages, i, 3))
        if stage == 3:
            # Authorization already linearized. External send/completion is not atomic with close.
            yield f"caller {i} sends previously authorized call", replace(s, stages=put(s.stages, i, 4))
        if stage == 4:
            yield f"caller {i} completes external call", replace(s, stages=put(s.stages, i, 5))


def action_check(before: Action, event: str, after: Action):
    if event.endswith(" reserves") or event.endswith("revalidates dispatch"):
        if before.closed:
            return "no new reservation or dispatch authorization after root closure"
        if before.time >= 2:
            return "no new reservation or dispatch authorization after expiry"
        if not before.connected:
            return "no new reservation or dispatch authorization during partition"
    return None


@dataclass(frozen=True)
class Renewal:
    generation: int = 0
    phase: str = "ACTIVE"
    time: int = 0
    closed: bool = False
    connected: bool = True
    # Worker stages: idle, checked, reserved, provider invoked, provider returned.
    workers: tuple[int, int] = (0, 0)
    checked_generations: tuple[int, int] = (-1, -1)
    invocations: tuple[int, int] = (0, 0)
    ready_owner: int = -1
    delivered: bool = False
    response_authorized: bool = False


def renewal_edges(s: Renewal, mutation: str = ""):
    live = not s.closed and s.time < 2 and s.connected
    if s.time < 2:
        yield "advance time", replace(s, time=s.time + 1)
    yield "partition" if s.connected else "reconnect", replace(s, connected=not s.connected)
    if not s.closed:
        yield "close root", replace(s, closed=True, phase="CLOSED")
    if s.phase == "REFRESHING":
        if mutation == "blind_crash_retry":
            yield "crash and blindly reopen generation", replace(s, phase="ACTIVE", workers=(0, 0), checked_generations=(-1, -1))
        else:
            # Durable REFRESHING cannot distinguish a pre-call from a post-call crash.
            yield "crash and enter recovery required", replace(s, phase="RECOVERY_REQUIRED", workers=(0, 0), checked_generations=(-1, -1))
    if s.response_authorized:
        yield "previously released response arrives", replace(s, delivered=True, response_authorized=False)
    if s.phase == "READY":
        yield "crash with durable READY retained", replace(s, delivered=False)
        yield "lose READY response", replace(s, delivered=False)
        if live:
            yield f"same-ID retry releases owner {s.ready_owner}", replace(s, response_authorized=True)
            yield f"wrong-ID retry {1 - s.ready_owner} rejected", s
            if s.delivered:
                g = s.generation + 1
                yield "acknowledge replacement", replace(s, generation=g, phase="ACTIVE" if g < 2 else "EXHAUSTED", workers=(0, 0), checked_generations=(-1, -1), ready_owner=-1, delivered=False)
    for i, stage in enumerate(s.workers):
        if s.phase == "ACTIVE" and stage == 0 and live:
            yield f"operation {i} checks generation {s.generation}", replace(s, workers=put(s.workers, i, 1), checked_generations=put(s.checked_generations, i, s.generation))
        reserve_allowed = s.phase == "ACTIVE"
        if mutation == "broken_cas":
            reserve_allowed = s.phase in ("ACTIVE", "REFRESHING")
        if stage == 1 and reserve_allowed and live and s.checked_generations[i] == s.generation:
            yield f"operation {i} reserves generation {s.generation}", replace(s, phase="REFRESHING", workers=put(s.workers, i, 2))
        if stage == 2 and s.phase == "REFRESHING" and live:
            counts = put(s.invocations, s.generation, s.invocations[s.generation] + 1)
            yield f"operation {i} invokes provider generation {s.generation}", replace(s, workers=put(s.workers, i, 3), invocations=counts)
        if stage == 3:
            # If close/expiry wins, do not publish usable replacement material.
            if not s.closed and s.time < 2 and s.connected and s.phase == "REFRESHING":
                yield f"operation {i} persists READY", replace(s, phase="READY", workers=put(s.workers, i, 4), ready_owner=i, delivered=False)
            elif s.closed or s.time >= 2:
                yield f"operation {i} returns after close or expiry; suppress response", replace(s, phase="CLOSED", closed=True, workers=put(s.workers, i, 4), delivered=False)


def renewal_check(before: Renewal, event: str, after: Renewal):
    if any(n > 1 for n in after.invocations):
        return "at most one provider invocation per root generation"
    reserved = sum(w in (2, 3, 4) for w in after.workers)
    if reserved > 1:
        return "one reserved renewal operation per generation"
    if "reserves generation" in event or "invokes provider" in event:
        if before.closed or before.time >= 2 or not before.connected:
            return "renewal initiation requires open, unexpired, reachable authority"
    if event.startswith("same-ID retry"):
        if before.invocations != after.invocations:
            return "READY retry cannot invoke provider again"
        if before.ready_owner != after.ready_owner or before.generation != after.generation:
            return "READY retry preserves response identity and generation"
    if event.startswith("same-ID retry") or event.endswith("persists READY"):
        if before.closed or before.time >= 2 or not before.connected:
            return "READY commit and release authorization require live reachable authority"
    if before.phase == "RECOVERY_REQUIRED" and "invokes provider" in event:
        return "ambiguous crash outcome is fail-closed"
    return None


@dataclass(frozen=True)
class Delegation:
    time: int = 0
    closed: bool = False
    connected: bool = True
    # (authority bitset, expiry, remaining depth); root acts as parent authority.
    nodes: tuple[tuple[int, int, int], ...] = ((3, 2, 2),)


def delegation_edges(s: Delegation, mutation: str = ""):
    if s.time < 2:
        yield "advance time", replace(s, time=s.time + 1)
    yield "partition" if s.connected else "reconnect", replace(s, connected=not s.connected)
    if not s.closed:
        yield "close root", replace(s, closed=True)
    live = not s.closed and s.connected and all(s.time < n[1] for n in s.nodes)
    if not live:
        return
    parent_mask, parent_expiry, parent_budget = s.nodes[-1]
    if len(s.nodes) < 3 and parent_budget > 0:
        for requested in range(8):  # A/read-diff, A/write, B/write, including all combinations
            for policy in (1, 3, 7):
                for requested_expiry in (1, 2, 3):
                    for requested_budget in (0, 1, 2):
                        authority = 3 & parent_mask & requested & policy
                        if mutation == "ignore_requested_constraints":
                            authority = 3 & parent_mask & policy
                        if mutation == "ignore_policy":
                            authority = 3 & parent_mask & requested
                        if mutation == "child_authority_union":
                            authority = 3 | parent_mask | requested | policy
                        expiry = min(2, parent_expiry, requested_expiry)
                        budget = min(parent_budget - 1, requested_budget)
                        if mutation == "unclamped_child_expiry":
                            expiry = requested_expiry
                        child = (authority, expiry, budget)
                        label = f"create {'child' if len(s.nodes) == 1 else 'grandchild'} request={requested:03b} policy={policy:03b} expiry={requested_expiry} depth={requested_budget}"
                        yield label, replace(s, nodes=s.nodes + (child,))
    for i, (mask, expiry, _) in enumerate(s.nodes[1:], 1):
        if s.time < expiry:
            for bit in (1, 2, 4):
                if mask & bit:
                    yield f"node {i} authorizes tuple {bit}", s


def delegation_check(before: Delegation, event: str, after: Delegation):
    if event.startswith("create "):
        args = dict(item.split("=", 1) for item in event.split() if "=" in item)
        requested, policy = int(args["request"], 2), int(args["policy"], 2)
        if after.nodes[-1][0] & ~requested or after.nodes[-1][0] & ~policy:
            return "delegated authority respects the actual requested tuple set and policy"
        if after.nodes[-1][1] > int(args["expiry"]):
            return "delegated expiry cannot exceed requested expiry"
        if after.nodes[-1][2] > int(args["depth"]):
            return "delegated depth budget cannot exceed requested budget"
    for i, (mask, expiry, budget) in enumerate(after.nodes[1:], 1):
        parent = after.nodes[i - 1]
        if mask & ~3 or mask & ~parent[0]:
            return "child and grandchild authority stays within root and parent"
        if expiry > parent[1] or expiry > 2:
            return "child and grandchild expiry is bounded by root and parent"
        if budget < 0 or budget >= parent[2]:
            return "delegation consumes depth; zero-budget leaf cannot delegate"
    if "authorizes tuple" in event or event.startswith("create "):
        if before.closed or not before.connected or any(before.time >= n[1] for n in before.nodes):
            return "ancestor expiry, closure and partition reject new authorization"
    return None


def explore(name, initial, edges: Callable, check: Callable, mutation="", expected_failure=False):
    queue = deque([initial])
    parents = {initial: None}
    transitions = 0
    coverage = set()
    exercised = {}
    max_depth = 0
    depths = {initial: 0}
    while queue:
        state = queue.popleft()
        for event, nxt in edges(state, mutation):
            transitions += 1
            coverage.add(event)
            features = []
            if isinstance(state, Action):
                if state.closed and "previously authorized call" in event:
                    features.append("external_send_after_close")
                if state.closed and "completes external call" in event:
                    features.append("external_completion_after_close")
                if state.time >= 2 and "completes external call" in event:
                    features.append("external_completion_after_expiry")
            if isinstance(state, Renewal):
                if event.startswith("crash") and state.phase == "REFRESHING":
                    features.append("crash_after_provider_call" if 3 in state.workers else "crash_before_provider_call")
                if event.startswith("same-ID retry"):
                    features.append("READY_same_ID_retry")
                    if state.delivered:
                        features.append("READY_repeated_same_ID_retry")
                if "response arrives" in event and state.closed:
                    features.append("released_response_arrival_after_close")
                if "response arrives" in event and state.time >= 2:
                    features.append("released_response_arrival_after_expiry")
                if "invokes provider generation 1" in event:
                    features.append("second_generation_provider_call")
            if isinstance(state, Delegation):
                if event.startswith("create grandchild"):
                    features.append("grandchild_creation")
                if "authorizes tuple" in event:
                    node = int(event.split()[1])
                    if state.nodes[node][2] == 0:
                        features.append("zero_budget_leaf_operation")
            for feature in features:
                exercised.setdefault(feature, {"event": event, "minimum_transition_depth": depths[state] + 1})
            violation = check(state, event, nxt)
            if violation:
                trace = [{"event": event, "state": asdict(nxt)}]
                current = state
                while parents[current] is not None:
                    previous, previous_event = parents[current]
                    trace.append({"event": previous_event, "state": asdict(current)})
                    current = previous
                trace.append({"event": "initial", "state": asdict(current)})
                trace.reverse()
                return {"name": name, "mutation": mutation or None, "expected_failure": expected_failure, "outcome": "COUNTEREXAMPLE", "exhaustive": False, "frontier_exhausted": False, "visited_states": len(parents), "examined_transitions": transitions, "max_depth": max_depth, "violation": violation, "shortest_counterexample": trace, "event_labels_seen": sorted(coverage), "coverage_witnesses": exercised}
            if nxt not in parents:
                parents[nxt] = (state, event)
                depths[nxt] = depths[state] + 1
                max_depth = max(max_depth, depths[nxt])
                queue.append(nxt)
    return {"name": name, "mutation": mutation or None, "expected_failure": expected_failure, "outcome": "PASS", "exhaustive": True, "frontier_exhausted": True, "visited_states": len(parents), "examined_transitions": transitions, "max_depth": max_depth, "violation": None, "shortest_counterexample": None, "event_labels_seen": sorted(coverage), "coverage_witnesses": exercised}


MODELS = {
    "authorization": (Action(), action_edges, action_check),
    "renewal": (Renewal(), renewal_edges, renewal_check),
    "delegation": (Delegation(), delegation_edges, delegation_check),
}
CONTROLS = {
    "check_then_reserve": "authorization",
    "missing_close_guard": "authorization",
    "missing_expiry_guard": "authorization",
    "broken_cas": "renewal",
    "blind_crash_retry": "renewal",
    "child_authority_union": "delegation",
    "ignore_requested_constraints": "delegation",
    "ignore_policy": "delegation",
    "unclamped_child_expiry": "delegation",
}
BOUNDS = {
    "authorization": {"callers": 2, "one_shot_operations_per_caller": 1, "times": [0, 1, 2], "expiry": 2, "epochs": [0, 1], "network": ["connected", "partitioned"], "stages_per_caller": 6},
    "renewal": {"operation_ids": [0, 1], "renewable_generations": [0, 1], "terminal_generation": 2, "times": [0, 1, 2], "expiry": 2, "workers_per_generation": 2, "network": ["authoritative state reachable", "authoritative state unavailable"], "crash": "REFRESHING becomes RECOVERY_REQUIRED; READY persists", "response": "one immutable symbolic ciphertext per READY generation and owner; release reservation and later network arrival are separate transitions"},
    "delegation": {"max_nodes": 3, "lineage": ["root/parent", "child", "grandchild"], "root_authority": ["repository A/read-diff", "repository A/write"], "tuple_universe": ["repository A/read-diff", "repository A/write", "repository B/write"], "requested_authority_masks": list(range(8)), "policy_masks": [1, 3, 7], "requested_expiries": [1, 2, 3], "root_expiry": 2, "times": [0, 1, 2], "requested_depth_budgets": [0, 1, 2], "root_depth_budget": 2},
}


def run_suite():
    results = [explore(name, *spec) for name, spec in MODELS.items()]
    controls = [explore(f"negative:{mutation}", *MODELS[model], mutation=mutation, expected_failure=True) for mutation, model in CONTROLS.items()]
    success = all(r["outcome"] == "PASS" for r in results) and all(r["outcome"] == "COUNTEREXAMPLE" for r in controls)
    return {"schema_version": 1, "scope": "Exhaustive finite-state reachability of proposed protocol abstractions; not shipped implementation conformance or unbounded proof", "algorithm": "Breadth-first search; predecessor links reconstruct shortest transition-count counterexamples", "bounds": BOUNDS, "assumptions": ["Linearizable root updates, epoch reservations and compare-and-swap", "The partition flag means authoritative state unavailable: no new reservation, provider initiation, READY commit or response release; a provider result may wait for reconnect without another invocation", "Durable generation, operation identifier and READY data survive restart", "Trusted broker/authorizer and supervisor isolation", "Authentic receipts/proofs and correct exact-tuple canonicalization are assumed; no cryptographic algorithm is checked", "Provider invocation is an external effect; ambiguous interrupted exchanges fail closed", "Previously dispatch-authorized calls and previously released responses may arrive or complete after root closure/expiry; release authorization is distinct from network arrival", "Same-generation operation IDs are finite symbols; reusing a symbol in a later generation denotes a different bound operation"], "exclusions": ["Unbounded state or arbitrarily many descendants/generations", "Liveness, fairness, eventual delivery or provider availability", "Real cryptography, receipt HMAC correctness, token secrecy/non-persistence, provider account identity and provider token revocation", "Actual source/runtime/API conformance", "Atomicity between the provider and broker persistence", "Composition proof across factored submodels or arbitrary delegation trees"], "model_findings": ["An interrupted durable REFRESHING record does not distinguish a pre-provider crash from a post-provider crash; recovery conservatively rejects new renewal without reconciliation/new consent", "Authorization is linearized before external send, so a previously authorized provider request can complete after cancellation; likewise a response released before cancellation can arrive afterward", "Persisted READY plus generation and operation identity is required for response-only retries"], "composition": "Three independently explored submodels; no cross-product or arbitrary-tree composition proof", "correct_models": results, "negative_controls": controls, "summary": {"correct_passes": sum(r["outcome"] == "PASS" for r in results), "correct_models": len(results), "negative_controls_detected": sum(r["outcome"] == "COUNTEREXAMPLE" for r in controls), "negative_controls": len(controls), "success": success}}


def markdown(report):
    lines = ["# Bounded proposed-protocol verification", "", report["scope"], "", "Deterministic exhaustive BFS; counts below are fresh output from model_check.py.", "", "| Model | Outcome | Visited states | Examined transitions | Maximum discovered depth |", "| --- | --- | ---: | ---: | ---: |"]
    for r in report["correct_models"] + report["negative_controls"]:
        lines.append(f'| {r["name"]} | {r["outcome"]} | {r["visited_states"]} | {r["examined_transitions"]} | {r["max_depth"]} |')
    lines += ["", "Correct models exhaust their complete finite reachable graph. Negative controls stop at the first violating edge; their counts are partial. Counterexamples are shortest from each model's initial state and include each resulting state in JSON.", "", "## Exact bounds", "", "```json", json.dumps(report["bounds"], indent=2), "```", "", "## Findings", ""]
    lines += [f"- {x}" for x in report["model_findings"]]
    for section in ("assumptions", "exclusions"):
        lines += ["", f"## {section.title()}", ""] + [f"- {x}" for x in report[section]]
    lines += ["", "## Shortest negative-control traces", ""]
    for r in report["negative_controls"]:
        lines += [f'### {r["mutation"]}', "", str(r["violation"]), ""]
        for i, step in enumerate(r["shortest_counterexample"] or []):
            lines.append(f'{i}. {step["event"]}')
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--negative-control", choices=sorted(CONTROLS))
    parser.add_argument("--replay", help="Replay a negative-control trace stored in this JSON report")
    args = parser.parse_args()
    if args.replay:
        data = json.loads(Path(args.replay).read_text())
        ok = True
        for saved in data["negative_controls"]:
            mutation = saved["mutation"]
            initial, edges, check = MODELS[CONTROLS[mutation]]
            steps = saved["shortest_counterexample"]
            current = initial
            normalize = lambda x: json.loads(json.dumps(x, sort_keys=True))
            equal = normalize(asdict(current)) == steps[0]["state"]
            violation = None
            for index, step in enumerate(steps[1:], 1):
                candidates = [(event, nxt) for event, nxt in edges(current, mutation)
                              if event == step["event"] and normalize(asdict(nxt)) == step["state"]]
                if not candidates:
                    equal = False
                    break
                event, nxt = candidates[0]
                violation = check(current, event, nxt)
                if violation and index != len(steps) - 1:
                    equal = False
                current = nxt
            equal &= violation == saved["violation"] and violation is not None
            print(f'{mutation}: {"REPLAY MATCH" if equal else "MISMATCH"}')
            ok &= equal
        return 0 if ok else 1
    if args.negative_control:
        mutation = args.negative_control
        result = explore(f"negative:{mutation}", *MODELS[CONTROLS[mutation]], mutation=mutation, expected_failure=True)
        print(json.dumps(result, indent=2))
        return 1 if result["outcome"] == "COUNTEREXAMPLE" else 0
    report = run_suite()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "model-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (args.output_dir / "model-report.md").write_text(markdown(report) + "\n")
    print(json.dumps(report["summary"], sort_keys=True))
    for r in report["correct_models"]:
        print(f'{r["name"]}: {r["outcome"]}; states={r["visited_states"]}; transitions={r["examined_transitions"]}')
    return 0 if report["summary"]["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
