# Bounded proposed-protocol verification

Exhaustive finite-state reachability of proposed protocol abstractions; not shipped implementation conformance or unbounded proof

Deterministic exhaustive BFS; counts below are fresh output from model_check.py.

| Model | Outcome | Visited states | Examined transitions | Maximum discovered depth |
| --- | --- | ---: | ---: | ---: |
| authorization | PASS | 432 | 1296 | 14 |
| renewal | PASS | 1164 | 3868 | 20 |
| delegation | PASS | 528 | 4264 | 6 |
| negative:check_then_reserve | COUNTEREXAMPLE | 32 | 48 | 3 |
| negative:missing_close_guard | COUNTEREXAMPLE | 32 | 50 | 3 |
| negative:missing_expiry_guard | COUNTEREXAMPLE | 46 | 77 | 4 |
| negative:broken_cas | COUNTEREXAMPLE | 75 | 130 | 4 |
| negative:blind_crash_retry | COUNTEREXAMPLE | 252 | 580 | 7 |
| negative:child_authority_union | COUNTEREXAMPLE | 4 | 4 | 1 |
| negative:ignore_requested_constraints | COUNTEREXAMPLE | 4 | 4 | 1 |
| negative:ignore_policy | COUNTEREXAMPLE | 12 | 58 | 1 |
| negative:unclamped_child_expiry | COUNTEREXAMPLE | 8 | 10 | 1 |

Correct models exhaust their complete finite reachable graph. Negative controls stop at the first violating edge; their counts are partial. Counterexamples are shortest from each model's initial state and include each resulting state in JSON.

## Exact bounds

```json
{
  "authorization": {
    "callers": 2,
    "one_shot_operations_per_caller": 1,
    "times": [
      0,
      1,
      2
    ],
    "expiry": 2,
    "epochs": [
      0,
      1
    ],
    "network": [
      "connected",
      "partitioned"
    ],
    "stages_per_caller": 6
  },
  "renewal": {
    "operation_ids": [
      0,
      1
    ],
    "renewable_generations": [
      0,
      1
    ],
    "terminal_generation": 2,
    "times": [
      0,
      1,
      2
    ],
    "expiry": 2,
    "workers_per_generation": 2,
    "network": [
      "authoritative state reachable",
      "authoritative state unavailable"
    ],
    "crash": "REFRESHING becomes RECOVERY_REQUIRED; READY persists",
    "response": "one immutable symbolic ciphertext per READY generation and owner; release reservation and later network arrival are separate transitions"
  },
  "delegation": {
    "max_nodes": 3,
    "lineage": [
      "root/parent",
      "child",
      "grandchild"
    ],
    "root_authority": [
      "repository A/read-diff",
      "repository A/write"
    ],
    "tuple_universe": [
      "repository A/read-diff",
      "repository A/write",
      "repository B/write"
    ],
    "requested_authority_masks": [
      0,
      1,
      2,
      3,
      4,
      5,
      6,
      7
    ],
    "policy_masks": [
      1,
      3,
      7
    ],
    "requested_expiries": [
      1,
      2,
      3
    ],
    "root_expiry": 2,
    "times": [
      0,
      1,
      2
    ],
    "requested_depth_budgets": [
      0,
      1,
      2
    ],
    "root_depth_budget": 2
  }
}
```

## Findings

- An interrupted durable REFRESHING record does not distinguish a pre-provider crash from a post-provider crash; recovery conservatively rejects new renewal without reconciliation/new consent
- Authorization is linearized before external send, so a previously authorized provider request can complete after cancellation; likewise a response released before cancellation can arrive afterward
- Persisted READY plus generation and operation identity is required for response-only retries

## Assumptions

- Linearizable root updates, epoch reservations and compare-and-swap
- The partition flag means authoritative state unavailable: no new reservation, provider initiation, READY commit or response release; a provider result may wait for reconnect without another invocation
- Durable generation, operation identifier and READY data survive restart
- Trusted broker/authorizer and supervisor isolation
- Authentic receipts/proofs and correct exact-tuple canonicalization are assumed; no cryptographic algorithm is checked
- Provider invocation is an external effect; ambiguous interrupted exchanges fail closed
- Previously dispatch-authorized calls and previously released responses may arrive or complete after root closure/expiry; release authorization is distinct from network arrival
- Same-generation operation IDs are finite symbols; reusing a symbol in a later generation denotes a different bound operation

## Exclusions

- Unbounded state or arbitrarily many descendants/generations
- Liveness, fairness, eventual delivery or provider availability
- Real cryptography, receipt HMAC correctness, token secrecy/non-persistence, provider account identity and provider token revocation
- Actual source/runtime/API conformance
- Atomicity between the provider and broker persistence
- Composition proof across factored submodels or arbitrary delegation trees

## Shortest negative-control traces

### check_then_reserve

no new reservation or dispatch authorization during partition

0. initial
1. caller 0 checks authority
2. partition
3. caller 0 reserves

### missing_close_guard

no new reservation or dispatch authorization after root closure

0. initial
1. caller 0 checks authority
2. close root and advance epoch
3. caller 0 reserves

### missing_expiry_guard

no new reservation or dispatch authorization after expiry

0. initial
1. advance time
2. caller 0 checks authority
3. advance time
4. caller 0 reserves

### broken_cas

one reserved renewal operation per generation

0. initial
1. operation 0 checks generation 0
2. operation 1 checks generation 0
3. operation 0 reserves generation 0
4. operation 1 reserves generation 0

### blind_crash_retry

at most one provider invocation per root generation

0. initial
1. operation 0 checks generation 0
2. operation 0 reserves generation 0
3. operation 0 invokes provider generation 0
4. crash and blindly reopen generation
5. operation 0 checks generation 0
6. operation 0 reserves generation 0
7. operation 0 invokes provider generation 0

### child_authority_union

delegated authority respects the actual requested tuple set and policy

0. initial
1. create child request=000 policy=001 expiry=1 depth=0

### ignore_requested_constraints

delegated authority respects the actual requested tuple set and policy

0. initial
1. create child request=000 policy=001 expiry=1 depth=0

### ignore_policy

delegated authority respects the actual requested tuple set and policy

0. initial
1. create child request=010 policy=001 expiry=1 depth=0

### unclamped_child_expiry

child and grandchild expiry is bounded by root and parent

0. initial
1. create child request=000 policy=001 expiry=3 depth=0

