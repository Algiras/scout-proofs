# SCOUT reference implementation

An independent, open reference implementation of the SCOUT credential-renewal
protocol described in the paper (sealed grant delivery, session-gated recoverable
renewal, cooperative teardown), written from the paper alone. It is a reference
for the protocol logic, not a production-hardened service.

## Layout

| Crate | Role |
|---|---|
| `scout-core` | Pure protocol state machines: no I/O, clock, randomness or crypto, zero dependencies. Tokens, commitments, ciphertexts and operation ids appear only as opaque integers. Kani proof harnesses live in `src/proofs.rs`. |
| `scout-wire` | Sealing (X25519 + HKDF-SHA256 + AES-256-GCM), Ed25519 proofs over canonical JSON, HMAC commitments, a tiny HTTP server and client. |
| `scout-broker` | `scoutd`: HTTP shell that calls `scout-core` for every protocol decision; conditional-write store (memory or atomic JSON file). |
| `scout-runner` | `scout-run`: keys in memory, signed requests, recoverable renewal, process-group supervision, revoke and finalize on every exit path. `scout-whoami` is a demo workload. |
| `scout-mockprovider` | `mockprovider`: OAuth 2.0 provider with single-use rotating refresh tokens, RFC 7009 revocation, auto-approve, fault injection and `/debug/stats`. |

## Run locally (three commands)

```sh
cargo build --release
./target/release/mockprovider --listen 127.0.0.1:9000 --client-secret demo-client-secret-xx --auto-approve true --access-ttl 8 &
./target/release/scoutd --listen 127.0.0.1:8080 --client-secret demo-client-secret-xx --commit-key demo-commit-key-0123456789 \
  --provider-auth-url http://127.0.0.1:9000/authorize --provider-token-url http://127.0.0.1:9000/token \
  --provider-revoke-url http://127.0.0.1:9000/revoke &
./target/release/scout-run --broker http://127.0.0.1:8080 --auto-consent true --renew-margin 5 --poll-every 1 \
  -- ./target/release/scout-whoami http://127.0.0.1:9000/api/whoami 12
```

The runner prints the consent URL, opens the grant, starts the workload with only
`PATH` and `SCOUT_ACCESS_TOKEN`, renews before expiry, then revokes and finalizes.
`curl 127.0.0.1:9000/debug/stats` shows provider refresh and revocation counts.
The commitment key must differ from the client secret. A compose demo is in
`docker-compose.yml`.

## Tests

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

- `scout-core` tests explore the state machines breadth-first, check the inductive
  step over every state of a small universe that satisfies the invariant, and
  print state and transition counts (`cargo test -p scout-core -- --nocapture`).
- `scout-broker/tests/e2e.rs`: happy path, lost reply, competing operation,
  ambiguous outcome, foreign token, storage snapshot, closure, undelivered
  revocation, delivery record, bind-before-mint, restart, runner supervision.
- `scout-broker/tests/conformance.rs`: exhaustive search of the renewal logic
  against the real store and core with an injected clock, checking S1-S5.

## Formal verification with Kani

The harnesses are inductive: they assume an arbitrary state satisfying the
invariant, apply one arbitrary event and assert the invariant, so they cover any
number of steps. Properties: session F1-F4, delivery D1-D2, renewal S1-S5,
teardown T1-T6. History properties use ghost fields in `src/ghost.rs`, which is
compiled only for Kani and tests.

```sh
cd impl/scout-core
cargo kani                                              # all proofs
cargo kani --harness renewal_inductive_s1_to_s5         # one harness
cargo kani --features broken-variants --harness broken_ # defective variants; each must FAIL (should_panic)
```

## Deploy with Helm

```sh
docker build -t scout:dev impl
kind create cluster --name scout-demo && kind load docker-image scout:dev --name scout-demo
helm install scout deploy/helm/scout
kubectl logs -f job/scout-scout-example
```

The chart runs one broker replica (file store on a PVC), an optional mock
provider, a NetworkPolicy that lets only the broker reach the provider's token and
revocation port, and an example runner Job. Generated secrets are for the demo
only; use `secrets.existingSecret` otherwise.

## Limitations

- Single broker replica and a single-file store; no replication or failover.
- The mock provider stands in for a real one; no real provider adapter is included.
- No assertion-mediated renewal (the paper's design only).
- No supervisor or child delegation, authorization epochs or cancellation.
- The principal is an unauthenticated string given at consent start; a deployment must put real authentication there.
- The workload receives its access token once, in its environment; renewed tokens are held by the runner and are not pushed to the workload.
- Proof nonces are not tracked for replay (proofs are bound to method, route, authority and session, and accepted within five minutes).
- Closed markers are never garbage-collected. The HTTP server is minimal and has no TLS; terminate TLS in front of it.
- Kani proofs cover `scout-core` only, not the shell crates.

## Licence

Apache License 2.0; see `LICENSE`.
