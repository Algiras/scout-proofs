# Proposed PACT reference wire format, version 1

This is one exact **proposed reference profile** supporting disclosure sections 5.1–5.5. It does not change shipped PACT messages, describe a deployed API, demonstrate security of a deployment, or establish patentability. `wire_codec.py` is an executable encoder, cryptographic checker, and subset validator; it is not a broker, database transaction implementation, provider client, or formal proof. `test_wire_codec.py` tests this profile using real HMAC-SHA256 and Ed25519. Every key and token in `wire-vectors.json` is intentionally public, fixed dummy material.

Narrative synchronization: 24 October 2026, disclosure v0.8. The clarifications below cover atomic commit/release gating, authenticated pending issue/retrieve status, and durable orphan-state retention. This markdown update changes neither codec/model code nor wire fields, and reports no additional executed tests or implementation conformance.

## Insertable disclosure summary

A reference embodiment encodes receipts and request proofs as versioned, domain-separated, length-prefixed typed tuples. A broker authenticates each receipt with HMAC-SHA256 under a receipt-purpose key distinct from the token-commitment key and provider-client secret. An Ed25519 request proof binds the actual operation kind, method, route, authority identifier, root, session, base generation, epoch, receipt and token digests, operation identifier, acknowledgement digests, timestamp, and fresh nonce. The initiating operation fingerprint binds immutable renewal context while excluding the per-attempt timestamp, nonce, and signature; retrieval and acknowledgement carry fresh proofs against that persisted context. Current authoritative state, approved policy, epoch, and the captured token commitment are checked before reserving or releasing anything. Orphaned in-progress exchanges require recovery rather than automatic re-execution.

## 1. Byte grammar

All integers are unsigned, network/big-endian. `u32(x)` is exactly four bytes; `u64(x)` is exactly eight bytes, with `0 <= x <= 2^64-1`. Boolean is exactly one byte, `00` or `01`; booleans are not integers. `LP(b) = u32(len(b)) || b`, where lengths count bytes, not characters. Each field is limited to 1,048,576 bytes. A version-1 record is:

```
ASCII("PACTREF") || 01 || LP(ASCII(domain)) || u32(field_count)
  || for each schema field in its declared order:
       LP(ASCII(field_name)) || ASCII(type_code) || LP(encoded_value)
```

There is no alignment, separator, terminating NUL, optional field, omitted default, or trailing data. Type codes are `s` (string), `u` (uint64), `o` (boolean), `b` (exact bytes), and `a` (authority list). The schema fixes field names, types, and order; a binary decoder must reject unknown/repeated/out-of-order fields, incorrect counts/lengths, truncated values, nonminimal alternative forms, and trailing bytes. The reference currently constructs bytes from validated objects rather than exposing a general binary decoder.

Strings are nonempty UTF-8, at most 4,096 bytes, already NFC; normalization is **checked, never performed**. Reject all Unicode General Category `C*` characters (including controls, surrogates, formatting and bidi controls). Opaque identifiers are compared as exact UTF-8 bytes: no case folding, trimming, URL decoding, confusable folding, or inference of provider identity. A profile using distinct identifiers must not equate visually similar strings. Provider-issued refresh tokens are opaque bytes, length 1–16,384; no Unicode or whitespace normalization is applied.

An authority row is exactly four ASCII strings `(resource_id, operation_id, argument_name, argument_value)`, each matching `[A-Za-z0-9_.:@-]{1,256}`. This narrow profile permits exactly one named argument per authorized operation, e.g. `(repo-A, read-diff, diff, diff-D)`. A row is a permission as a whole; rows are alternatives, never independent lists to combine. Multiple security-relevant arguments require a separately specified versioned schema, not duplicate rows or a Cartesian product. Encode each row as four `LP(UTF8(value))` fields. Sort rows lexicographically by their complete encoded byte string; reject duplicates. Encode the list as `u32(row_count) || LP(row_1) || ... || LP(row_n)`, with 1–1,024 rows. Input ordering is immaterial; the canonical encoding is sorted.

No authority row is a URL. An adapter maps exact opaque IDs to its allowlisted provider endpoint and security-relevant arguments. Unknown operations, alternate targets, redirects, ambiguous paths, percent-encoding, and extra security arguments are rejected. These adapter semantics remain an implementation obligation; this codec does not enforce provider egress or actual endpoint behavior.

## 2. Receipt and token commitment

Domains are exact ASCII literals:

- `PACT-TOKEN-COMMITMENT-v1`
- `PACT-RECEIPT-v1`
- `PACT-RENEWAL-PROOF-v1`
- `PACT-RENEWAL-OPERATION-v1`

Keys are independently provisioned 32-byte secrets. `receipt-authentication` keys may authenticate only receipts; `token-commitment` keys may compute only token commitments. They are distinct from each other and from confidential provider-client authentication. Registry entries contain an immutable key ID, purpose, secret, issuance/verification status, and validity/retirement metadata. IDs do not authorize selecting a different purpose. Reject a mismatched purpose or ID, unknown key, revoked key, or verification past its retained validity. Registry identity and purpose must come from trusted configuration. Key management, storage, and distribution are outside this reference codec.

The token commitment is HMAC-SHA256 with a commitment-purpose key over the tuple in this order:

```
key_id:s, root:s, provider:s, client:s, generation:u, token:b
```

Use domain `PACT-TOKEN-COMMITMENT-v1`. The commitment is exactly 32 bytes. It binds the exact token issued for that root/provider/client/generation, rather than merely proving that a token is acceptable to the provider.

Receipt payload schema, in this exact order:

```
receipt_key_id:s, commitment_key_id:s,
root:s, consent:s, principal:s, session:s, capability:s, provider:s, client:s,
enc_key_sha256:b, sign_key_sha256:b, authority:a, refreshable:o,
deadline_ms:u, epoch:u, generation:u, commitment:b
```

The key thumbprints and commitment are exactly 32 bytes. Encryption thumbprint is SHA-256 of the raw 32-byte X25519 public key; signing thumbprint is SHA-256 of the raw 32-byte Ed25519 public key. Receipt authentication is `HMAC-SHA256(receipt_key, encode("PACT-RECEIPT-v1", receipt_schema, receipt))`, exactly 32 bytes. Receipt digest is `SHA256(receipt_payload || LP(receipt_authenticator))`; SHA-256 means the standard 32-byte output without textual hex conversion.

Issue a receipt only from the approved exchange and authenticated authoritative record. The authenticated principal, consent event, provider/client, actual captured token and pinned runner keys must be established by the broker. A receipt never substitutes for independently verifying the provider subject. In this profile a request sends a receipt digest reference, and the broker resolves it to the retained receipt and authenticator in the authoritative operation/root record. It does not accept a caller-chosen policy as authoritative.

During `RENEWAL_ACTIVE(g)`, the authoritative approved receipt is the current generation-g receipt. During `REFRESHING(g)` and `READY(g+1)`, retain that initiating receipt with the pending operation; the next receipt is stored separately. On acknowledgement make the next receipt current atomically without reopening a closed root or changing its authorization epoch. An old receipt can authenticate only the retained matching pending operation, never a fresh renewal, authority expansion, expired deadline, or obsolete epoch.

Key rotation does not silently change receipt context. New receipts identify the new receipt/commitment-purpose keys; retained receipts continue using their recorded keys while authorized. Preserve verification/commitment keys through their receipts' bounded lifetimes, pending response-retention windows, and applicable replay retention. If a required key is unavailable or revoked, fail closed and require reconciliation or new consent; do not skip validation or extend policy. A root cancellation always overrides otherwise valid cryptography.

## 3. Proofs, requests, and transport

The exact common operation context is:

```
authority_id:s, root:s, session:s, generation:u, epoch:u,
receipt_sha256:b, token_sha256:b, operation_id:s
```

`authority_id` is a trusted broker-service identifier mapped to an exact authenticated TLS origin/audience in configuration; it is not a caller-supplied URL or a permission set. The receipt's `authority` field separately contains permissions. Do not trust forwarded-host headers to determine this identifier. `generation` always names the initiating base generation g, including retrieval/acknowledgement of a READY result at g+1. `token_sha256` is SHA-256 of the exact initiating refresh-token bytes. The operation ID is unique within the root's lifetime, including tombstones; never reuse it for a different context.

Retrieval omits the token value from transport but retains `token_sha256` in the signed initiating context. Omitting the value is not permission to remove or replace its digest, change generation, or reconstruct the fingerprint from a replacement token.

A proof payload uses domain `PACT-RENEWAL-PROOF-v1` and this exact schema:

```
kind:s, method:s, route:s,
<the common context above in order>,
response_sha256:b, next_receipt_sha256:b, signed_at_ms:u, nonce:b
```

All four digest fields are exactly 32 bytes; nonce is exactly 32 fresh random bytes. Timestamp is Unix epoch milliseconds, with broker acceptance `abs(now_ms - signed_at_ms) <= 60000`; `now_ms` must also fit uint64. Require trusted broker time. Signature is Ed25519 over these exact payload bytes, exactly 64 bytes, verified with the root's pinned signing key. Ed25519 is not used as an encryption algorithm.

The three shapes differ by their exact kind/route and acknowledgement fields:

| Kind | Method and exact canonical route | Token transport | Acknowledgement fields |
| --- | --- | --- | --- |
| `issue` | `POST /pact-reference/v1/renew/issue` | exact initiating token | both all-zero 32-byte digests |
| `retrieve` | `POST /pact-reference/v1/renew/retrieve` | absent/null | both all-zero 32-byte digests |
| `ack` | `POST /pact-reference/v1/renew/ack` | absent/null | SHA-256 of exact sealed response bytes, and digest of exact next receipt |

No query, fragment, absolute URI, percent-encoding, trailing slash, duplicate slash, alternate capitalization, method alias, or redirect is accepted. Resolve the configured TLS origin separately; the signed authority ID binds that origin/audience. The route and method received by the broker must exactly match the proof values.

A stable operation fingerprint is `SHA256(encode("PACT-RENEWAL-OPERATION-v1", common_schema, common_context))`. Store it with the initiating request-payload digest and operation ID before contacting the provider. Kind, route, acknowledgement digests, per-attempt timestamp, nonce and signature are not part of this common context: they are independently signed on every attempt and checked against the particular endpoint/phase. Thus `issue`, `retrieve`, and `ack` share the renewal identity but cannot replay one another's endpoint proof. An acknowledgement additionally binds the exact produced result. No other initiating context may change on retry.

JSON transport is precisely an object with keys `request`, `signature`, and `token`. `request` contains exactly all proof-schema fields; bytes are canonical unpadded base64url and uint64 values are exact JSON integers. `signature` is unpadded base64url; `token` is base64url for issue and JSON null otherwise. JSON member order and surrounding whitespace are irrelevant; duplicate keys, unknown/extra fields, missing fields, NaN/Infinity, floats for uint64, padded or noncanonical base64url, `+`, `/`, whitespace within encodings, and invalid UTF-8 are rejected. Re-encoding base64url must reproduce exactly the received string. Clients with floating-point-only numbers must parse uint64 losslessly before encoding; this profile does not permit rounded numbers or string substitutes. Maximum JSON envelope is 1,048,576 UTF-8 bytes. Never sign a JSON serializer's incidental output; sign the typed tuple.

## 4. Validation order and atomic boundaries

Parsing rejects malformed/canonical-shape errors before cryptographic work; that is not authorization. After parsing:

1. Resolve only trusted authority and root key candidates. Verify the actual method/route/audience, pinned Ed25519 key and signature, timestamp window, and unused nonce. A key supplied by the request is never a trust anchor.
2. Authenticate the resolved receipt under its recorded receipt-purpose key; compare its digest with the signed digest reference. Retrieve current linearizable root and operation records. Compare session/root, current epoch, approved receipt bytes, provider/client, original consent/policy, both runner thumbprints, refreshability and deadline. Never replace authoritative state with a receipt's assertions.
3. For an issue request, compare SHA-256 of the submitted token to the signed token digest and recompute its keyed commitment with the recorded commitment-purpose key. A new issue additionally requires `RENEWAL_ACTIVE(g)`, exact current generation, an unused operation ID and no existing family reservation. A repeated issue matching the retained reserved operation in `REFRESHING(g)` or `READY(g+1)` is a status request, not a new issue: validate its fresh proof/nonce, retained initiating receipt and exact fingerprint, then return status only without reserving again or calling the provider. A matching retrieve while `REFRESHING(g)` likewise returns status only; its token envelope is null. These status paths require an atomic recheck of the open root and matching epoch and nonce consumption; they cannot bypass `CLOSED` or `RECOVERY_REQUIRED`. A conflicting identifier or context cannot enter either path. Constant-time comparisons apply to MACs/commitments. Verify all fields before an authorized mutation; do not reveal token-specific failure details to unauthenticated callers.
4. For a new issue, in one linearizable transaction, recheck root open/epoch/deadline, consume the nonce and reserve `(g, operation ID, fingerprint, initiating-payload digest)` as `REFRESHING(g)`. Make this reservation durable before provider dispatch. Only the transaction winner may initiate the single provider exchange. The reference checker assumes its caller holds this transaction; its in-memory nonce set is not a distributed replay ledger or CAS implementation.
5. Persist a runner-sealed result and authenticated next receipt as `READY(g+1)` only via a transaction conditional on the same root-open/epoch/operation state. Each initial response release requires its own atomic open-root and matching-epoch check; a successful READY commit does not itself authorize later release. A cancelled or superseded operation cannot authorize a fresh usable result. Completion recomputes the next-generation token commitment using returned rotated refresh bytes, or the original token bytes only under verified provider no-rotation semantics. The old commitment cannot simply be copied because its authenticated input includes generation.
6. READY retrieval requires a fresh proof/nonce, matching retained initiating context and old receipt, current open root/epoch/deadline, matching pending operation, `READY(g+1)`, and unexpired retained-result deadline. Atomically authorize response release and consume the nonce. Return the same persisted ciphertext without a provider call. While REFRESHING is live, use the status-only path in step 3; no ciphertext is released. The codec intentionally rejects non-READY retrieval instead of implementing status polling; the narrative pending-status branches do not establish additional codec coverage.
7. Acknowledgement requires the same checks plus exact response/next-receipt digests. Atomically consume nonce, activate g+1/current next receipt, and retain a terminal operation tombstone. It cannot initiate a provider exchange, reopen a closed root, or change the authorization epoch.

Nonce reuse is rejected even on retries. A matching operation ID with fresh nonce is permitted only through the appropriate authenticated status, retrieval or acknowledgement path and phase; a repeated issue never repeats the exchange. Retain each nonce at least until broker time is strictly greater than `signed_at_ms + 60000`, including future-skew allowance and any clock rollback bounds. This reference checker retains all nonces for the process lifetime; it does not implement timed eviction. On state/nonce-store unavailability, uncertain durability, or clock uncertainty beyond the accepted policy, reject.

Cancellation and action reservation use the same authoritative epoch. Closure rejects new issue reservations and **new** READY releases, even for a previously valid receipt. A release authorized before closure may already be in transit and arrive afterward; cancellation cannot recall released ciphertext or create atomicity with a provider. Recheck at dispatch, but previously authorized provider calls may complete. An in-flight refresh result after closure is withheld from new release; best-effort upstream revocation can fail.

## 5. Recovery, retention, and child records

An orphaned durable `REFRESHING` record cannot distinguish a crash before provider invocation from a crash after rotation. Absent authoritative provider reconciliation, enter `RECOVERY_REQUIRED` for **any** orphaned in-progress reservation. Durably retain the reservation or recovery marker until the root deadline, rejecting further issue attempts for that ambiguous generation. After retention expires, an expired, unknown or deleted root still rejects requests; eviction must not recreate `RENEWAL_ACTIVE` authority. Neither lease expiry, broker restart, elapsed timeout, nor another caller authorizes re-executing that provider refresh. Recovery requires authoritative reconciliation establishing usable credential state or a newly approved authorization exchange establishing fresh root credentials. Renewed consent alone neither justifies replay nor invalidates the earlier provider family. A provider-supported reconciliation/idempotency interface requires a separately specified adapter contract; none is assumed here. A READY write must be durable before retrieval succeeds.

Retain a READY result until `min(root renewal deadline, ready_commit_time + 600000 ms)`; overflow is rejected. Retrieval after that bound fails closed and requires recovery/new consent. Acknowledgement removes further ciphertext retrieval, but retain an operation tombstone until `root deadline + 120000 ms` (checked uint64 arithmetic) recording base/result generations, fingerprint, acknowledgement digests, and outcome. A fresh, matching repeated ack may return acknowledged status during that interval without a provider call or reactivation; the reference validator conservatively rejects post-ack requests rather than implementing that convenience. Never reuse root IDs or operation IDs; a deleted/unknown root rejects all operations, so tombstone eviction cannot recreate authority. If operational retention limits expire earlier, fail closed rather than reconstruct a refresh from an old receipt.

Child handle/record authentication is an authority-service responsibility separate from broker receipt HMACs. The supervisor is the root runner and execution-side custodian; children receive handles and do not call the broker as root runners. Supervisor-side coordination serves waiting child operations using a shared replacement, while broker-side generation reservation also excludes competing operation identifiers from duplicated or failed-over supervisor requests. Distinct child handles may have equal or different permission sets; each remains independently enforced.

Before deriving a child or accepting an action, Supervisor 210 verifies the issuer against a configured authority-service trust anchor, exact root/session/supervisor audience, child identity and pinned key, authenticated parent chain, exact permissions, expiry, remaining delegation budget, current epoch and revocation state. Child request proofs bind the exact canonical action and one-time reservation. The supervisor recomputes the intersection from current authenticated records; a model-produced record, task digest, broker receipt, or valid root proof cannot itself authorize a child action. Section 7 specifies an exact HMAC-authenticated handle and Ed25519 child-action proof format. The reference does not implement authority-service issuance, the full issuer registry and lineage/action authorization validator, policy intersection, isolation, or dispatch. Its child tests exercise encoding, MACs, signatures and tampering only.

## 6. Reproducible evidence and remaining gaps

Run with bundled Python:

```
python3 -m unittest discover -s docs/patent/verification -p test_wire_codec.py -v
python3 docs/patent/verification/wire_codec.py
```

The second command deterministically prints `wire-vectors.json`, including receipt payload bytes, real HMAC, pinned Ed25519 public key, proof payloads/signatures for all three shapes, and the common operation fingerprint. This is executable format evidence, not deployed PACT conformance or a cryptographic audit.

Still requiring implementation/verification: durable transactional reservation/nonces, key registry status and retention checks, explicit network method/origin binding, trusted receipt resolution, both-key/state policy binding in the full service, response sealing/authenticated retrieval, bounded retention/tombstones, recovery workers, cancellation release linearization, trusted child-record issuer registry and full lineage/action authorization validator, adapter canonicalization/egress isolation, and provider-specific behavior. `validate` covers a meaningful subset with authoritative state supplied by the caller. It does not pretend that passing local tests proves these integration properties.

## 7. Child handle and action proof reference profile

For one exact local reference construction, the authority service and designated isolated supervisor share a separate 32-byte **delegation-handle-authentication** key. This is not a broker receipt or token-commitment key. The designated supervisor is trusted to verify and enforce handles; sharing this key means it can also authenticate handles, an explicit trust assumption. A deployment requiring verifier-only supervision must select and specify a different authenticated-handle construction instead of claiming that property for this HMAC profile.

Use domain `PACT-DELEGATION-HANDLE-v1` and exact fields:

```
handle_key_id:s, issuer:s, delegation:s, root:s, session:s, parent:s,
child:s, child_key_sha256:b, supervisor:s, provider:s, client:s,
authority:a, expiry_ms:u, budget:u, epoch:u
```

Authenticate the encoded payload with HMAC-SHA256 under that purpose-specific key. `child_key_sha256` is SHA-256 of the raw 32-byte child Ed25519 key. The handle digest is SHA-256 of `encoded_handle || LP(handle_authenticator)`. The issuer identifier, handle key ID, and supervisor audience must match the trusted authority-service registry; a valid MAC from any other issuer/service is insufficient. Issue the handle only after authenticating and recomputing the root/parent/request/policy intersection. Check expiry against both parent and root, budget decrement, current epoch and authenticated lineage at issuance and action validation. Zero budget disallows a new child but permits authorized leaf operations.

A child action uses `PACT-CHILD-ACTION-PROOF-v1` and exact schema:

```
method:s, route:s, authority_id:s, delegation:s, root:s, session:s,
parent:s, child:s, epoch:u, handle_sha256:b, provider:s, client:s,
authority:a, signed_at_ms:u, nonce:b
```

Method is exactly `POST`; route is exactly `/pact-reference/v1/actions/execute`; `authority_id` is the handle's designated supervisor ID mapped to its configured authenticated TLS origin. `authority` contains exactly **one** requested operation tuple, using the same sorted-list encoding; it does not repeat the entire allowed set. Handle digest and nonce are exactly 32 bytes. The child signs the complete encoded payload with its bound Ed25519 key. Apply the same exact-route, clock-window, canonicalization, and nonce rules as renewal, using a child-key-specific durable nonce namespace.

Validation first authenticates the handle issuer/MAC/audience and child proof, then reads current authoritative root, ancestor, child and policy records; matches all handle/action context, provider/client, epoch, expiry and bound key; and checks that the exact requested tuple belongs to the recomputed effective permission set. A valid root proof cannot stand in for a child proof. Atomically consume the nonce and reserve the action against that same current epoch; revalidate before credential injection and dispatch. A signed adapter-level tuple still requires a correct unambiguous mapping to the provider method, endpoint, resource and arguments, plus enforced egress isolation. Encoding/signature checks do not prove this mapping or isolation.

The reference includes real child-handle HMAC and child Ed25519 action vectors and a tampering test. It intentionally does not implement the authority service, trusted issuer registry, full lineage/policy authorization, durable child reservation ledger or provider dispatch. These remain explicit integration gaps, not inferred successes.
