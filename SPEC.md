# agentctl V1 SPEC

Status: implementation contract
Protocol: Agent Action Assertion v1
Date: 2026-09-01

## 1. Objective and boundaries

agentctl is a cross-project machine identity and exact-action authorization
layer. It is not an IAM replacement, deployment controller, workflow engine,
secret manager, database proxy, browser automation layer, or business
authorization system.

The target project remains authoritative for domain authentication, business
authorization, validation, transactions, and execution audit. agentctl must
never map a machine principal to a fake human user.

V1 has no runtime dependency on SPIRE, OPA, Cedar, Kubernetes, service mesh,
external PKI, or a hosted control plane. Interfaces are replaceable so those
systems can be adapters later.

## 2. Naming candidates

The CLI name is `agentctl`. Formal project name candidates after discovery:

1. Agentctl
2. Scopebound
3. RequestSeal
4. AttestPath
5. Machine Action Authorization

The implementation uses `agentctl` as the working project name because naming
does not affect the wire protocol.

## 3. Trust model

```text
Agent process
  holds a short-lived signing capability
  creates one assertion for one exact request
        |
        v
Target middleware / verifier
  checks signature, registry, time, scope, request binding, and replay
        |
        v
Target domain authority
  performs its own business authorization and transaction
```

The agent is assumed to be steerable by prompt injection. Request binding limits
the blast radius but does not prove human intent. A compromised agent that can
use an otherwise valid key can still make an authorized action within its
granted scope; narrow scopes, short TTLs, revocation, and target-domain checks
are required controls.

## 4. Assertion wire format

An assertion is a compact three-part value:

```text
agentctl-aav1.<base64url(canonical-json(payload))>.<base64url(ed25519-signature)>
```

The prefix is fixed. There is no algorithm negotiation in V1. The signature is
over the ASCII bytes of the prefix, a dot, and the payload segment:

```text
signing_input = b"agentctl-aav1." + payload_segment_ascii
```

The payload has these required fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | string | Exactly `agent-action-assertion/v1`. |
| `iss` | string | Principal that issued the assertion. |
| `sub` | string | Principal acting on the request. V1 requires `iss == sub`; delegation is future work. |
| `aud` | string | Exact target audience. |
| `environment` | string | Exact environment, such as `development` or `production`. |
| `scope` | string | One explicit scope. Wildcards are not matched in V1. |
| `iat` | integer | Unix timestamp in seconds when created. |
| `nbf` | integer | Unix timestamp in seconds when usable. |
| `exp` | integer | Exclusive expiry timestamp in seconds. |
| `jti` | string | Unique consume-once authorization identifier. |
| `kid` | string | Key registry identifier. |
| `http_method` | string | Uppercase transmitted HTTP method. |
| `canonical_path` | string | Canonical path plus canonical query. |
| `content_type` | string | Lowercase trimmed transmitted content type, or empty string. |
| `body_sha256` | string | Lowercase SHA-256 of the exact transmitted body bytes. |
| `request_id` | string | Correlation identifier supplied to the target API. |
| `principal_epoch` | integer | Principal revocation epoch at issuance. |
| `key_epoch` | integer | Key revocation epoch at issuance. |
| `resource` | string | Optional exact resource constraint. |
| `project` | string | Optional project identifier for audit/provenance. |

Unknown payload fields are rejected. The optional `resource` and `project`
fields are omitted rather than encoded as null when absent.

### 4.1 Canonical JSON

Canonical JSON is UTF-8, with object keys sorted lexicographically by Unicode
code point, no insignificant whitespace, no ASCII escaping for non-ASCII
characters, and standard JSON escaping for quotes, backslashes, and control
characters. Assertion values are limited to strings, booleans, integers, arrays,
objects, and null; V1 assertion fields use only strings and integers.

Timestamps are integer Unix seconds. HTTP methods are uppercase ASCII. SHA-256
values are lowercase hexadecimal. JTI, request ID, principal IDs, key IDs,
audiences, environments, scopes, and resources are non-empty trimmed strings.

### 4.2 Canonical request target

`canonical_path` is derived from the transmitted request target:

1. Fragments are rejected.
2. The path is `/` when empty and must begin with `/`.
3. Dot segments are rejected rather than interpreted.
4. Percent escapes must be valid. Unreserved percent-encoded bytes are decoded
   to their unreserved characters. Other percent escapes are retained with
   uppercase hex digits.
5. A query is split on `&`; each pair is split on its first `=`. Missing `=`
   means an empty value. Names and values are percent-decoded using RFC 3986
   plus `+` to space, sorted by decoded name then decoded value, and encoded
   with RFC 3986 percent encoding where spaces are `%20`, never `+`.
6. The canonical query is appended as `?name=value&name=value`; an absent or
   empty query is omitted.

The verifier recomputes this value from the actual request target. It does not
reconstruct a semantic JSON object from the body. Body binding always hashes the
bytes that will be transmitted.

### 4.3 TTL and time

The default maximum TTL is 300 seconds. `exp` must be greater than `nbf`,
`iat` must be no later than `nbf`, and `exp - iat` must not exceed the configured
maximum. The verifier denies when `now < nbf` or `now >= exp`. Clock skew is zero
by default and may only be widened explicitly by the target verifier.

## 5. Principal, key, and scope model

Principal registry records contain `principal_id`, `display_name`,
`environment`, `enabled`, timestamps, `revoked_at`, and `revocation_epoch`.
Key records contain `key_id`, `principal_id`, `algorithm` (exactly `Ed25519`),
public key bytes, status, timestamps, optional expiry, and `key_epoch`.

Scope grants contain `principal_id`, `environment`, `audience`, `scope`, and an
optional exact `resource`. An assertion is authorized only when one grant
matches all of those fields. Deny is the default.

The verifier denies unknown, disabled, expired, or revoked keys and principals;
it requires the assertion epochs to equal the currently registered epochs.

## 6. Verification order

The reference verifier performs these checks and returns a typed denial code on
the first failure:

1. Parse the compact format and canonical JSON.
2. Check fixed prefix, version, required fields, types, and unknown fields.
3. Validate time window and maximum TTL.
4. Load principal and key; check ownership, status, expiry, and epochs.
5. Verify Ed25519 over the exact signing input.
6. Compare issuer, subject, audience, environment, method, canonical path,
   content type, body digest, request ID, and optional resource.
7. Evaluate explicit scope policy.
8. Consume `jti` in durable replay storage in the same authorization path.
9. Append `AUTHORIZED` or `REJECTED` typed audit evidence.

The implementation never falls back to a human session, browser cookie, CSRF
token, administrator password, bearer token, or direct database mutation.

## 7. Replay and revocation

`jti` is consumed only after all other checks pass. The production contract for
the replay store is an atomic insert with a unique key. An in-memory store is
for tests only. The reference implementation includes SQLite storage using a
unique primary key and an immediate transaction.

Principal and key revocation is represented by status plus monotonically
versioned epochs. Revocation increments the epoch; assertions issued under an
older epoch are denied even if the key itself has not expired.

## 8. Audit contract

Audit events are typed and append-only:

```text
AUTHORIZED | REJECTED | EXECUTED | FAILED
```

Each event includes `event_id`, `principal_type`, `principal_id`, `key_id`,
`environment`, `audience`, `scope`, `action`, `http_method`, `canonical_path`,
`body_sha256`, `resource`, `request_id`, `jti`, `result`, `result_code`, and
`created_at`. The JSONL reference sink also records a hash chain for tamper
evidence. It never records private keys, secrets, raw credentials, or bearer
tokens.

`AUTHORIZED` means verifier authorization only. `EXECUTED` means a transport
response was received. `FAILED` means transport or local call failure. None of
these values claims that the target domain operation succeeded.

## 9. CLI and manifest

The CLI exposes:

```text
agentctl identity
agentctl principals
agentctl capabilities
agentctl sign
agentctl call
agentctl verify
agentctl audit
```

`.agent-control.yaml` declares project, audiences, and exact action routes. It
must not contain private keys or secrets. The CLI discovers it from the current
directory or an explicit path, validates it against the manifest schema, and
uses the selected action to construct one exact request.

## 10. Acceptance matrix

| Case | Expected |
| --- | --- |
| Valid request | PASS |
| Expired | DENY |
| Not yet valid | DENY |
| Wrong issuer | DENY |
| Wrong audience | DENY |
| Wrong environment | DENY |
| Missing scope grant | DENY |
| Wrong method | DENY |
| Wrong path/query | DENY |
| Body changed after signing | DENY |
| Bad signature | DENY |
| Unknown key | DENY |
| Revoked key | DENY |
| Disabled principal | DENY |
| Revoked principal | DENY |
| Replayed JTI | DENY |
| Malformed assertion | DENY |
| Python sign -> Python verify | PASS |
| Python sign -> TypeScript verify | PASS |
| TypeScript sign -> Python verify | PASS |
| TypeScript sign -> TypeScript verify | PASS |

## 11. Integration boundary

ORION integration is a contract/example only. It maps release read/import/
approve/activate scopes to ORION's existing canonical API and leaves
`StrategyReleaseRepository` and domain authority unchanged. Terminal integration
must first identify a suitable canonical machine-control API; no Terminal code is
copied and no production endpoint is called by this repository.

## 12. Definition of done

- Research and threat model are documented.
- Protocol, schema, CLI, Python verifier, and TypeScript verifier run locally.
- Durable replay and revocation checks are exercised.
- Golden vectors and cross-language parity pass.
- Generic, ORION, and Terminal adapter contracts exist without production code.
- Security matrix and independent review are complete.
- Commit status and push status are reported separately.
- Production mutation is `NO`.
