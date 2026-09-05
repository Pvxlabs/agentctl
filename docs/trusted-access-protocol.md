# Agentctl Trusted Identity Protocol v1

ATIP is the identity-establishment protocol used by Trusted Development
Access. Its public name is `Agentctl Trusted Identity Protocol`, its protocol
version is `ATIP-v1`, and its stable wire version is
`trusted-dev-identity/v1`.

ATIP is deliberately separate from Agent Action Assertion v1 (AAV1):

```text
ATIP: verified DEV transport -> signed application-neutral identity
AAV1: signed machine identity -> exact request authorization
```

The compact ATIP envelope is:

```text
agentctl-tdi1.<base64url(canonical-json(payload))>.<base64url(ed25519-signature)>
```

The signature covers the ASCII bytes of `agentctl-tdi1.` followed by the exact
payload segment. There is no algorithm negotiation. Ed25519 is required.

## Payload

Required fields are:

| Field | Meaning |
| --- | --- |
| `version` | Exactly `trusted-dev-identity/v1`. |
| `iss` | Registered DEV authority principal ID. |
| `sub` | Application-neutral subject such as `dev-user` or `dev-agent`. |
| `principal_type` | `human`, `agent`, or `observer`. |
| `scopes` | Sorted, unique, explicit application scopes. |
| `aud` | Exact application audience. |
| `environment` | `dev` or `development`; no production value is accepted. |
| `transport` | Verified transport identifier, currently `localhost` or `tailscale`. |
| `iat`, `nbf`, `exp` | Integer Unix-second validity window. `exp` is exclusive. |
| `jti` | Unique consume-once replay identifier. |
| `kid` | Registered Ed25519 authority key ID. |
| `principal_epoch` | Authority principal revocation epoch. |
| `key_epoch` | Authority key revocation epoch. |
| `peer_identity` | Optional server-resolved Tailscale peer identity. |

Unknown fields, non-canonical JSON, invalid identifiers, duplicate scopes,
invalid time windows, and TTLs longer than 300 seconds are rejected.

## Verification

The verifier evaluates, in order:

1. Envelope, canonical JSON, version, field types, and time window.
2. Exact audience and DEV environment.
3. Asserted transport against the current server-owned observation.
4. Registered key, principal ownership, status, expiry, and revocation epochs.
5. Ed25519 signature.
6. Explicit subject/type policy and scope subset.
7. Atomic consume-once JTI replay protection.
8. Typed audit event.

The verifier returns an `AgentctlPrincipal`; it does not create an application
cookie, session, database user, or browser identity.

## Transport proof

`TransportObservation` must be populated from the connection layer, not from
request headers. `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` are rejected
as proof. A raw `100.x.x.x` address is not sufficient for Tailscale.

The localhost verifier requires a loopback socket peer. The Tailscale verifier
requires an address in `100.64.0.0/10` or `fd7a:115c:a1e0::/48` plus a
server-side peer resolver. The Python provider
`TailscaleLocalAPITransportVerifier` uses the local
`/run/tailscale/tailscaled.sock` endpoint by default and calls
`/localapi/v0/whois?addr=<server-observed-peer>`. It requires the returned
`Node.Addresses` to contain the observed peer and emits `node:<StableID>` as
the generic peer identity. LocalAPI errors, unknown peers, malformed responses,
or address mismatches fail closed with `UNTRUSTED_TRANSPORT`.

The socket path and LocalAPI result are server-owned. An application must never
take the peer address, resolver result, or transport selection from a client
header. `TAILSCALE_SOCKET_PEER_INVARIANT` is the implementation invariant for
this binding: address-range membership alone never authorizes a request.

## Security invariant

```text
TRUSTED_DEV_ACCESS_INVARIANT

explicit enabled DEV policy
  + verified server-side transport
  + explicitly allowed subject/type
  + explicitly allowed scopes
  + authenticated integrity-protected assertion
  + auditable decision
  + consume-once JTI
  = Trusted DEV identity establishment
```

ATIP does not prove human intent. Application deployments must control which
principal an issuance path can request and must not expose a public arbitrary
principal selector.
