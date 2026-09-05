# Verifier SDK Contract

Target middleware should pass the following values without reserialization:

```text
assertion
HTTP method
request target
exact transmitted body bytes
content type
X-Agentctl-Request-ID
optional resource identifier
```

The verifier returns the machine principal, the one authorized scope, and
request-bound evidence. The target application remains responsible for
domain authentication, business authorization, validation, transaction
handling, and canonical readback.

## Trusted DEV identity establishment

For DEV-only interactive or agent entrypoints, use
`TrustedIdentityVerifier` after the server has obtained a
`TransportObservation` from its connection layer. Do not construct that
observation from `X-Forwarded-*`, `X-Real-IP`, or arbitrary request headers.
The Tailscale verifier's resolver must query a trusted server-side integration
(for example, the local Tailscale API) and return the authenticated peer
identity.

The verifier returns an application-neutral subject such as `dev-user` or
`dev-agent`, plus exact scopes. An application adapter then maps that subject
to its ordinary authenticated principal and starts its normal session. The
adapter must not skip application authorization or turn a trusted subject into
an unrestricted administrator.

See [Trusted Development Access](../docs/trusted-access.md) for the Python and
TypeScript integration examples, local agent issuance workflow, three identity
paths, and the `TRUSTED_DEV_ACCESS_INVARIANT` acceptance boundary.
