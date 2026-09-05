# Agent Action Assertion v1

The wire format is:

```text
agentctl-aav1.<base64url(canonical-json(payload))>.<base64url(ed25519-signature)>
```

The signature covers the ASCII bytes of `agentctl-aav1.` plus the exact
payload segment. Canonical JSON uses UTF-8, lexicographically sorted object
keys, no insignificant whitespace, and no ASCII escaping for non-ASCII text.
Assertion fields use integer Unix seconds and lowercase SHA-256 hex.

Request targets bind the path and query, not a reserialized business object:
fragments and dot segments are rejected, unreserved path escapes are decoded,
query pairs are decoded and sorted by decoded name/value, and spaces are
encoded as `%20`. The body digest always covers the bytes sent on the wire.

See [SPEC.md](../SPEC.md) for the complete V1 contract.

Trusted Development Access uses a separate signed identity envelope:

```text
agentctl-tdi1.<base64url(canonical-json(payload))>.<base64url(ed25519-signature)>
```

It carries an application-neutral subject, exact sorted scopes, DEV
environment, audience, verified transport, authority key/epochs, and a
consume-once JTI. It is intentionally not an AAV1 request assertion and does
not contain application usernames or passwords.

See [Trusted Access Protocol](../docs/trusted-access-protocol.md) for the
ATIP-v1 payload, transport proof, verification order, and security invariant.
