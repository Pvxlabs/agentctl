# CLI Contract

The CLI is intentionally a thin signer, verifier, and transport wrapper.

- `identity create` creates a local-development Ed25519 key file.
- `principals add|list|revoke` manages the file-backed development registry.
- `capabilities` lists actions from `.agent-control.yaml`.
- `trusted-access validate` validates and prints the optional DEV trusted-access
  policy; it never mints an assertion from caller-supplied IP/header values.
- `trusted-access issue` issues a short-lived localhost DEV identity assertion
  from a local DEV authority. It is intended for a local agent or test runner;
  remote Tailscale issuance belongs to an application-controlled authority
  endpoint with a server-side peer resolver.
- `sign` creates one assertion for one exact method, target, body, and request ID.
- `call` resolves one manifest action, signs it, calls its canonical API, and
  reports transport outcome without interpreting business success.
- `verify` verifies an assertion against exact request bytes and consumes its
  JTI in a durable SQLite replay store.
- `audit verify` checks the JSONL hash chain.

The local identity format is a development adapter. Production signers should
implement the same boundary using KMS, HSM, or workload identity.
