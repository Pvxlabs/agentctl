# CLI Contract

The CLI is intentionally a thin signer, verifier, and transport wrapper.

- `identity create` creates a local-development Ed25519 key file.
- `principals add|list|revoke` manages the file-backed development registry.
- `capabilities` lists actions from `.agent-control.yaml`.
- `trusted-access validate` validates and prints the optional DEV trusted-access
  policy; it never mints an assertion from caller-supplied IP/header values.
- `trusted-access bootstrap|status|doctor|rotate-authority|revoke-authority`
  manages the host-local Trusted DEV Access runtime. The default location is
  `$AGENTCTL_RUNTIME_DIR`, `$XDG_STATE_HOME/agentctl/trusted-access`, or
  `~/.local/state/agentctl/trusted-access`.
- `trusted-access issue` issues a short-lived localhost DEV identity assertion
  from the canonical runtime by default. `--runtime-dir` selects another
  runtime; the older `--identity-file` plus `--registry-file` form remains
  compatible. Remote Tailscale issuance belongs to an application-controlled
  authority endpoint with a server-side peer resolver.
- `sign` creates one assertion for one exact method, target, body, and request ID.
- `call` resolves one manifest action, signs it, calls its canonical API, and
  reports transport outcome without interpreting business success.
- `verify` verifies an assertion against exact request bytes and consumes its
  JTI in a durable SQLite replay store.
- `audit verify` checks the JSONL hash chain.

The runtime directory is host-local and private: the directory is `0700` and
its identity, registry, replay, audit, and metadata files are `0600`. Runtime
state is mutable operational data and must not be committed to source control.

The local identity format is a development adapter. Production signers should
implement the same boundary using KMS, HSM, or workload identity.
