# agentctl

`agentctl` is a small, open-source authorization substrate for AI agents,
coding agents, and deployment controllers that must call protected APIs without
reusing human browser credentials or carrying long-lived administrator secrets.

The V1 boundary is deliberately narrow:

```text
machine identity
  -> scoped, short-lived, request-bound assertion
  -> canonical target API
  -> target project's existing domain authority
  -> typed audit
```

agentctl answers:

- Who is calling?
- Where may it operate?
- What scope does it have?
- Which exact request is authorized?
- When is the authorization valid?
- Has this request been replayed?
- Which machine principal was audited?

It does not decide whether a deployment should go live, a release should be
activated, or an order should execute. Those decisions stay inside the target
project's canonical domain authority.

## Status

This repository is the V1 implementation described by [SPEC.md](SPEC.md).
The protocol is intentionally versioned and language-neutral. The Python
package contains the CLI and reference verifier; the TypeScript package
contains an independent verifier implementation used by the cross-language
conformance tests.

## Quick start

For AI-assisted development, the recommended first path is simply to ask the
coding agent:

```text
Integrate agentctl Trusted Access into this project.
```

The agent can install the pinned public release, install its canonical Skill,
inspect the project, and run the public onboarding workflow. No GitHub URL,
commit SHA, manifest schema, or DEV password is required from the user.

The canonical user-local install path is:

```bash
python3 -m pip install --user "git+https://github.com/Pvxlabs/agentctl.git@v0.1.1"
agentctl --version
agentctl skill install --update
```

For a consumer project, the manual fallback is:

```bash
agentctl trusted-access onboard --plan
agentctl trusted-access onboard
```

See [docs/distribution.md](docs/distribution.md) for the release contract and
compatibility behavior.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install '.[dev]'

agentctl identity create --principal-id demo-agent --out .agentctl/identity.json
agentctl principals add \
  --identity-file .agentctl/identity.json \
  --registry-file .agentctl/registry.json \
  --audience demo-api \
  --scope records.read
agentctl capabilities --manifest examples/generic-python/.agent-control.yaml
agentctl sign \
  --identity-file .agentctl/identity.json \
  --registry-file .agentctl/registry.json \
  --environment development \
  --audience demo-api \
  --scope records.read \
  GET /records \
  --out .agentctl/assertion.txt
agentctl verify \
  --assertion-file .agentctl/assertion.txt \
  --registry-file .agentctl/registry.json \
  --replay-db .agentctl/replay.sqlite \
  --environment development \
  --audience demo-api \
  --request-id REQUEST_ID_FROM_SIGN_OUTPUT \
  GET /records
```

`verify` requires the same request ID that was bound into the assertion. In a
real middleware, read it from the `X-Agentctl-Request-ID` header and pass the
exact transmitted body bytes to the verifier.

The first command creates a local-development key. Production deployments
should use a signer adapter backed by KMS, HSM, or workload identity; V1 does
not implement a secret manager.

## Repository layout

- `protocol/`: language-neutral wire and canonicalization specification.
- `cli/`: CLI surface notes and command contract.
- `python/agentctl/`: Python protocol, CLI, verifier, registry, replay, audit,
  and manifest modules.
- `verifier/`: verifier SDK contract shared by target middleware adapters.
- `storage/`: replay and audit storage contract notes.
- `typescript/`: independent TypeScript verifier and protocol implementation.
- `schemas/`: JSON Schemas for assertions and project manifests.
- `vectors/`: cross-language golden vectors.
- `examples/`: generic middleware, ORION/Terminal adapter contracts, and
  runnable Trusted Access FastAPI/Express references.
- `python/agentctl/trusted.py`: Trusted Development Access authority,
  transport proofs, signed identity assertions, and application adapter hook.
- `skills/agentctl/SKILL.md`: canonical instructions for Trusted Access onboarding agents.
- `skill/SKILL.md`: legacy compatibility pointer to the canonical Skill.
- `docs/`: research notes and threat model.
- `tests/`: protocol, security, and parity tests.

## Security boundary

The verifier is fail-closed. It checks the assertion, registry state, policy,
request binding, and durable consume-once JTI before returning authorization
evidence. The target project's middleware must still perform its own
authentication, business authorization, domain validation, transaction, and
canonical readback.

The audit model never records private keys, raw credentials, or bearer tokens.
An `EXECUTED` audit event means the target request received a transport response;
it is not a claim that the target business operation succeeded.

## Trusted Development Access

Trusted DEV access is an identity-establishment path, not an authentication
disable switch. A target server passes server-owned connection metadata to the
authority or verifier:

```text
verified localhost/Tailscale transport
  -> explicit DEV policy
  -> application-neutral subject and scopes
  -> short-lived signed identity assertion
  -> application adapter maps subject to its normal session principal
  -> existing application authorization
```

`localhost` is proven from the socket peer address. `tailscale` requires both
the expected tailnet address range and a server-side peer identity resolver,
such as a Tailscale LocalAPI integration. Forwarded headers and a bare `100.x`
address are never sufficient. The core never contains application accounts;
ORION, Terminal, and other projects own their subject-to-account adapters.

The manifest policy is optional and disabled by default:

```yaml
trusted_access:
  enabled: true
  environment: dev
  transports: [localhost, tailscale]
  principals:
    user:
      subject: dev-user
      scopes: [app:read]
    agent:
      subject: dev-agent
      type: agent
      scopes: [app:read, app:test]
```

An enabled policy with a production environment, unknown transport, missing
principal, ambiguous fields, or a missing server-side transport verifier fails
closed. Existing AAV1 machine request authentication and production behavior
are unchanged.

The security invariant is explicit: Trusted DEV access requires an enabled DEV
policy, server-verified transport, an allowed application-neutral principal and
allowed scopes, an integrity-protected assertion, normal application
authorization, auditable decisions, and consume-once replay protection. Missing
or ambiguous configuration fails closed. See
[docs/trusted-access-protocol.md](docs/trusted-access-protocol.md) for the
verification order and [docs/trusted-access.md](docs/trusted-access.md) for
the Human Browser, AI Agent, and Production Machine paths.

### Canonical Runtime

The reusable authority runtime is initialized once per DEV host:

```bash
agentctl trusted-access bootstrap --manifest .agent-control.yaml
agentctl trusted-access status --manifest .agent-control.yaml
agentctl trusted-access doctor --manifest .agent-control.yaml
agentctl trusted-access issue \
  --manifest .agent-control.yaml \
  --principal agent \
  --scope app:read \
  --scope app:test \
  --out .agentctl/dev-agent.assertion
```

Runtime state defaults to `$AGENTCTL_RUNTIME_DIR`, then
`$XDG_STATE_HOME/agentctl/trusted-access`, then
`~/.local/state/agentctl/trusted-access`. It contains a private Ed25519
authority, public registry, durable replay database, hash-chained audit log,
and metadata. `rotate-authority` creates a new signing key while retaining
the previous key for normal short-lived assertion expiry; `revoke-authority`
explicitly disables a key. No runtime private key or mutable state belongs in
the repository.

## Development

```bash
python -m pytest
pnpm --dir typescript install
pnpm --dir typescript build
```

See [docs/threat-model.md](docs/threat-model.md) for residual risks and the
security review checklist.

## License

MIT. See [LICENSE](LICENSE).
