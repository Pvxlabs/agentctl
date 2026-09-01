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
- `examples/`: generic middleware plus ORION and Terminal adapter contracts.
- `skill/SKILL.md`: instructions for coding and deployment agents.
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
