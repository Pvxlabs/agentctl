# Trusted Development Access

Trusted Development Access removes repeated interactive DEV login without
turning authentication or authorization off. It establishes a short-lived,
signed, application-neutral principal; the application then maps that subject
to its normal DEV account/session and continues its normal authorization.

```text
server-owned transport observation
  -> explicit enabled DEV policy
  -> allowed application-neutral subject and scopes
  -> signed ATIP-v1 assertion
  -> application adapter
  -> normal application principal/session
  -> normal application authorization and audit
```

The implementation is intentionally not an IAM, SSO, VPN, reverse proxy, or
general HTTP gateway. It is a small authority/verifier and adapter contract.

## Configuration

Add `trusted_access` to the existing `.agent-control.yaml` manifest. The
feature is disabled when omitted and fails closed when enabled outside DEV.

```yaml
trusted_access:
  enabled: true
  environment: dev
  transports:
    - localhost
    - tailscale
  application:
    identity: example-app
    audience: example-app-dev
  adapter:
    type: declarative_mapping
    mappings:
      dev-user: app-dev-user
      dev-admin: app-dev-admin
      dev-agent: app-dev-agent
  principals:
    user:
      subject: dev-user
      type: human
      scopes:
        - app:read
    admin:
      subject: dev-admin
      type: human
      scopes:
        - app:read
        - app:admin
    agent:
      subject: dev-agent
      type: agent
      scopes:
        - app:read
        - app:test
```

The mapping values are owned by the application. They are placeholders in the
CLI scaffold and must be replaced by each project. agentctl core does not
contain ORION, Terminal, or any other application's account names.

An enabled configuration requires an explicit DEV environment, unique known
transports, at least one principal, unique subject/type pairs, and explicit
scopes. Application and adapter fields are schema-validated and unknown fields
are rejected.

## Canonical DEV Runtime

`TrustedAccessRuntime` is the host-local lifecycle boundary for one reusable
DEV authority. It reuses `LocalIdentity`, `Registry`, `SQLiteReplayStore`, and
`JsonlAuditSink`; it does not introduce another wire protocol or proxy HTTP
traffic. The default layout is:

```text
$AGENTCTL_RUNTIME_DIR
or $XDG_STATE_HOME/agentctl/trusted-access
or ~/.local/state/agentctl/trusted-access

authority.json   # private Ed25519 identity, mode 0600
registry.json    # public registry and revocation state, mode 0600
replay.sqlite    # durable consume-once JTI store, mode 0600
audit.jsonl      # hash-chained lifecycle and access audit, mode 0600
runtime.json     # versioned runtime metadata, mode 0600
```

The directory is mode `0700`. Bootstrap requires an enabled DEV policy and
fails closed for missing, malformed, mismatched, revoked, or unsafe state. A
missing registry can be recovered only from a valid authority identity;
bootstrap never silently recreates a revoked authority. Rotation is explicit:
the new key becomes the issuance key and the previous key remains registered
until its assertions expire or an operator explicitly revokes it.

The lifecycle commands are:

```bash
agentctl trusted-access bootstrap --manifest .agent-control.yaml
agentctl trusted-access status --manifest .agent-control.yaml
agentctl trusted-access doctor --manifest .agent-control.yaml
agentctl trusted-access rotate-authority --manifest .agent-control.yaml
agentctl trusted-access revoke-authority --manifest .agent-control.yaml
```

All commands support `--runtime-dir` and `--json`. `doctor` additionally
checks the configured Tailscale LocalAPI socket when `tailscale` is enabled.
Runtime state is operational host state and must not be committed.

## Python integration

Install the application framework separately from agentctl, then construct the
SDK with the existing registry/replay components and an application adapter:

```python
from agentctl.application import DeclarativeMappingAdapter, TrustedAccessSDK
from agentctl.integrations.fastapi import create_fastapi_dependency
from agentctl.runtime import TrustedAccessRuntime, TrustedAccessRuntimePaths
from agentctl.trusted import (
    LocalhostTransportVerifier,
    TAILSCALE_LOCALAPI_SOCKET,
    TailscaleLocalAPIClient,
    TailscaleLocalAPITransportVerifier,
    TrustedIdentityVerifier,
)

runtime = TrustedAccessRuntime(TrustedAccessRuntimePaths.from_dir())
identity, registry, _authority, _authority_key = runtime.load_identity_registry(manifest)
transport_verifiers = {"localhost": LocalhostTransportVerifier()}
if "tailscale" in manifest.trusted_access.transports:
    transport_verifiers["tailscale"] = TailscaleLocalAPITransportVerifier(
        TailscaleLocalAPIClient(TAILSCALE_LOCALAPI_SOCKET)
    )

verifier = TrustedIdentityVerifier(
    registry,
    manifest.trusted_access,
    runtime.replay_store(),
    expected_audience="example-app-dev",
    audit_sink=runtime.audit_sink(),
    transport_verifiers=transport_verifiers,
)
sdk = TrustedAccessSDK(
    verifier,
    DeclarativeMappingAdapter({"dev-user": "app-dev-user"}),
)
current_application_principal = create_fastapi_dependency(sdk, transport="localhost")
```

The FastAPI dependency reads the actual socket peer from `request.client.host`,
rejects forwarding headers, stores both the `AgentctlPrincipal` and mapped
application principal on request state, and returns the mapped application
principal. The application still checks scopes and domain rules.

For custom applications, implement:

```python
class ApplicationAdapter:
    def establish(self, principal: AgentctlPrincipal):
        # Load/create the application's ordinary DEV session principal.
        # Keep application authorization after this point.
        ...
```

## TypeScript integration

The TypeScript SDK has the same contract and exports an Express middleware:

```ts
const verifier = new TrustedIdentityVerifier(
  registry,
  config,
  replayStore,
  "example-app-dev",
  { localhost: new LocalhostTransportVerifier() },
);
const sdk = new TrustedAccessSDK(
  verifier,
  new DeclarativeMappingAdapter({ "dev-user": "app-dev-user" }),
);
app.get("/me", createExpressTrustedAccessMiddleware(sdk), handler);
```

Use `authorizationScheme` to change the scheme and
`authorizationHeaderName` to change the header name. The default is
`Authorization: Agentctl-Trusted <assertion>`.

## Issuance

The local CLI path is:

```bash
agentctl trusted-access init --path .
agentctl trusted-access validate --manifest .agent-control.yaml
agentctl trusted-access doctor --manifest .agent-control.yaml
agentctl trusted-access bootstrap --manifest .agent-control.yaml
agentctl trusted-access issue \
  --manifest .agent-control.yaml \
  --principal agent \
  --scope app:read \
  --scope app:test \
  --out .agentctl/dev-agent.assertion
```

`trusted-access issue` uses the canonical local DEV runtime and a fixed loopback
observation. It is suitable for a local Codex, Claude, Playwright, or CI test
process. It does not accept a user-supplied IP, forwarding header, or
Tailscale identity. The explicit identity/registry file form remains available
for compatibility with older project-local setups.

For a remote Tailscale browser or agent, the application or a separately
controlled DEV authority must issue the assertion after verifying the actual
server-side peer with `TailscaleLocalAPITransportVerifier`. The issuer must not
expose an unrestricted endpoint such as `/issue?principal=admin`.

## Three identity paths

### Human Browser

The browser reaches a DEV application over a verified localhost or Tailscale
transport. A deployment-controlled entrypoint chooses an allowed DEV principal
according to its own policy, asks the authority for ATIP, and passes the
verified subject to the application adapter. The adapter creates the normal
application session; all application role and domain authorization remains
active. agentctl does not prove which human is behind a shared DEV network.

### AI Agent

An agent uses a local DEV machine identity and `trusted-access issue`, or calls
an application-controlled Tailscale DEV authority. It sends
`Authorization: Agentctl-Trusted <assertion>`. The application verifies ATIP,
maps `dev-agent` to its test principal, and enforces `app:read`, `app:test`,
or other explicitly configured scopes. No password, browser cookie, or hidden
login page is involved.

### Production Machine

Production machine-to-machine calls continue to use AAV1 (`Agentctl` scheme),
the existing principal registry, exact request binding, scope grants, replay
store, revocation epochs, and audit model. ATIP is DEV-only and cannot be
activated by a production environment configuration.

## CLI workflow

```text
trusted-access init
  -> creates or validates the existing manifest and local DEV authority state
trusted-access validate
  -> prints the normalized policy as JSON
trusted-access doctor
  -> checks authority, audience, adapter, scopes, transport prerequisites
trusted-access issue
  -> signs one short-lived local localhost identity assertion
trusted-access test
  -> runs one end-to-end local authority -> verifier -> principal smoke test
trusted-access conformance
  -> runs deterministic ATIP positive and negative cases
```

All commands emit machine-readable JSON. Configuration errors use exit code 2;
failed security tests and conformance use exit code 1.

## Consumer onboarding

Use the onboarding command to lower the cost of adding Trusted Access to a new
DEV application while keeping the existing authority, verifier, replay, audit,
and application adapter boundaries:

```bash
agentctl trusted-access onboard --path . --plan
agentctl trusted-access onboard --path .
```

`--plan` is read-only. It detects the project framework, reports existing
integration and candidate files, and shows the manifest/profile that would be
created; it does not write files or execute commands. The execution form may
write a new manifest atomically, bootstrap or reuse the canonical runtime, and
run the configured checks.

Onboarding never executes a discovered filename. Application startup, restart,
identity bootstrap, and smoke commands run only when they are explicitly
declared under `trusted_access.onboarding`, as argv arrays with `shell=False`.
An already healthy DEV application is reused. No daemon, supervisor, proxy, or
reverse proxy is created.

Identity lifecycle remains application-owned. A consumer may declare either an
adapter module or a command contract. An adapter owns its DEV datastore and
must implement `inspect_identity`, `ensure_identity`, `validate_role`, and
`validate_active`. A command bootstrap must return a verified JSON status:

```json
{
  "identities": {
    "user@test.local": {"active": true, "role": "user"},
    "admin@test.local": {"active": true, "role": "admin"}
  }
}
```

The command form is useful for an existing project bootstrap script; the
adapter form is useful when the application already exposes a typed identity
lifecycle API. They are mutually exclusive, and missing contracts fail
closed. The fallback password value may be passed to an application adapter
for DEV account creation, but credentials are never part of an assertion or
the canonical Trusted Access authentication path.

Onboarding metadata is not part of ATIP and does not change application
authorization. The application still maps `dev-user`, `dev-admin`, and
`dev-agent` to its own accounts, creates its ordinary session, and enforces
roles, scopes, CSRF, and domain permissions.

## P620 and internal tooling

P620 Performance Console, DEV Portal, and similar observability pages may stay
directly accessible when they are already strictly restricted to localhost or
Tailscale DEV networks and do not carry identity, role, scope, or business
authorization semantics. They do not need to be forced through agentctl.

## Reference applications

- `examples/trusted-access-fastapi/` is a runnable FastAPI integration.
- `examples/trusted-access-express/` is a runnable TypeScript/Express integration.

The FastAPI example uses the Python LocalAPI provider directly. The TypeScript
SDK keeps its existing synchronous verifier contract; its resolver callback is
useful for tests or an already-authenticated server-side provider, but is not a
production substitute for LocalAPI. A Node integration that needs live LocalAPI
verification should put the async Unix-socket lookup at its request boundary
and pass only the resulting server-owned peer identity into an async adapter;
agentctl does not spawn a blocking subprocess or trust request headers.

## Remaining security boundary

Transport proof establishes where the connection came from, not human intent.
The application owns principal selection for browser flows, controls issuance
endpoints, creates sessions, and performs domain authorization. A compromised
agent with a valid local authority key can act within its configured scopes
until expiry or revocation. Keep keys local to DEV, TTLs short, scopes narrow,
replay storage durable, and audit enabled.
