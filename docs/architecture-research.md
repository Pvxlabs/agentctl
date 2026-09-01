# Architecture Discovery

Research date: 2026-09-01

## WHAT_TO_REUSE

- Ed25519 and SHA-256 from mature, audited cryptographic libraries.
- SPIFFE/SPIRE's separation between workload identity and application policy;
  future identity adapters can expose SVID-backed principals without changing
  the assertion verifier contract.
- OPA's policy decision point / policy enforcement point separation as a
  replaceable policy backend boundary.
- Cedar's explicit, typed, deny-by-default authorization semantics as a future
  policy adapter, not as a V1 runtime dependency.
- PortAuth's layered thinking: credential container, constrained payload, and
  deterministic fail-closed evaluation.
- Delego's exact-action fingerprinting, query canonicalization, durable
  conformance vectors, and distinction between authorization and enforcement.
- AgentAuth's explicit delegation-chain model as a future extension, while V1
  requires issuer and subject equality and does not implement delegation.
- OrgKernel's machine identity, bounded execution scope, and tamper-evident
  audit concerns, while avoiding its larger organizational governance surface.

## WHAT_TO_LEARN_FROM

- A valid credential is not enough: the exact request must be bound to the
  signed evidence to prevent confused-deputy substitution.
- Portable protocol work needs independent implementations and golden vectors;
  prose agreement is not byte-level interoperability.
- Query and body normalization are parser-differential attack surfaces.
- Replay state must be durable and atomically consumed in production.
- Verification must be deterministic and fail closed, with stable error codes.
- Audit needs typed semantics that distinguish authorization, attempted
  transport execution, and target-domain outcomes.
- Delegation, human approval, organizational hierarchy, and policy engines are
  separate concerns and should not be smuggled into a small request verifier.

## WHAT_NOT_TO_BUILD

- No SPIRE server, OPA server, Cedar service, Kubernetes controller, service
  mesh, external PKI, secret manager, database proxy, workflow engine, or API
  gateway in V1.
- No JWT algorithm negotiation, homemade cryptography, opaque wildcard scopes,
  human-session fallback, browser-cookie reader, CSRF simulator, or password
  broker.
- No target-project business decision logic and no direct database write path.
- No hosted global control plane or new superuser authority.
- No human approval workflow in the core protocol; this can be a future
  policy/approval adapter with its own contract.

## WHY_AGENTCTL_STILL_NEEDS_TO_EXIST

The adjacent projects cover different boundaries. Workload identity systems
issue or deliver identities; policy engines evaluate policy; intent-bound
authorization systems often include a broker or approval workflow; delegation
libraries preserve agent-to-agent authority chains; organizational kernels may
own identity, token minting, API endpoints, and large governance models.

agentctl's V1 is intentionally the narrow interoperability layer between an
agent process and a target project's canonical API: one machine principal, one
short-lived assertion, one exact request, one durable replay decision, and one
typed audit record. It is useful without forcing every adopter to run a new
distributed control plane or surrender domain authority to agentctl.

## Source inventory

- SPIFFE/SPIRE: official SPIFFE and SPIRE documentation.
- OPA: official Open Policy Agent documentation.
- Cedar: official Cedar documentation.
- PortAuth: `kyndryl-open-source/aiagent-portable-authorization` and its
  `w3id.org/portauth` namespace.
- Delego: `Delego-Dev/specification` and `Delego-Dev/delego`.
- AgentAuth: `nsquaredlabs/agentauth`.
- OrgKernel: `MetapriseAI/OrgKernel`.

The last three named projects are active open-source repositories with different
scopes and maturity. This document records design lessons rather than copying
their code or claiming protocol compatibility.
