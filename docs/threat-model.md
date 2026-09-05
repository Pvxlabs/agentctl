# Threat Model

## Assets

- Machine principal identity and public-key registry state.
- Scope grants and environment/audience restrictions.
- Exact request authorization evidence.
- Replay ledger and revocation epochs.
- Typed audit records.
- Target project's domain authority and business data.

## Adversaries

- A prompt-injected agent attempting to redirect a valid action.
- An attacker replaying an old assertion.
- A network attacker modifying the assertion or request in transit.
- A compromised or misconfigured verifier with stale registry state.
- A malicious operator attempting to substitute a human identity.
- A storage attacker attempting to reset replay or revocation state.

## Controls

| Threat | V1 control |
| --- | --- |
| Assertion forgery | Ed25519 signature over fixed-prefix plus canonical payload. |
| Algorithm downgrade | Fixed `agentctl-aav1` prefix and Ed25519 only. |
| Request substitution | Method, canonical path/query, content type, exact body digest, audience, environment, and request ID binding. |
| Expired assertion | Exclusive `exp` check and maximum TTL. |
| Future assertion | `nbf` check. |
| Unknown/revoked key | Key registry status, expiry, ownership, and epoch checks. |
| Disabled/revoked principal | Principal status and epoch checks. |
| JTI replay | Atomic durable consume-once store. |
| Scope escalation | Exact explicit scope grant; no wildcard matching in V1. |
| Confused deputy | `iss == sub`, exact audience, exact request binding, and target-domain authority remains separate. |
| Secret leakage | No secret fields in manifests or audit; private key file permissions are restricted for local development. |
| Audit tampering | Append-only JSONL sink with hash chaining and verification command. |
| Trusted DEV transport spoofing | Socket peer metadata for localhost; server-side Tailscale peer resolver plus address-family check; forwarded headers rejected. |
| DEV identity replay | Short-lived `agentctl-tdi1` assertion with durable consume-once JTI. |
| DEV-to-production confusion | Trusted policy accepts only exact `dev`/`development`; enabled production policy is rejected; verifier rechecks environment. |
| Application account substitution | Core emits only application-neutral subjects; adapter owns mapping and normal application authorization remains required. |

Trusted Access is not applied to every private DEV page. P620 Performance
Console, DEV Portal, and similar observability/tooling pages may remain
localhost/Tailscale-only when they do not carry identity, role, scope, or
business authorization semantics.

## Residual risks

- A compromised agent holding a currently valid private key can make actions
  within its granted scope until expiry or revocation. V1 does not prove human
  intent or inspect prompt contents.
- Registry distribution and signer key protection are deployment concerns. V1
  provides file/env development adapters and interfaces for KMS/HSM/SPIFFE, not
  a production secret manager.
- Clock skew can cause valid assertions to be denied or, if an adopter widens
  skew carelessly, extend an authorization window. Keep clock skew explicit and
  bounded.
- A target API may return HTTP 200 while reporting a business failure in its
  payload. agentctl records transport outcome and never interprets that as
  domain success.
- Revocation is only as fresh as the verifier's registry read. Production
  deployments must define a bounded registry refresh and fail-closed behavior.

## Review questions

- Are all canonicalization routines identical across language implementations?
- Is the body hashed before any middleware re-serialization?
- Is replay storage durable, unique, and atomic across processes?
- Can a human cookie, password, bearer token, or database handle enter the
  agentctl process or audit sink?
- Does the target project still perform domain authorization and canonical
  readback after mutations?
- Does the integration grant only explicit production scopes and audiences?
- Is trusted DEV access explicitly enabled and independently configured for each
  DEV deployment?
- Is the Tailscale peer resolver backed by a server-side LocalAPI or equivalent,
  rather than request headers or an IP allowlist alone?
- Does the negative suite reject production enablement, missing or ambiguous
  environment, unknown principals, scope escalation, invalid/expired/tampered
  assertions, and spoofed forwarding headers?
