import assert from "node:assert/strict";
import { createPrivateKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  buildAssertion,
  canonicalRequestTarget,
  parseAssertion,
  sha256Hex,
} from "./protocol.js";
import { MemoryReplayStore, VerificationError, verifyAgentRequest, type AuditEvent, type Registry } from "./verifier.js";
import { LocalhostTransportVerifier, TailscaleTransportVerifier, TrustedAccessAuthority, TrustedAccessError, TrustedIdentityVerifier, type TrustedAccessConfig } from "./trusted.js";

const vector = JSON.parse(readFileSync(new URL("../../vectors/assertion-v1.json", import.meta.url), "utf8")) as {
  assertion: string;
  private_seed_base64url: string;
  public_key_base64url: string;
  request: { method: string; target: string; body: string; content_type: string; request_id: string; resource: string; body_sha256: string; canonical_path: string };
};
const seed = Buffer.from(vector.private_seed_base64url, "base64url");
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
  format: "der",
  type: "pkcs8",
});
const registry: Registry = {
  principals: [{ principal_id: "vector-agent", display_name: "Vector Agent", environment: "development", enabled: true, revocation_epoch: 0 }],
  keys: [{ key_id: "vector-key", principal_id: "vector-agent", algorithm: "Ed25519", public_key: vector.public_key_base64url, enabled: true, key_epoch: 0 }],
  grants: [{ principal_id: "vector-agent", environment: "development", audience: "vector-api", scope: "items.read", resource: "item:123" }],
};

function build(jti = "vector-jti-0001"): string {
  return buildAssertion({
    principalId: "vector-agent",
    audience: "vector-api",
    environment: "development",
    scope: "items.read",
    httpMethod: vector.request.method,
    target: vector.request.target,
    body: Buffer.from(vector.request.body, "utf8"),
    keyId: "vector-key",
    principalEpoch: 0,
    keyEpoch: 0,
    privateKey,
    contentType: vector.request.content_type,
    resource: vector.request.resource,
    project: "agentctl-conformance",
    requestId: vector.request.request_id,
    jti,
    now: 1_700_000_000,
    ttlSeconds: 300,
  });
}

test("TypeScript matches the shared golden vector", () => {
  assert.equal(build(), vector.assertion);
  assert.equal(canonicalRequestTarget(vector.request.target), vector.request.canonical_path);
  assert.equal(sha256Hex(Buffer.from(vector.request.body, "utf8")), vector.request.body_sha256);
  assert.equal(parseAssertion(vector.assertion).payload.scope, "items.read");
});

test("TypeScript verifier authorizes once and rejects replay", () => {
  const replayStore = new MemoryReplayStore();
  const request = {
    method: vector.request.method,
    target: vector.request.target,
    body: Buffer.from(vector.request.body, "utf8"),
    contentType: vector.request.content_type,
    requestId: vector.request.request_id,
    resource: vector.request.resource,
  };
  const options = { assertion: build("ts-jti-0001"), request, registry, replayStore, expectedAudience: "vector-api", expectedEnvironment: "development", now: 1_700_000_001 };
  assert.equal(verifyAgentRequest(options).evidence.scope, "items.read");
  assert.throws(() => verifyAgentRequest(options), (error: unknown) => error instanceof VerificationError && error.code === "REPLAYED_JTI");
});

test("TypeScript verifies the Python-produced compact assertion", () => {
  const result = verifyAgentRequest({
    assertion: vector.assertion,
    request: {
      method: vector.request.method,
      target: vector.request.target,
      body: Buffer.from(vector.request.body, "utf8"),
      contentType: vector.request.content_type,
      requestId: vector.request.request_id,
      resource: vector.request.resource,
    },
    registry,
    replayStore: new MemoryReplayStore(),
    expectedAudience: "vector-api",
    expectedEnvironment: "development",
    now: 1_700_000_001,
  });
  assert.equal(result.evidence.jti, "vector-jti-0001");
});

test("TypeScript verifier rejects request substitution", () => {
  assert.throws(
    () => verifyAgentRequest({ assertion: build("ts-jti-0002"), request: { method: "GET", target: vector.request.target, body: Buffer.from(vector.request.body), contentType: vector.request.content_type, requestId: vector.request.request_id, resource: vector.request.resource }, registry, replayStore: new MemoryReplayStore(), expectedAudience: "vector-api", expectedEnvironment: "development", now: 1_700_000_001 }),
    (error: unknown) => error instanceof VerificationError && error.code === "METHOD_MISMATCH",
  );
});

test("TypeScript Trusted DEV identity establishes an application-neutral subject once", () => {
  const config: TrustedAccessConfig = {
    enabled: true,
    environment: "development",
    transports: ["localhost"],
    principals: { agent: { name: "agent", subject: "dev-agent", principal_type: "agent", scopes: ["app:read", "app:test"] } },
  };
  const transport = new LocalhostTransportVerifier();
  const authority = new TrustedAccessAuthority(privateKey, "vector-agent", "vector-key", registry, config, { localhost: transport });
  const assertion = authority.issue({ requestedPrincipal: "agent", audience: "dev-api", scopes: ["app:test"], observation: { transport: "localhost", peerAddress: "127.0.0.1" }, now: 1_700_000_000 });
  const verifier = new TrustedIdentityVerifier(registry, config, new MemoryReplayStore(), "dev-api", { localhost: transport });
  const evidence = verifier.verify(assertion, { observation: { transport: "localhost", peerAddress: "127.0.0.1" }, now: 1_700_000_001 });
  assert.equal(evidence.sub, "dev-agent");
  assert.throws(() => verifier.verify(assertion, { observation: { transport: "localhost", peerAddress: "127.0.0.1" }, now: 1_700_000_001 }), (error: unknown) => error instanceof TrustedAccessError && error.code === "REPLAYED_JTI");
  assert.throws(() => transport.verify({ transport: "localhost", peerAddress: "100.90.1.2" }), (error: unknown) => error instanceof TrustedAccessError && error.code === "UNTRUSTED_TRANSPORT");
});

test("TypeScript Trusted DEV decisions use the existing audit sink without leaking assertions", () => {
  const config: TrustedAccessConfig = {
    enabled: true,
    environment: "development",
    transports: ["localhost"],
    principals: { agent: { subject: "dev-agent", principal_type: "agent", scopes: ["app:test"] } },
  };
  const transport = new LocalhostTransportVerifier();
  const events: AuditEvent[] = [];
  const auditSink = { append: (event: AuditEvent) => { events.push(event); } };
  const authority = new TrustedAccessAuthority(privateKey, "vector-agent", "vector-key", registry, config, { localhost: transport }, auditSink);
  const verifier = new TrustedIdentityVerifier(registry, config, new MemoryReplayStore(), "dev-api", { localhost: transport }, auditSink);
  const observation = { transport: "localhost", peerAddress: "127.0.0.1" };
  const assertion = authority.issue({ requestedPrincipal: "agent", audience: "dev-api", scopes: ["app:test"], observation, now: 1_700_000_000 });
  verifier.verify(assertion, { observation, now: 1_700_000_001 });
  assert.throws(() => verifier.verify(assertion, { observation, now: 1_700_000_001 }), (error: unknown) => error instanceof TrustedAccessError && error.code === "REPLAYED_JTI");
  assert.throws(() => verifier.verify("malformed", { observation, now: 1_700_000_001 }), (error: unknown) => error instanceof TrustedAccessError && error.code === "MALFORMED_TRUSTED_ASSERTION");
  assert.deepEqual(events.map((event) => [event.result, event.result_code, event.action]), [
    ["AUTHORIZED", "TRUSTED_IDENTITY_ISSUED", "trusted_dev.issue"],
    ["AUTHORIZED", "TRUSTED_IDENTITY_VERIFIED", "trusted_dev.verify"],
    ["REJECTED", "REPLAYED_JTI", "trusted_dev.verify"],
    ["REJECTED", "MALFORMED_TRUSTED_ASSERTION", "trusted_dev.verify"],
  ]);
  assert.ok(events.every((event) => event.principal_type === "trusted_dev"));
  assert.ok(events.every((event) => !("private_key" in event) && !("assertion" in event)));
});

test("TypeScript Trusted DEV transport resolver failures are audited and fail closed", () => {
  const config: TrustedAccessConfig = {
    enabled: true,
    environment: "development",
    transports: ["tailscale"],
    principals: { agent: { subject: "dev-agent", principal_type: "agent", scopes: ["app:test"] } },
  };
  const events: AuditEvent[] = [];
  const auditSink = { append: (event: AuditEvent) => { events.push(event); } };
  const transport = new TailscaleTransportVerifier(() => { throw new Error("resolver unavailable"); });
  const authority = new TrustedAccessAuthority(privateKey, "vector-agent", "vector-key", registry, config, { tailscale: transport }, auditSink);
  assert.throws(() => authority.issue({ requestedPrincipal: "agent", audience: "dev-api", scopes: ["app:test"], observation: { transport: "tailscale", peerAddress: "100.90.1.2" }, now: 1_700_000_000 }), (error: unknown) => error instanceof TrustedAccessError && error.code === "UNTRUSTED_TRANSPORT");
  assert.equal(events.at(-1)?.result_code, "UNTRUSTED_TRANSPORT");
  assert.equal(events.at(-1)?.result, "REJECTED");
});

test("TypeScript Trusted DEV identity rejects expiry, tampering, malformed keys, and production config", () => {
  const config: TrustedAccessConfig = {
    enabled: true,
    environment: "development",
    transports: ["localhost"],
    principals: { agent: { name: "agent", subject: "dev-agent", principal_type: "agent", scopes: ["app:test"] } },
  };
  const transport = new LocalhostTransportVerifier();
  const authority = new TrustedAccessAuthority(privateKey, "vector-agent", "vector-key", registry, config, { localhost: transport });
  const verifier = new TrustedIdentityVerifier(registry, config, new MemoryReplayStore(), "dev-api", { localhost: transport });
  const expired = authority.issue({ requestedPrincipal: "agent", audience: "dev-api", scopes: ["app:test"], observation: { transport: "localhost", peerAddress: "127.0.0.1" }, now: 1_700_000_000, ttlSeconds: 1 });
  assert.throws(() => verifier.verify(expired, { observation: { transport: "localhost", peerAddress: "127.0.0.1" }, now: 1_700_000_001 }), (error: unknown) => error instanceof TrustedAccessError && error.code === "EXPIRED");
  const fresh = authority.issue({ requestedPrincipal: "agent", audience: "dev-api", scopes: ["app:test"], observation: { transport: "localhost", peerAddress: "127.0.0.1" }, now: 1_700_000_000 });
  const parts = fresh.split(".");
  parts[2] = `${parts[2][0] === "A" ? "B" : "A"}${parts[2].slice(1)}`;
  assert.throws(() => verifier.verify(parts.join("."), { observation: { transport: "localhost", peerAddress: "127.0.0.1" }, now: 1_700_000_001 }), (error: unknown) => error instanceof TrustedAccessError && error.code === "BAD_SIGNATURE");
  const badRegistry = { ...registry, keys: [{ ...registry.keys[0], public_key: "bad" }] };
  const badVerifier = new TrustedIdentityVerifier(badRegistry, config, new MemoryReplayStore(), "dev-api", { localhost: transport });
  assert.throws(() => badVerifier.verify(fresh, { observation: { transport: "localhost", peerAddress: "127.0.0.1" }, now: 1_700_000_001 }), (error: unknown) => error instanceof TrustedAccessError && error.code === "INVALID_REGISTRY");
  assert.throws(() => new TrustedIdentityVerifier(registry, { ...config, environment: "production" }, new MemoryReplayStore(), "dev-api", { localhost: transport }), (error: unknown) => error instanceof TrustedAccessError && error.code === "TRUSTED_ACCESS_NOT_DEV");
  assert.throws(() => new TrustedIdentityVerifier(registry, { ...config, transports: ["localhost", "localhost"] }, new MemoryReplayStore(), "dev-api", { localhost: transport }), (error: unknown) => error instanceof TrustedAccessError && error.code === "INVALID_TRUSTED_ACCESS_CONFIGURATION");
});

test("TypeScript Trusted DEV identity enforces the configured application audience", () => {
  const config: TrustedAccessConfig = {
    enabled: true,
    environment: "development",
    transports: ["localhost"],
    application: { identity: "example", audience: "dev-api" },
    principals: { agent: { name: "agent", subject: "dev-agent", principal_type: "agent", scopes: ["app:test"] } },
  };
  const transport = new LocalhostTransportVerifier();
  const authority = new TrustedAccessAuthority(privateKey, "vector-agent", "vector-key", registry, config, { localhost: transport });
  assert.throws(() => authority.issue({ requestedPrincipal: "agent", audience: "other-api", scopes: ["app:test"], observation: { transport: "localhost", peerAddress: "127.0.0.1" }, now: 1_700_000_000 }), (error: unknown) => error instanceof TrustedAccessError && error.code === "WRONG_AUDIENCE");
  assert.throws(() => new TrustedIdentityVerifier(registry, config, new MemoryReplayStore(), "other-api", { localhost: transport }), (error: unknown) => error instanceof TrustedAccessError && error.code === "INVALID_TRUSTED_ACCESS_CONFIGURATION");
});

test("TypeScript Tailscale resolver errors are untrusted transport", () => {
  const verifier = new (class extends TailscaleTransportVerifier {
    constructor() { super(() => { throw new Error("resolver unavailable"); }); }
  })();
  assert.throws(() => verifier.verify({ transport: "tailscale", peerAddress: "100.90.1.2" }), (error: unknown) => error instanceof TrustedAccessError && error.code === "UNTRUSTED_TRANSPORT");
});

test("TypeScript Tailscale transport matches the configured IPv4 and IPv6 ranges", () => {
  const verifier = new TailscaleTransportVerifier((peer) => `node:${peer}`);
  assert.equal(verifier.verify({ transport: "tailscale", peerAddress: "100.90.1.2" }).peerIdentity, "node:100.90.1.2");
  assert.equal(verifier.verify({ transport: "tailscale", peerAddress: "fd7a:115c:a1e0::42" }).peerIdentity, "node:fd7a:115c:a1e0::42");
  assert.throws(() => verifier.verify({ transport: "tailscale", peerAddress: "100.63.1.2" }), (error: unknown) => error instanceof TrustedAccessError && error.code === "UNTRUSTED_TRANSPORT");
  assert.throws(() => verifier.verify({ transport: "tailscale", peerAddress: "fd7a:115c:a1e1::42" }), (error: unknown) => error instanceof TrustedAccessError && error.code === "UNTRUSTED_TRANSPORT");
});
