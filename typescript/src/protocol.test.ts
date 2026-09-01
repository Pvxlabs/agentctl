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
import { MemoryReplayStore, VerificationError, verifyAgentRequest, type Registry } from "./verifier.js";

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
