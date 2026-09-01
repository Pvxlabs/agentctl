import { createPublicKey, randomUUID } from "node:crypto";

import {
  AssertionPayload,
  MAX_TTL_SECONDS,
  ProtocolError,
  canonicalRequestTarget,
  normalizeContentType,
  parseAssertion,
  sha256Hex,
  verifySignature,
} from "./protocol.js";

export interface PrincipalRecord {
  principal_id: string;
  display_name: string;
  environment: string;
  enabled: boolean;
  revoked_at?: string | null;
  revocation_epoch: number;
  created_at?: string;
  updated_at?: string;
}

export interface KeyRecord {
  key_id: string;
  principal_id: string;
  algorithm: string;
  public_key: string;
  enabled: boolean;
  expires_at?: string | null;
  revoked_at?: string | null;
  key_epoch: number;
  created_at?: string;
}

export interface ScopeGrant {
  principal_id: string;
  environment: string;
  audience: string;
  scope: string;
  resource?: string | null;
}

export interface Registry {
  principals: PrincipalRecord[];
  keys: KeyRecord[];
  grants: ScopeGrant[];
}

export interface RequestContext {
  method: string;
  target: string;
  body: Uint8Array;
  contentType?: string;
  requestId?: string;
  resource?: string;
}

export interface ReplayStore {
  consume(jti: string, expiresAt: number, now: number): boolean;
}

export class MemoryReplayStore implements ReplayStore {
  private readonly entries = new Map<string, number>();

  consume(jti: string, expiresAt: number, now: number): boolean {
    for (const [key, expiry] of this.entries) if (expiry <= now) this.entries.delete(key);
    if (this.entries.has(jti)) return false;
    this.entries.set(jti, expiresAt);
    return true;
  }
}

export interface AuditEvent {
  event_id: string;
  principal_type: "machine";
  principal_id: string;
  key_id: string;
  environment: string;
  audience: string;
  scope: string;
  action: string;
  http_method: string;
  canonical_path: string;
  body_sha256: string;
  resource: string | null;
  request_id: string;
  jti: string;
  result: "AUTHORIZED" | "REJECTED";
  result_code: string;
  created_at: string;
}

export interface AuditSink {
  append(event: AuditEvent): void;
}

export class VerificationError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "VerificationError";
    this.code = code;
  }
}

export interface AuthorizationEvidence {
  principal_id: string;
  key_id: string;
  environment: string;
  audience: string;
  scope: string;
  request_id: string;
  jti: string;
  canonical_path: string;
  body_sha256: string;
  resource: string | null;
}

export interface VerificationResult {
  principal: PrincipalRecord;
  scopes: string[];
  evidence: AuthorizationEvidence;
}

function reject(code: string, message: string): never {
  throw new VerificationError(code, message);
}

function decodePublicKey(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) reject("INVALID_REGISTRY", "public key is not valid base64url");
  const raw = Buffer.from(value, "base64url");
  if (raw.toString("base64url") !== value || raw.length !== 32) reject("INVALID_REGISTRY", "Ed25519 public keys must be 32 bytes");
  return raw;
}

function publicKeyObject(value: string): ReturnType<typeof createPublicKey> {
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({ key: Buffer.concat([spkiPrefix, decodePublicKey(value)]), format: "der", type: "spki" });
}

function parseExpiry(value: string | null | undefined): number | null {
  if (value === undefined || value === null) return null;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) reject("INVALID_REGISTRY", "key expires_at is not valid RFC3339");
  return Math.floor(parsed / 1000);
}

function findPrincipal(registry: Registry, id: string): PrincipalRecord | undefined {
  return registry.principals.find((item) => item.principal_id === id);
}

function findKey(registry: Registry, id: string): KeyRecord | undefined {
  return registry.keys.find((item) => item.key_id === id);
}

function hasGrant(registry: Registry, payload: AssertionPayload): boolean {
  return registry.grants.some(
    (grant) =>
      grant.principal_id === payload.iss &&
      grant.environment === payload.environment &&
      grant.audience === payload.aud &&
      grant.scope === payload.scope &&
      (grant.resource === undefined || grant.resource === null || grant.resource === payload.resource),
  );
}

function isoNow(): string {
  return new Date().toISOString();
}

export function verifyAgentRequest(options: {
  assertion: string;
  request: RequestContext;
  registry: Registry;
  replayStore: ReplayStore;
  expectedAudience: string;
  expectedEnvironment: string;
  now: number;
  action?: string;
  auditSink?: AuditSink;
  maxTtlSeconds?: number;
  clockSkewSeconds?: number;
}): VerificationResult {
  let payload: AssertionPayload | undefined;
  const action = options.action ?? "verify_agent_request";
  const audit = (result: "AUTHORIZED" | "REJECTED", code: string, value: AssertionPayload | undefined): void => {
    const requestPath = (() => {
      try {
        return canonicalRequestTarget(options.request.target);
      } catch {
        return "";
      }
    })();
    options.auditSink?.append({
      event_id: randomUUID(),
      principal_type: "machine",
      principal_id: value?.iss ?? "",
      key_id: value?.kid ?? "",
      environment: value?.environment ?? "",
      audience: value?.aud ?? "",
      scope: value?.scope ?? "",
      action,
      http_method: typeof options.request.method === "string" ? options.request.method.toUpperCase() : "",
      canonical_path: requestPath || value?.canonical_path || "",
      body_sha256: sha256Hex(options.request.body),
      resource: value?.resource ?? null,
      request_id: options.request.requestId ?? value?.request_id ?? "",
      jti: value?.jti ?? "",
      result,
      result_code: code,
      created_at: isoNow(),
    });
  };
  const deny = (code: string, message: string): never => {
    audit("REJECTED", code, payload);
    return reject(code, message);
  };
  try {
    payload = parseAssertion(options.assertion).payload;
  } catch (error) {
    const protocol = error as ProtocolError;
    audit("REJECTED", protocol.code ?? "MALFORMED_ASSERTION", undefined);
    throw new VerificationError(protocol.code ?? "MALFORMED_ASSERTION", protocol.message);
  }
  const maxTtl = options.maxTtlSeconds ?? MAX_TTL_SECONDS;
  const skew = options.clockSkewSeconds ?? 0;
  if (typeof options.request.method !== "string" || options.request.method.length === 0) deny("INVALID_REQUEST", "HTTP method is required");
  if (!Number.isSafeInteger(options.now) || options.now < 0) deny("INVALID_CLOCK", "verifier now must be a non-negative integer");
  if (maxTtl <= 0 || maxTtl > MAX_TTL_SECONDS || skew < 0) deny("INVALID_CONFIGURATION", "invalid verifier time configuration");
  if (payload.exp - payload.iat > maxTtl) deny("TTL_EXCEEDED", "assertion exceeds verifier TTL");
  if (options.now + skew < payload.nbf) deny("NOT_YET_VALID", "assertion is not yet valid");
  if (options.now - skew >= payload.exp) deny("EXPIRED", "assertion has expired");

  const key = findKey(options.registry, payload.kid);
  if (!key) {
    audit("REJECTED", "UNKNOWN_KEY", payload);
    throw new VerificationError("UNKNOWN_KEY", "key is not registered");
  }
  if (key.algorithm !== "Ed25519") deny("UNSUPPORTED_KEY_ALGORITHM", "key algorithm is not Ed25519");
  if (!key.enabled) deny("KEY_DISABLED", "key is disabled");
  if (key.revoked_at) deny("KEY_REVOKED", "key is revoked");
  const expiry = parseExpiry(key.expires_at);
  if (expiry !== null && options.now >= expiry) deny("KEY_EXPIRED", "key is expired");
  const principal = findPrincipal(options.registry, key.principal_id);
  if (!principal) {
    audit("REJECTED", "UNKNOWN_PRINCIPAL", payload);
    throw new VerificationError("UNKNOWN_PRINCIPAL", "key owner principal is not registered");
  }
  if (!principal.enabled) deny("PRINCIPAL_DISABLED", "principal is disabled");
  if (principal.revoked_at) deny("PRINCIPAL_REVOKED", "principal is revoked");
  if (payload.principal_epoch !== principal.revocation_epoch) deny("PRINCIPAL_EPOCH_MISMATCH", "principal revocation epoch is stale");
  if (payload.key_epoch !== key.key_epoch) deny("KEY_EPOCH_MISMATCH", "key epoch is stale");
  try {
    verifySignature(parseAssertion(options.assertion), publicKeyObject(key.public_key));
  } catch (error) {
    const protocol = error as ProtocolError;
    deny(protocol.code ?? "BAD_SIGNATURE", protocol.message);
  }
  if (payload.iss !== principal.principal_id || payload.sub !== principal.principal_id) deny("WRONG_ISSUER", "assertion issuer is not the registered key owner");
  if (payload.aud !== options.expectedAudience) deny("WRONG_AUDIENCE", "assertion audience does not match verifier");
  if (payload.environment !== options.expectedEnvironment || payload.environment !== principal.environment) deny("WRONG_ENVIRONMENT", "assertion environment does not match verifier");
  if (payload.http_method !== options.request.method.toUpperCase()) deny("METHOD_MISMATCH", "HTTP method is not bound by the assertion");
  if (payload.canonical_path !== canonicalRequestTarget(options.request.target)) deny("PATH_MISMATCH", "request target is not bound by the assertion");
  if (payload.content_type !== normalizeContentType(options.request.contentType)) deny("CONTENT_TYPE_MISMATCH", "content type is not bound by the assertion");
  if (payload.body_sha256 !== sha256Hex(options.request.body)) deny("BODY_DIGEST_MISMATCH", "request body is not bound by the assertion");
  if (options.request.requestId === undefined || payload.request_id !== options.request.requestId) deny("REQUEST_ID_MISMATCH", "request ID is not bound by the assertion");
  if (payload.resource !== undefined && payload.resource !== options.request.resource) deny("RESOURCE_MISMATCH", "resource is not bound by the assertion");
  if (!hasGrant(options.registry, payload)) deny("SCOPE_DENIED", "no exact scope grant matches the assertion");
  if (!options.replayStore.consume(payload.jti, payload.exp, options.now)) deny("REPLAYED_JTI", "assertion JTI has already been consumed");
  const evidence: AuthorizationEvidence = {
    principal_id: principal.principal_id,
    key_id: key.key_id,
    environment: payload.environment,
    audience: payload.aud,
    scope: payload.scope,
    request_id: payload.request_id,
    jti: payload.jti,
    canonical_path: payload.canonical_path,
    body_sha256: payload.body_sha256,
    resource: payload.resource ?? null,
  };
  audit("AUTHORIZED", "AUTHORIZED", payload);
  return { principal, scopes: [payload.scope], evidence };
}
