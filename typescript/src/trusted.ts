import { createPublicKey, randomUUID, sign, verify } from "node:crypto";
import { isIP } from "node:net";

import { canonicalJsonBytes } from "./protocol.js";
import type { Registry } from "./verifier.js";

export const TRUSTED_IDENTITY_VERSION = "trusted-dev-identity/v1";
export const TRUSTED_IDENTITY_PREFIX = "agentctl-tdi1";
export const MAX_TRUSTED_IDENTITY_TTL_SECONDS = 300;

export class TrustedAccessError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "TrustedAccessError";
    this.code = code;
  }
}

export interface TrustedPrincipalPolicy {
  name: string;
  subject: string;
  scopes: string[];
  principal_type?: "human" | "agent" | "observer";
}

export interface TrustedAccessConfig {
  enabled: boolean;
  environment?: string;
  transports: string[];
  principals: Record<string, TrustedPrincipalPolicy>;
}

export interface TransportObservation {
  transport: "localhost" | "tailscale";
  peerAddress?: string;
  forwardedHeadersPresent?: boolean;
}

export interface TransportEvidence {
  transport: "localhost" | "tailscale";
  peerAddress: string;
  peerIdentity?: string;
}

export interface TransportVerifier {
  readonly transport: "localhost" | "tailscale";
  verify(observation: TransportObservation): TransportEvidence;
}

function fail(code: string, message: string): never {
  throw new TrustedAccessError(code, message);
}

function identifier(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value || !/^[A-Za-z0-9._:-]{1,256}$/u.test(value)) {
    fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", `${field} must be a trimmed identifier`);
  }
  return value;
}

function decodeTrustedPublicKey(value: unknown): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) fail("INVALID_REGISTRY", "public key is not valid base64url");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value || decoded.length !== 32) fail("INVALID_REGISTRY", "Ed25519 public keys must be 32 bytes");
  return decoded;
}

const KNOWN_TRANSPORTS = new Set(["localhost", "tailscale"]);
const PRINCIPAL_TYPES = new Set(["human", "agent", "observer"]);

function validateTrustedPrincipalPolicy(name: string, value: unknown): TrustedPrincipalPolicy {
  if (typeof name !== "string" || !/^[A-Za-z0-9._:-]{1,256}$/u.test(name)) {
    fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "principal name must be a trimmed identifier");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted principal policy is malformed");
  }
  const policy = value as Record<string, unknown>;
  const unknown = Object.keys(policy).filter((key) => !new Set(["name", "subject", "scopes", "principal_type", "type"]).has(key));
  if (unknown.length) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", `unknown trusted principal fields: ${unknown.join(", ")}`);
  const subject = identifier(policy.subject, `principal ${name} subject`);
  if (!Array.isArray(policy.scopes) || policy.scopes.length === 0 || policy.scopes.some((scope) => typeof scope !== "string")) {
    fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", `principal ${name} scopes must be a non-empty list`);
  }
  const scopes = policy.scopes.map((scope) => identifier(scope, `principal ${name} scope`));
  if (new Set(scopes).size !== scopes.length) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", `principal ${name} scopes must be unique`);
  if (policy.name !== undefined && policy.name !== name) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "principal policy name does not match its key");
  if (policy.type !== undefined && policy.principal_type !== undefined && policy.type !== policy.principal_type) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", `principal ${name} has ambiguous principal type`);
  const principalType = policy.principal_type ?? policy.type ?? (name === "agent" ? "agent" : "human");
  if (typeof principalType !== "string" || !PRINCIPAL_TYPES.has(principalType)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "principal type is unsupported");
  return { name, subject, scopes, principal_type: principalType as TrustedPrincipalPolicy["principal_type"] };
}

export function validateTrustedAccessConfig(config: TrustedAccessConfig): TrustedAccessConfig {
  if (typeof config !== "object" || config === null || Array.isArray(config)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted access config must be an object");
  const unknown = Object.keys(config).filter((key) => !new Set(["enabled", "environment", "transports", "principals"]).has(key));
  if (unknown.length) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", `unknown trusted_access fields: ${unknown.join(", ")}`);
  if (typeof config.enabled !== "boolean") fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.enabled must be boolean");
  if (config.environment !== undefined) identifier(config.environment, "trusted_access.environment");
  if (!Array.isArray(config.transports)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.transports must be a list");
  if (config.enabled && config.transports.length === 0) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "at least one trusted transport is required");
  if (new Set(config.transports).size !== config.transports.length) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted transports must be unique");
  for (const transport of config.transports) {
    if (typeof transport !== "string" || !KNOWN_TRANSPORTS.has(transport)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted transports must be localhost or tailscale");
  }
  if (config.enabled && !isDevEnvironment(config.environment)) fail("TRUSTED_ACCESS_NOT_DEV", "trusted access can only be enabled for DEV");
  if (config.principals === null || typeof config.principals !== "object" || Array.isArray(config.principals)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.principals must be an object");
  const entries = Object.entries(config.principals);
  if (config.enabled && entries.length === 0) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "at least one trusted principal is required");
  const normalized: Record<string, TrustedPrincipalPolicy> = {};
  for (const [name, value] of entries) normalized[name] = validateTrustedPrincipalPolicy(name, value);
  return { ...config, environment: config.environment, transports: [...config.transports], principals: normalized };
}

export function isDevEnvironment(environment: unknown): environment is "dev" | "development" {
  return environment === "dev" || environment === "development";
}

export class LocalhostTransportVerifier implements TransportVerifier {
  readonly transport = "localhost" as const;
  verify(observation: TransportObservation): TransportEvidence {
    if (observation.transport !== this.transport || observation.forwardedHeadersPresent) fail("UNTRUSTED_TRANSPORT", "localhost proof cannot use forwarding headers");
    const peer = observation.peerAddress;
    if (!peer || isIP(peer) === 0 || !(peer === "127.0.0.1" || peer === "::1" || peer.startsWith("127."))) fail("UNTRUSTED_TRANSPORT", "peer is not loopback");
    return { transport: this.transport, peerAddress: peer };
  }
}

export class TailscaleTransportVerifier implements TransportVerifier {
  readonly transport = "tailscale" as const;
  constructor(private readonly resolvePeer: (peerAddress: string) => string | undefined) {}
  verify(observation: TransportObservation): TransportEvidence {
    if (observation.transport !== this.transport || observation.forwardedHeadersPresent) fail("UNTRUSTED_TRANSPORT", "Tailscale proof cannot use forwarding headers");
    const peer = observation.peerAddress;
    if (!peer || isIP(peer) !== 4 || !peer.startsWith("100.")) fail("UNTRUSTED_TRANSPORT", "peer is not in the configured Tailscale address family");
    const octets = peer.split(".").map(Number);
    if (octets[0] !== 100 || octets[1] < 64 || octets[1] > 127) fail("UNTRUSTED_TRANSPORT", "peer is outside the Tailscale CGNAT range");
    let peerIdentity: string | undefined;
    try { peerIdentity = this.resolvePeer(peer); } catch { fail("UNTRUSTED_TRANSPORT", "Tailscale peer identity could not be verified"); }
    if (!peerIdentity?.trim()) fail("UNTRUSTED_TRANSPORT", "Tailscale peer identity was not verified by the server-side resolver");
    return { transport: this.transport, peerAddress: peer, peerIdentity: peerIdentity.trim() };
  }
}

function b64(value: Uint8Array): string { return Buffer.from(value).toString("base64url"); }
function decode(value: unknown): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) fail("MALFORMED_TRUSTED_ASSERTION", "invalid base64url segment");
  const result = Buffer.from(value, "base64url");
  if (result.toString("base64url") !== value) fail("MALFORMED_TRUSTED_ASSERTION", "invalid base64url segment");
  return result;
}

export interface TrustedIdentityPayload {
  version: string; iss: string; sub: string; principal_type: "human" | "agent" | "observer"; scopes: string[];
  aud: string; environment: string; transport: "localhost" | "tailscale"; iat: number; nbf: number; exp: number;
  jti: string; kid: string; principal_epoch: number; key_epoch: number; peer_identity?: string;
}

function validatePayload(value: unknown): TrustedIdentityPayload {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("MALFORMED_TRUSTED_ASSERTION", "payload must be an object");
  const payload = value as Record<string, unknown>;
  const allowed = new Set(["version", "iss", "sub", "principal_type", "scopes", "aud", "environment", "transport", "iat", "nbf", "exp", "jti", "kid", "principal_epoch", "key_epoch", "peer_identity"]);
  const unknown = Object.keys(payload).filter((key) => !allowed.has(key));
  if (unknown.length) fail("MALFORMED_TRUSTED_ASSERTION", `unknown trusted assertion fields: ${unknown.join(", ")}`);
  if (payload.version !== TRUSTED_IDENTITY_VERSION) fail("WRONG_TRUSTED_ASSERTION_VERSION", "unsupported trusted identity assertion version");
  for (const field of ["iss", "sub", "aud", "environment", "jti", "kid"]) identifier(payload[field], field);
  if (!["human", "agent", "observer"].includes(String(payload.principal_type))) fail("MALFORMED_TRUSTED_ASSERTION", "unsupported principal type");
  if (payload.transport !== "localhost" && payload.transport !== "tailscale") fail("MALFORMED_TRUSTED_ASSERTION", "unsupported transport");
  if (!Array.isArray(payload.scopes) || payload.scopes.length === 0 || payload.scopes.some((scope) => typeof scope !== "string") || JSON.stringify(payload.scopes) !== JSON.stringify([...new Set(payload.scopes)].sort())) fail("MALFORMED_TRUSTED_ASSERTION", "scopes must be sorted, unique, and non-empty");
  payload.scopes.forEach((scope) => identifier(scope, "scope"));
  for (const field of ["iat", "nbf", "exp", "principal_epoch", "key_epoch"]) if (!Number.isSafeInteger(payload[field]) || Number(payload[field]) < 0) fail("MALFORMED_TRUSTED_ASSERTION", `${field} must be a non-negative integer`);
  if (Number(payload.iat) > Number(payload.nbf) || Number(payload.exp) <= Number(payload.nbf)) fail("INVALID_TRUSTED_TIME_WINDOW", "iat <= nbf < exp is required");
  if (Number(payload.exp) - Number(payload.iat) > MAX_TRUSTED_IDENTITY_TTL_SECONDS) fail("TRUSTED_ASSERTION_TTL_EXCEEDED", "trusted identity assertion TTL is too long");
  if (payload.peer_identity !== undefined) identifier(payload.peer_identity, "peer_identity");
  return payload as unknown as TrustedIdentityPayload;
}

export function parseTrustedIdentityAssertion(compact: string): { payload: TrustedIdentityPayload; signature: Buffer; payloadSegment: string } {
  const parts = compact.split(".");
  if (parts.length !== 3 || parts[0] !== TRUSTED_IDENTITY_PREFIX) fail("MALFORMED_TRUSTED_ASSERTION", "invalid trusted assertion envelope");
  const bytes = decode(parts[1]);
  const signature = decode(parts[2]);
  if (signature.length !== 64) fail("MALFORMED_TRUSTED_ASSERTION", "Ed25519 signatures must be 64 bytes");
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString("utf8")); } catch { fail("MALFORMED_TRUSTED_ASSERTION", "payload is not valid JSON"); }
  const payload = validatePayload(parsed);
  if (!canonicalJsonBytes(payload as never).equals(bytes)) fail("MALFORMED_TRUSTED_ASSERTION", "payload is not canonical JSON");
  return { payload, signature, payloadSegment: parts[1] };
}

export class TrustedAccessAuthority {
  private readonly config: TrustedAccessConfig;

  constructor(private readonly privateKey: import("node:crypto").KeyObject, private readonly authorityPrincipalId: string, private readonly authorityKeyId: string, private readonly registry: Registry, config: TrustedAccessConfig, private readonly verifiers: Record<string, TransportVerifier>) {
    this.config = validateTrustedAccessConfig(config);
    if (!this.config.enabled) fail("TRUSTED_ACCESS_DISABLED", "trusted DEV access is not enabled");
    const principal = registry.principals.find((item) => item.principal_id === authorityPrincipalId);
    const key = registry.keys.find((item) => item.key_id === authorityKeyId);
    if (!principal || !key || key.principal_id !== authorityPrincipalId) fail("AUTHORITY_NOT_REGISTERED", "authority is not registered");
    if (principal.environment !== this.config.environment || !isDevEnvironment(principal.environment)) fail("AUTHORITY_NOT_DEV", "authority identity is not DEV");
    if (!principal.enabled || principal.revoked_at) fail("AUTHORITY_REVOKED", "authority principal is disabled or revoked");
    if (!key.enabled || key.revoked_at) fail("AUTHORITY_REVOKED", "authority key is disabled or revoked");
    if (key.algorithm !== "Ed25519") fail("AUTHORITY_ALGORITHM_UNSUPPORTED", "authority key algorithm is unsupported");
    if (key.expires_at !== undefined && key.expires_at !== null && Number.isNaN(Date.parse(key.expires_at))) fail("INVALID_REGISTRY", "authority key expires_at is invalid");
    if (privateKey.asymmetricKeyType !== "ed25519") fail("AUTHORITY_ALGORITHM_UNSUPPORTED", "authority private key algorithm is unsupported");
    const publicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" }) as Buffer;
    if (!publicKey.subarray(-32).equals(decodeTrustedPublicKey(key.public_key))) fail("AUTHORITY_KEY_MISMATCH", "authority key does not match private key");
  }
  issue(input: { requestedPrincipal: string; audience: string; scopes: string[]; observation: TransportObservation; now: number; ttlSeconds?: number }): string {
    if (!this.config.transports.includes(input.observation.transport)) fail("TRANSPORT_NOT_ALLOWED", "transport is not enabled by policy");
    const transport = this.verifiers[input.observation.transport]?.verify(input.observation);
    if (!transport) fail("TRANSPORT_VERIFIER_MISSING", "no server-side verifier is configured");
    const policy = this.config.principals[input.requestedPrincipal];
    if (!policy) fail("UNKNOWN_TRUSTED_PRINCIPAL", "requested trusted principal is not allowed");
    if (!input.scopes.length || new Set(input.scopes).size !== input.scopes.length || input.scopes.some((scope) => !policy.scopes.includes(scope))) fail("SCOPE_DENIED", "requested scope is not allowed");
    input.scopes.forEach((scope) => identifier(scope, "requested scope"));
    identifier(input.audience, "audience");
    const principal = this.registry.principals.find((item) => item.principal_id === this.authorityPrincipalId);
    const key = this.registry.keys.find((item) => item.key_id === this.authorityKeyId);
    if (!principal || !key || key.principal_id !== this.authorityPrincipalId) fail("AUTHORITY_NOT_REGISTERED", "authority is not registered");
    const now = input.now;
    const ttl = input.ttlSeconds ?? 60;
    if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(ttl) || ttl <= 0 || ttl > MAX_TRUSTED_IDENTITY_TTL_SECONDS) fail("INVALID_TRUSTED_TIME_WINDOW", "invalid trusted assertion time or TTL");
    if (key.algorithm !== "Ed25519" || !key.enabled || key.revoked_at) fail("AUTHORITY_REVOKED", "authority is disabled or revoked");
    if (key.expires_at !== undefined && key.expires_at !== null) {
      const expiresAt = Date.parse(key.expires_at);
      if (Number.isNaN(expiresAt)) fail("INVALID_REGISTRY", "authority key expires_at is invalid");
      if (expiresAt <= now * 1000) fail("KEY_EXPIRED", "trusted access authority key is expired");
    }
    const payload: TrustedIdentityPayload = { aud: input.audience, environment: this.config.environment!, exp: now + ttl, iat: now, iss: this.authorityPrincipalId, jti: randomUUID(), key_epoch: key.key_epoch, kid: this.authorityKeyId, nbf: now, principal_epoch: principal.revocation_epoch, principal_type: policy.principal_type ?? (policy.name === "agent" ? "agent" : "human"), scopes: [...input.scopes].sort(), sub: policy.subject, transport: transport.transport, version: TRUSTED_IDENTITY_VERSION, ...(transport.peerIdentity ? { peer_identity: transport.peerIdentity } : {}) };
    validatePayload(payload);
    const payloadSegment = b64(canonicalJsonBytes(payload as never));
    return `${TRUSTED_IDENTITY_PREFIX}.${payloadSegment}.${b64(sign(null, Buffer.from(`${TRUSTED_IDENTITY_PREFIX}.${payloadSegment}`, "ascii"), this.privateKey))}`;
  }
}

export class TrustedIdentityVerifier {
  private readonly config: TrustedAccessConfig;

  constructor(private readonly registry: Registry, config: TrustedAccessConfig, private readonly replayStore: { consume(jti: string, expiresAt: number, now: number): boolean }, private readonly expectedAudience: string, private readonly verifiers: Record<string, TransportVerifier>) {
    this.config = validateTrustedAccessConfig(config);
    if (!this.config.enabled) fail("TRUSTED_ACCESS_DISABLED", "trusted DEV access is not enabled");
    if (!isDevEnvironment(this.config.environment)) fail("TRUSTED_ACCESS_NOT_DEV", "trusted access can only be enabled for DEV");
    identifier(expectedAudience, "expected audience");
  }
  verify(assertion: string, input: { observation: TransportObservation; now: number }): TrustedIdentityPayload {
    const parsed = parseTrustedIdentityAssertion(assertion);
    const payload = parsed.payload;
    if (payload.aud !== this.expectedAudience) fail("WRONG_AUDIENCE", "trusted assertion audience does not match verifier");
    if (payload.environment !== this.config.environment || !isDevEnvironment(payload.environment)) fail("WRONG_ENVIRONMENT", "trusted assertion environment does not match verifier");
    if (input.now < payload.nbf) fail("NOT_YET_VALID", "trusted assertion is not yet valid");
    if (input.now >= payload.exp) fail("EXPIRED", "trusted assertion has expired");
    if (payload.transport !== input.observation.transport || !this.config.transports.includes(payload.transport)) fail("UNTRUSTED_TRANSPORT", "asserted transport is not allowed");
    const transport = this.verifiers[payload.transport]?.verify(input.observation);
    if (!transport || (payload.peer_identity !== undefined && payload.peer_identity !== transport.peerIdentity)) fail("UNTRUSTED_TRANSPORT", "current transport proof does not match assertion");
    const key = this.registry.keys.find((item) => item.key_id === payload.kid);
    const principal = key && this.registry.principals.find((item) => item.principal_id === key.principal_id);
    if (!key || !principal) fail("UNKNOWN_KEY", "trusted assertion authority is not registered");
    if (key.algorithm !== "Ed25519") fail("AUTHORITY_ALGORITHM_UNSUPPORTED", "trusted assertion authority algorithm is unsupported");
    if (key.expires_at !== undefined && key.expires_at !== null) {
      const expiresAt = Date.parse(key.expires_at);
      if (Number.isNaN(expiresAt)) fail("INVALID_REGISTRY", "key expires_at is not valid RFC3339");
      if (expiresAt <= input.now * 1000) fail("KEY_EXPIRED", "trusted assertion authority key is expired");
    }
    if (!key.enabled || key.revoked_at || !principal.enabled || principal.revoked_at) fail("AUTHORITY_REVOKED", "trusted assertion authority is disabled or revoked");
    if (payload.iss !== principal.principal_id || payload.key_epoch !== key.key_epoch || payload.principal_epoch !== principal.revocation_epoch) fail("STALE_AUTHORITY_EPOCH", "trusted assertion authority epoch is stale");
    const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
    try { if (!verify(null, Buffer.from(`${TRUSTED_IDENTITY_PREFIX}.${parsed.payloadSegment}`, "ascii"), createPublicKey({ key: Buffer.concat([spkiPrefix, decodeTrustedPublicKey(key.public_key)]), format: "der", type: "spki" }), parsed.signature)) fail("BAD_SIGNATURE", "trusted identity assertion signature verification failed"); } catch (error) { if (error instanceof TrustedAccessError) throw error; fail("BAD_SIGNATURE", "trusted identity assertion signature verification failed"); }
    const policy = Object.values(this.config.principals).find((item) => item.subject === payload.sub && (item.principal_type ?? (item.name === "agent" ? "agent" : "human")) === payload.principal_type);
    if (!policy || payload.scopes.some((scope) => !policy.scopes.includes(scope))) fail("SCOPE_DENIED", "trusted assertion principal or scope is not allowed");
    if (!this.replayStore.consume(payload.jti, payload.exp, input.now)) fail("REPLAYED_JTI", "trusted identity assertion has already been consumed");
    return payload;
  }
}
