import { createPublicKey, randomUUID, sign, verify } from "node:crypto";
import { isIP } from "node:net";

import { canonicalJsonBytes, sha256Hex } from "./protocol.js";
import type { AuditEvent, AuditSink, Registry, ReplayStore } from "./verifier.js";

export const TRUSTED_IDENTITY_VERSION = "trusted-dev-identity/v1";
export const TRUSTED_IDENTITY_PREFIX = "agentctl-tdi1";
export const ATIP_PROTOCOL_NAME = "Agentctl Trusted Identity Protocol";
export const ATIP_VERSION = "ATIP-v1";
export const ATIP_WIRE_VERSION = TRUSTED_IDENTITY_VERSION;
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
  name?: string;
  subject: string;
  scopes: string[];
  principal_type?: "human" | "agent" | "observer";
}

export interface TrustedAccessConfig {
  enabled: boolean;
  environment?: string;
  transports: string[];
  principals: Record<string, TrustedPrincipalPolicy>;
  application?: { identity: string; audience?: string };
  adapter?: { type: "declarative_mapping" | "custom"; mappings?: Record<string, string> };
  /** Onboarding metadata is consumer-owned and has no ATIP wire semantics. */
  dev_profile?: Record<string, { principal: string; account: string; role: string }>;
  onboarding?: {
    identity_bootstrap?: {
      type: "command" | "adapter";
      command?: string[];
      module?: string;
    };
    start?: { command: string[] };
    restart?: { command: string[] };
    smoke?: { command: string[] };
  };
  handoff?: { enabled: boolean };
  ingress?: {
    mode: "session_bootstrap";
    bind: string;
    port: number;
    upstream: string;
    endpoint: string;
    surfaces: Record<string, { path: string; principal: string; audience: string; scopes: string[] }>;
  };
}

export interface TransportObservation {
  transport: string;
  peerAddress?: string;
  forwardedHeadersPresent?: boolean;
  handoff?: "trusted-ingress";
}

export interface TransportEvidence {
  transport: string;
  peerAddress: string;
  peerIdentity?: string;
}

export interface TrustedTransportVerifier {
  readonly transport: string;
  verify(observation: TransportObservation): TransportEvidence;
}

export type TransportVerifier = TrustedTransportVerifier;

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
  const unknown = Object.keys(config).filter((key) => !new Set(["enabled", "environment", "transports", "principals", "application", "adapter", "dev_profile", "onboarding", "handoff", "ingress"]).has(key));
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
  if (config.application !== undefined) {
    if (config.application === null || typeof config.application !== "object" || Array.isArray(config.application)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.application must be an object");
    const unknownApplication = Object.keys(config.application).filter((key) => !new Set(["identity", "audience"]).has(key));
    if (unknownApplication.length) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", `unknown trusted application fields: ${unknownApplication.join(", ")}`);
    identifier(config.application.identity, "trusted_access.application.identity");
    if (config.application.audience !== undefined) identifier(config.application.audience, "trusted_access.application.audience");
  }
  if (config.adapter !== undefined) {
    if (config.adapter === null || typeof config.adapter !== "object" || Array.isArray(config.adapter)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.adapter must be an object");
    const unknownAdapter = Object.keys(config.adapter).filter((key) => !new Set(["type", "mappings"]).has(key));
    if (unknownAdapter.length) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", `unknown trusted adapter fields: ${unknownAdapter.join(", ")}`);
    if (config.adapter.type !== "declarative_mapping" && config.adapter.type !== "custom") fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "unsupported trusted access adapter type");
    const mappings = config.adapter.mappings ?? {};
    if (mappings === null || typeof mappings !== "object" || Array.isArray(mappings)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted adapter mappings must be an object");
    for (const [subject, applicationIdentity] of Object.entries(mappings)) {
      identifier(subject, "trusted adapter subject");
      if (typeof applicationIdentity !== "string" || applicationIdentity.trim() !== applicationIdentity || applicationIdentity.length === 0) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted adapter application identity must be a trimmed string");
    }
    if (config.adapter.type === "declarative_mapping" && Object.keys(mappings).length === 0) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "declarative mapping adapter requires mappings");
  }
  if (config.dev_profile !== undefined) {
    if (config.dev_profile === null || typeof config.dev_profile !== "object" || Array.isArray(config.dev_profile)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.dev_profile must be an object");
    for (const [name, profile] of Object.entries(config.dev_profile)) {
      if (name.trim() !== name || name.length === 0 || profile === null || typeof profile !== "object" || Array.isArray(profile)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted dev profile entry is malformed");
      const unknownProfile = Object.keys(profile).filter((key) => !new Set(["principal", "account", "role"]).has(key));
      if (unknownProfile.length) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", `unknown trusted dev profile fields: ${unknownProfile.join(", ")}`);
      identifier(profile.principal, "trusted_access.dev_profile.principal");
      if (typeof profile.account !== "string" || profile.account.trim() !== profile.account || profile.account.length === 0) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.dev_profile.account must be a trimmed string");
      identifier(profile.role, "trusted_access.dev_profile.role");
    }
  }
  if (config.onboarding !== undefined) {
    if (config.onboarding === null || typeof config.onboarding !== "object" || Array.isArray(config.onboarding)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.onboarding must be an object");
    const unknownOnboarding = Object.keys(config.onboarding).filter((key) => !new Set(["identity_bootstrap", "start", "restart", "smoke"]).has(key));
    if (unknownOnboarding.length) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", `unknown trusted onboarding fields: ${unknownOnboarding.join(", ")}`);
    const validateCommand = (value: unknown, field: string) => {
      if (value === undefined) return;
      if (value === null || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((key) => key !== "command") || !Array.isArray((value as { command?: unknown }).command) || (value as { command: unknown[] }).command.length === 0 || (value as { command: unknown[] }).command.some((item) => typeof item !== "string" || item.trim().length === 0)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", `${field}.command must be a non-empty list of strings`);
    };
    validateCommand(config.onboarding.start, "onboarding.start");
    validateCommand(config.onboarding.restart, "onboarding.restart");
    validateCommand(config.onboarding.smoke, "onboarding.smoke");
    const bootstrap = config.onboarding.identity_bootstrap;
    if (bootstrap !== undefined) {
      if (bootstrap === null || typeof bootstrap !== "object" || Array.isArray(bootstrap)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "identity_bootstrap must be an object");
      const unknownBootstrap = Object.keys(bootstrap).filter((key) => !new Set(["type", "command", "module"]).has(key));
      if (unknownBootstrap.length) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", `unknown identity bootstrap fields: ${unknownBootstrap.join(", ")}`);
      if (bootstrap.type !== "command" && bootstrap.type !== "adapter") fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "identity bootstrap type must be command or adapter");
      if (bootstrap.type === "command") {
        validateCommand({ command: bootstrap.command }, "identity_bootstrap");
        if (bootstrap.module !== undefined) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "command identity bootstrap cannot declare module");
      } else {
        if (typeof bootstrap.module !== "string" || bootstrap.module.trim().length === 0) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "adapter identity bootstrap requires module");
        if (bootstrap.command !== undefined) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "adapter identity bootstrap cannot declare command");
      }
    }
  }
  if (config.handoff !== undefined && (config.handoff === null || typeof config.handoff !== "object" || Object.keys(config.handoff).some((key) => key !== "enabled") || typeof config.handoff.enabled !== "boolean")) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.handoff must contain boolean enabled");
  if (config.ingress !== undefined) {
    if (config.ingress === null || typeof config.ingress !== "object" || config.ingress.mode !== "session_bootstrap") fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress mode must be session_bootstrap");
    if (config.handoff?.enabled !== true) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress requires handoff.enabled");
    identifier(config.ingress.bind, "trusted ingress bind");
    if (!Number.isInteger(config.ingress.port) || config.ingress.port < 1 || config.ingress.port > 65535) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress port is invalid");
    if (!/^https?:\/\//u.test(config.ingress.upstream) || !config.ingress.endpoint.startsWith("/") || /[?#]/u.test(config.ingress.endpoint)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress upstream or endpoint is invalid");
    if (!config.ingress.surfaces || typeof config.ingress.surfaces !== "object" || Object.keys(config.ingress.surfaces).length === 0) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress surfaces must be non-empty");
    const paths = new Set<string>();
    for (const [name, surface] of Object.entries(config.ingress.surfaces)) {
      identifier(name, "trusted ingress surface name");
      if (!surface || typeof surface !== "object" || !surface.path.startsWith("/") || /[?#]/u.test(surface.path) || paths.has(surface.path) || !Array.isArray(surface.scopes) || surface.scopes.length === 0) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress surface is invalid");
      identifier(surface.principal, "trusted ingress surface principal");
      identifier(surface.audience, "trusted ingress surface audience");
      surface.scopes.forEach((scope) => identifier(scope, "trusted ingress surface scope"));
      paths.add(surface.path);
    }
  }
  const entries = Object.entries(config.principals);
  if (config.enabled && entries.length === 0) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "at least one trusted principal is required");
  const normalized: Record<string, TrustedPrincipalPolicy> = {};
  const identities = new Set<string>();
  for (const [name, value] of entries) {
    const policy = validateTrustedPrincipalPolicy(name, value);
    const identity = `${policy.subject}\u0000${policy.principal_type}`;
    if (identities.has(identity)) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted principal subject and type must be unique");
    identities.add(identity);
    normalized[name] = policy;
  }
  return { ...config, environment: config.environment, transports: [...config.transports], principals: normalized };
}

export function isDevEnvironment(environment: unknown): environment is "dev" | "development" {
  return environment === "dev" || environment === "development";
}

function parseIpv4(value: string): number | undefined {
  if (isIP(value) !== 4) return undefined;
  const octets = value.split(".").map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return undefined;
  return (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256) + octets[3];
}

function parseIpv6(value: string): number[] | undefined {
  if (isIP(value) !== 6) return undefined;
  const halves = value.split("::");
  if (halves.length > 2) return undefined;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const parseGroups = (groups: string[]) => groups.map((group) => /^[0-9a-f]{1,4}$/iu.test(group) ? Number.parseInt(group, 16) : -1);
  const leftValues = parseGroups(left);
  const rightValues = parseGroups(right);
  if (leftValues.some((group) => group < 0) || rightValues.some((group) => group < 0)) return undefined;
  const missing = 8 - leftValues.length - rightValues.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return undefined;
  return [...leftValues, ...Array.from({ length: missing }, () => 0), ...rightValues];
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
    if (!peer) fail("UNTRUSTED_TRANSPORT", "peer is not in the configured Tailscale address family");
    const ipv4 = parseIpv4(peer);
    const inIpv4Tailnet = ipv4 !== undefined && ipv4 >= 0x64400000 && ipv4 <= 0x647fffff;
    const ipv6 = parseIpv6(peer);
    const inIpv6Tailnet = ipv6 !== undefined && ipv6[0] === 0xfd7a && ipv6[1] === 0x115c && ipv6[2] === 0xa1e0;
    if (!inIpv4Tailnet && !inIpv6Tailnet) fail("UNTRUSTED_TRANSPORT", "peer is outside the configured Tailscale networks");
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
  aud: string; environment: string; transport: string; iat: number; nbf: number; exp: number;
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
  identifier(payload.transport, "transport");
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

function auditTrustedAccess(
  sink: AuditSink | undefined,
  result: "AUTHORIZED" | "REJECTED",
  code: string,
  payload: TrustedIdentityPayload | undefined,
  action: string,
): void {
  if (!sink) return;
  const event: AuditEvent = {
    event_id: randomUUID(),
    principal_type: "trusted_dev",
    principal_id: payload?.sub ?? "",
    key_id: payload?.kid ?? "",
    environment: payload?.environment ?? "",
    audience: payload?.aud ?? "",
    scope: payload?.scopes.join(",") ?? "",
    action,
    http_method: "",
    canonical_path: "",
    body_sha256: sha256Hex(Buffer.from("", "utf8")),
    resource: null,
    request_id: payload?.jti ?? "",
    jti: payload?.jti ?? "",
    result,
    result_code: code,
    created_at: new Date().toISOString(),
  };
  sink.append(event);
}

export class TrustedAccessAuthority {
  private readonly config: TrustedAccessConfig;

  constructor(private readonly privateKey: import("node:crypto").KeyObject, private readonly authorityPrincipalId: string, private readonly authorityKeyId: string, private readonly registry: Registry, config: TrustedAccessConfig, private readonly verifiers: Record<string, TransportVerifier>, private readonly auditSink?: AuditSink) {
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
    let payload: TrustedIdentityPayload | undefined;
    try {
      if (!this.config.transports.includes(input.observation.transport)) fail("TRANSPORT_NOT_ALLOWED", "transport is not enabled by policy");
      const verifier = this.verifiers[input.observation.transport];
      if (!verifier) fail("TRANSPORT_VERIFIER_MISSING", "no server-side verifier is configured");
      let transport: TransportEvidence;
      try {
        transport = verifier.verify(input.observation);
      } catch (error) {
        if (error instanceof TrustedAccessError) throw error;
        fail("UNTRUSTED_TRANSPORT", "trusted transport verification failed");
      }
      const policy = this.config.principals[input.requestedPrincipal];
      if (!policy) fail("UNKNOWN_TRUSTED_PRINCIPAL", "requested trusted principal is not allowed");
      if (!input.scopes.length || new Set(input.scopes).size !== input.scopes.length || input.scopes.some((scope) => !policy.scopes.includes(scope))) fail("SCOPE_DENIED", "requested scope is not allowed");
      input.scopes.forEach((scope) => identifier(scope, "requested scope"));
      identifier(input.audience, "audience");
      const configuredAudience = this.config.application?.audience;
      if (configuredAudience !== undefined && input.audience !== configuredAudience) fail("WRONG_AUDIENCE", "requested audience does not match trusted access application policy");
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
      payload = { aud: input.audience, environment: this.config.environment!, exp: now + ttl, iat: now, iss: this.authorityPrincipalId, jti: randomUUID(), key_epoch: key.key_epoch, kid: this.authorityKeyId, nbf: now, principal_epoch: principal.revocation_epoch, principal_type: policy.principal_type ?? (input.requestedPrincipal === "agent" ? "agent" : "human"), scopes: [...input.scopes].sort(), sub: policy.subject, transport: transport.transport, version: TRUSTED_IDENTITY_VERSION, ...(transport.peerIdentity ? { peer_identity: transport.peerIdentity } : {}) };
      validatePayload(payload);
      const payloadSegment = b64(canonicalJsonBytes(payload as never));
      const assertion = `${TRUSTED_IDENTITY_PREFIX}.${payloadSegment}.${b64(sign(null, Buffer.from(`${TRUSTED_IDENTITY_PREFIX}.${payloadSegment}`, "ascii"), this.privateKey))}`;
      auditTrustedAccess(this.auditSink, "AUTHORIZED", "TRUSTED_IDENTITY_ISSUED", payload, "trusted_dev.issue");
      return assertion;
    } catch (error) {
      if (error instanceof TrustedAccessError) auditTrustedAccess(this.auditSink, "REJECTED", error.code, payload, "trusted_dev.issue");
      throw error;
    }
  }
}

export class TrustedIdentityVerifier {
  private readonly config: TrustedAccessConfig;

  constructor(private readonly registry: Registry, config: TrustedAccessConfig, private readonly replayStore: ReplayStore, private readonly expectedAudience: string, private readonly verifiers: Record<string, TransportVerifier>, private readonly auditSink?: AuditSink) {
    this.config = validateTrustedAccessConfig(config);
    if (!this.config.enabled) fail("TRUSTED_ACCESS_DISABLED", "trusted DEV access is not enabled");
    if (!isDevEnvironment(this.config.environment)) fail("TRUSTED_ACCESS_NOT_DEV", "trusted access can only be enabled for DEV");
    identifier(expectedAudience, "expected audience");
    if (this.config.application?.audience !== undefined && expectedAudience !== this.config.application.audience) fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "expected audience does not match trusted access application policy");
  }
  verify(assertion: string, input: { observation: TransportObservation; now: number }): TrustedIdentityPayload {
    let payload: TrustedIdentityPayload | undefined;
    try {
      const parsed = parseTrustedIdentityAssertion(assertion);
      payload = parsed.payload;
      if (payload.aud !== this.expectedAudience) fail("WRONG_AUDIENCE", "trusted assertion audience does not match verifier");
      if (payload.environment !== this.config.environment || !isDevEnvironment(payload.environment)) fail("WRONG_ENVIRONMENT", "trusted assertion environment does not match verifier");
      if (input.now < payload.nbf) fail("NOT_YET_VALID", "trusted assertion is not yet valid");
      if (input.now >= payload.exp) fail("EXPIRED", "trusted assertion has expired");
      if (payload.transport !== input.observation.transport || !this.config.transports.includes(payload.transport)) fail("UNTRUSTED_TRANSPORT", "asserted transport is not allowed");
      let transport: TransportEvidence;
      if (input.observation.handoff !== undefined) {
        if (input.observation.handoff !== "trusted-ingress" || this.config.handoff?.enabled !== true) fail("UNTRUSTED_TRANSPORT", "trusted ingress handoff is not enabled");
        transport = { transport: input.observation.transport, peerAddress: input.observation.peerAddress ?? "trusted-ingress", peerIdentity: payload.peer_identity };
      } else {
        const verifier = this.verifiers[payload.transport];
        if (!verifier) fail("TRANSPORT_VERIFIER_MISSING", "no server-side verifier is configured");
        try {
          transport = verifier.verify(input.observation);
        } catch (error) {
          if (error instanceof TrustedAccessError) throw error;
          fail("UNTRUSTED_TRANSPORT", "trusted transport verification failed");
        }
      }
      if (payload.peer_identity !== undefined && payload.peer_identity !== transport.peerIdentity) fail("UNTRUSTED_TRANSPORT", "current transport proof does not match assertion");
      const key = this.registry.keys.find((item) => item.key_id === payload!.kid);
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
      const policy = Object.values(this.config.principals).find((item) => item.subject === payload!.sub && (item.principal_type ?? (item.name === "agent" ? "agent" : "human")) === payload!.principal_type);
      if (!policy || payload.scopes.some((scope) => !policy.scopes.includes(scope))) fail("SCOPE_DENIED", "trusted assertion principal or scope is not allowed");
      if (!this.replayStore.consume(payload.jti, payload.exp, input.now)) fail("REPLAYED_JTI", "trusted identity assertion has already been consumed");
      auditTrustedAccess(this.auditSink, "AUTHORIZED", "TRUSTED_IDENTITY_VERIFIED", payload, "trusted_dev.verify");
      return payload;
    } catch (error) {
      if (error instanceof TrustedAccessError) {
        auditTrustedAccess(this.auditSink, "REJECTED", error.code, payload, "trusted_dev.verify");
        throw error;
      }
      const wrapped = new TrustedAccessError("TRUSTED_ACCESS_VERIFICATION_FAILED", "trusted identity assertion verification failed");
      auditTrustedAccess(this.auditSink, "REJECTED", wrapped.code, payload, "trusted_dev.verify");
      throw wrapped;
    }
  }

  verifyHandoff(assertion: string, now: number): TrustedIdentityPayload {
    const payload = parseTrustedIdentityAssertion(assertion).payload;
    return this.verify(assertion, { observation: { transport: payload.transport, handoff: "trusted-ingress" }, now });
  }

  verifyHandoffPrincipal(assertion: string, now: number): import("./application.js").AgentctlPrincipal {
    const payload = this.verifyHandoff(assertion, now);
    return {
      issuer: payload.iss,
      subject: payload.sub,
      principalType: payload.principal_type,
      scopes: [...payload.scopes],
      audience: payload.aud,
      environment: payload.environment,
      authMethod: "trusted_dev",
      transport: payload.transport,
      assertionId: payload.jti,
      hasScope: (scope) => payload.scopes.includes(scope),
      requireScope: (scope) => {
        if (!payload.scopes.includes(scope)) fail("SCOPE_DENIED", "application scope is not granted to the trusted principal");
      },
    };
  }

  verifyPrincipal(assertion: string, input: { observation: TransportObservation; now: number }): import("./application.js").AgentctlPrincipal {
    const payload = this.verify(assertion, input);
    return {
      issuer: payload.iss,
      subject: payload.sub,
      principalType: payload.principal_type,
      scopes: [...payload.scopes],
      audience: payload.aud,
      environment: payload.environment,
      authMethod: "trusted_dev",
      transport: payload.transport,
      assertionId: payload.jti,
      hasScope: (scope) => payload.scopes.includes(scope),
      requireScope: (scope) => {
        if (!payload.scopes.includes(scope)) fail("SCOPE_DENIED", "application scope is not granted to the trusted principal");
      },
    };
  }
}
