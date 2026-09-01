import { createHash, randomUUID, sign, verify } from "node:crypto";

export const PROTOCOL_VERSION = "agent-action-assertion/v1";
export const ASSERTION_PREFIX = "agentctl-aav1";
export const MAX_TTL_SECONDS = 300;

export class ProtocolError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
  }
}

type JsonValue = null | boolean | string | number | JsonValue[] | { [key: string]: JsonValue };

function fail(code: string, message: string): never {
  throw new ProtocolError(code, message);
}

function validateJsonValue(value: unknown): asserts value is JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      fail("INVALID_JSON_NUMBER", "only finite safe integers are allowed");
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(validateJsonValue);
    return;
  }
  if (typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (typeof key !== "string") fail("INVALID_JSON_KEY", "object keys must be strings");
      validateJsonValue(item);
    }
    return;
  }
  fail("INVALID_JSON_VALUE", `unsupported JSON value type: ${typeof value}`);
}

function sortJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(sortJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort(compareCodePoints)
        .map((key) => [key, sortJson(value[key])]),
    );
  }
  return value;
}

export function canonicalJson(value: JsonValue): string {
  validateJsonValue(value);
  return JSON.stringify(sortJson(value));
}

export function canonicalJsonBytes(value: JsonValue): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

export function sha256Hex(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function compareCodePoints(left: string, right: string): number {
  const a = Array.from(left, (char) => char.codePointAt(0) ?? 0);
  const b = Array.from(right, (char) => char.codePointAt(0) ?? 0);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

function validateString(value: unknown, field: string, pattern?: RegExp): string {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    fail("MALFORMED_ASSERTION", `${field} must be a non-empty trimmed string`);
  }
  if (/[\u0000-\u0020\u007f]/u.test(value)) {
    fail("MALFORMED_ASSERTION", `${field} contains control characters`);
  }
  if (pattern && !pattern.test(value)) fail("MALFORMED_ASSERTION", `${field} has an invalid format`);
  return value;
}

function validateInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail("MALFORMED_ASSERTION", `${field} must be a non-negative integer`);
  }
  return value;
}

function validatePercentEscapes(value: string, code: string): void {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== "%") continue;
    if (!/^[0-9A-Fa-f]{2}$/u.test(value.slice(index + 1, index + 3))) {
      fail(code, "invalid percent escape");
    }
    index += 2;
  }
}

function normalizePath(path: string): string {
  if (path.length === 0) path = "/";
  if (!path.startsWith("/")) fail("INVALID_PATH", "request path must start with '/'");
  if (/[\u0000-\u0020\u007f]/u.test(path)) fail("INVALID_PATH", "request path contains control characters or spaces");
  validatePercentEscapes(path, "INVALID_PATH");
  let output = "";
  for (let index = 0; index < path.length; index += 1) {
    if (path[index] !== "%") {
      output += path[index];
      continue;
    }
    const byte = Number.parseInt(path.slice(index + 1, index + 3), 16);
    const character = String.fromCharCode(byte);
    if ((byte < 128 && /[A-Za-z0-9]/u.test(character)) || "-._~".includes(character)) {
      output += character;
    } else {
      output += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    }
    index += 2;
  }
  if (output.split("/").some((segment) => segment === "." || segment === "..")) {
    fail("INVALID_PATH", "dot segments are not allowed");
  }
  return output;
}

function decodeQueryPart(value: string): string {
  try {
    return decodeURIComponent(value.replaceAll("+", " "));
  } catch (error) {
    fail("INVALID_QUERY", `query is not valid UTF-8: ${String(error)}`);
  }
}

function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/gu, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

function canonicalQuery(query: string): string {
  if (query.length === 0) return "";
  validatePercentEscapes(query, "INVALID_QUERY");
  const pairs = query.split("&").map((pair) => {
    const separator = pair.indexOf("=");
    const rawName = separator < 0 ? pair : pair.slice(0, separator);
    const rawValue = separator < 0 ? "" : pair.slice(separator + 1);
    return [decodeQueryPart(rawName), decodeQueryPart(rawValue)] as const;
  });
  pairs.sort((left, right) => compareCodePoints(left[0], right[0]) || compareCodePoints(left[1], right[1]));
  return pairs.map(([name, value]) => `${encodeRfc3986(name)}=${encodeRfc3986(value)}`).join("&");
}

function stripAbsoluteAuthority(target: string): string {
  const scheme = target.match(/^([A-Za-z][A-Za-z0-9+.-]*):\/\//u);
  if (!scheme) return target;
  if (!/^(http|https)$/iu.test(scheme[1])) fail("INVALID_PATH", "only HTTP and HTTPS URLs are supported");
  const remainder = target.slice(scheme[0].length);
  const authorityEnd = remainder.search(/[/?#]/u);
  const authority = authorityEnd < 0 ? remainder : remainder.slice(0, authorityEnd);
  if (authority.length === 0 || authority.includes("@")) fail("INVALID_PATH", "URL userinfo or empty authority is not allowed");
  return authorityEnd < 0 ? "/" : remainder.slice(authorityEnd);
}

export function canonicalRequestTarget(target: string): string {
  if (typeof target !== "string" || target.length === 0) fail("INVALID_PATH", "request target must be a non-empty string");
  if (target.includes("#")) fail("INVALID_PATH", "URL fragments are not allowed");
  const relative = stripAbsoluteAuthority(target);
  const separator = relative.indexOf("?");
  const path = separator < 0 ? relative : relative.slice(0, separator);
  const query = separator < 0 ? "" : relative.slice(separator + 1);
  const canonicalPath = normalizePath(path);
  const canonicalQueryValue = canonicalQuery(query);
  return canonicalQueryValue ? `${canonicalPath}?${canonicalQueryValue}` : canonicalPath;
}

function b64urlEncode(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function b64urlDecode(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) fail("MALFORMED_ASSERTION", "invalid base64url segment");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) fail("MALFORMED_ASSERTION", "invalid base64url segment");
  return decoded;
}

export interface AssertionPayload {
  version: string;
  iss: string;
  sub: string;
  aud: string;
  environment: string;
  scope: string;
  iat: number;
  nbf: number;
  exp: number;
  jti: string;
  kid: string;
  http_method: string;
  canonical_path: string;
  content_type: string;
  body_sha256: string;
  request_id: string;
  principal_epoch: number;
  key_epoch: number;
  resource?: string;
  project?: string;
}

const PAYLOAD_FIELDS = new Set([
  "version", "iss", "sub", "aud", "environment", "scope", "iat", "nbf", "exp", "jti", "kid",
  "http_method", "canonical_path", "content_type", "body_sha256", "request_id", "principal_epoch",
  "key_epoch", "resource", "project",
]);

export function validatePayload(input: unknown): AssertionPayload {
  if (input === null || typeof input !== "object" || Array.isArray(input)) fail("MALFORMED_ASSERTION", "payload must be a JSON object");
  const value = input as Record<string, unknown>;
  const unknown = Object.keys(value).filter((key) => !PAYLOAD_FIELDS.has(key));
  if (unknown.length > 0) fail("MALFORMED_ASSERTION", `unknown assertion fields: ${unknown.sort(compareCodePoints).join(", ")}`);
  if (value.version !== PROTOCOL_VERSION) fail("WRONG_VERSION", "unsupported assertion version");
  for (const field of ["iss", "sub", "aud", "environment", "scope", "kid", "request_id"]) validateString(value[field], field);
  validateString(value.jti, "jti", /^[A-Za-z0-9._:-]{8,256}$/u);
  validateString(value.http_method, "http_method", /^[A-Z]+$/u);
  const path = validateString(value.canonical_path, "canonical_path");
  if (path !== canonicalRequestTarget(path)) fail("MALFORMED_ASSERTION", "canonical_path is not canonical");
  const contentType = value.content_type;
  if (typeof contentType !== "string" || contentType !== normalizeContentType(contentType)) fail("MALFORMED_ASSERTION", "content_type is not normalized");
  const digest = validateString(value.body_sha256, "body_sha256", /^[0-9a-f]{64}$/u);
  const iat = validateInteger(value.iat, "iat");
  const nbf = validateInteger(value.nbf, "nbf");
  const exp = validateInteger(value.exp, "exp");
  const principalEpoch = validateInteger(value.principal_epoch, "principal_epoch");
  const keyEpoch = validateInteger(value.key_epoch, "key_epoch");
  if (value.iss !== value.sub) fail("ISSUER_SUBJECT_MISMATCH", "V1 does not support delegated subjects");
  if (iat > nbf || exp <= nbf) fail("INVALID_TIME_WINDOW", "iat <= nbf < exp is required");
  if (exp - iat > MAX_TTL_SECONDS) fail("TTL_EXCEEDED", "assertion TTL exceeds the V1 maximum");
  for (const field of ["resource", "project"]) if (field in value) validateString(value[field], field);
  return {
    version: PROTOCOL_VERSION,
    iss: value.iss as string,
    sub: value.sub as string,
    aud: value.aud as string,
    environment: value.environment as string,
    scope: value.scope as string,
    iat,
    nbf,
    exp,
    jti: value.jti as string,
    kid: value.kid as string,
    http_method: value.http_method as string,
    canonical_path: path,
    content_type: contentType,
    body_sha256: digest,
    request_id: value.request_id as string,
    principal_epoch: principalEpoch,
    key_epoch: keyEpoch,
    ...(typeof value.resource === "string" ? { resource: value.resource } : {}),
    ...(typeof value.project === "string" ? { project: value.project } : {}),
  };
}

export function normalizeContentType(value: string | undefined): string {
  if (value === undefined) return "";
  if (typeof value !== "string") fail("INVALID_CONTENT_TYPE", "content type must be a string");
  const normalized = value.trim().toLowerCase();
  if (/[\u0000-\u001f\u007f]/u.test(normalized)) fail("INVALID_CONTENT_TYPE", "content type contains control characters");
  return normalized;
}

export interface ParsedAssertion {
  payload: AssertionPayload;
  payloadSegment: string;
  signature: Buffer;
  compact: string;
}

export function buildAssertion(options: {
  principalId: string;
  audience: string;
  environment: string;
  scope: string;
  httpMethod: string;
  target: string;
  body: Uint8Array;
  keyId: string;
  principalEpoch: number;
  keyEpoch: number;
  privateKey: import("node:crypto").KeyObject;
  contentType?: string;
  resource?: string;
  project?: string;
  requestId?: string;
  jti?: string;
  now?: number;
  ttlSeconds?: number;
}): string {
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const ttl = options.ttlSeconds ?? MAX_TTL_SECONDS;
  if (!Number.isSafeInteger(now) || now < 0) fail("INVALID_TIME_WINDOW", "now must be a non-negative integer");
  if (!Number.isSafeInteger(ttl) || ttl <= 0 || ttl > MAX_TTL_SECONDS) fail("TTL_EXCEEDED", "ttl_seconds must be between 1 and 300");
  if (typeof options.httpMethod !== "string") fail("INVALID_METHOD", "HTTP method must be a string");
  const payload = validatePayload({
    aud: validateString(options.audience, "audience"),
    body_sha256: sha256Hex(options.body),
    canonical_path: canonicalRequestTarget(options.target),
    content_type: normalizeContentType(options.contentType),
    environment: validateString(options.environment, "environment"),
    exp: now + ttl,
    iat: now,
    iss: validateString(options.principalId, "principal_id"),
    jti: options.jti ?? randomUUID(),
    kid: validateString(options.keyId, "key_id"),
    nbf: now,
    http_method: options.httpMethod.toUpperCase(),
    principal_epoch: options.principalEpoch,
    request_id: options.requestId ?? randomUUID(),
    scope: validateString(options.scope, "scope"),
    sub: validateString(options.principalId, "principal_id"),
    version: PROTOCOL_VERSION,
    key_epoch: options.keyEpoch,
    ...(options.resource === undefined ? {} : { resource: options.resource }),
    ...(options.project === undefined ? {} : { project: options.project }),
  });
  const payloadSegment = b64urlEncode(canonicalJsonBytes(payload as unknown as JsonValue));
  const signingInput = Buffer.from(`${ASSERTION_PREFIX}.${payloadSegment}`, "ascii");
  return `${ASSERTION_PREFIX}.${payloadSegment}.${b64urlEncode(sign(null, signingInput, options.privateKey))}`;
}

export function parseAssertion(compact: string): ParsedAssertion {
  if (typeof compact !== "string") fail("MALFORMED_ASSERTION", "assertion must be a string");
  const parts = compact.split(".");
  if (parts.length !== 3 || parts[0] !== ASSERTION_PREFIX) fail("MALFORMED_ASSERTION", "invalid assertion envelope");
  const payloadBytes = b64urlDecode(parts[1]);
  const signature = b64urlDecode(parts[2]);
  if (signature.length !== 64) fail("MALFORMED_ASSERTION", "Ed25519 signatures must be 64 bytes");
  let parsed: unknown;
  try {
    parsed = JSON.parse(payloadBytes.toString("utf8"));
  } catch (error) {
    fail("MALFORMED_ASSERTION", `invalid payload JSON: ${String(error)}`);
  }
  const payload = validatePayload(parsed);
  if (!canonicalJsonBytes(payload as unknown as JsonValue).equals(payloadBytes)) fail("MALFORMED_ASSERTION", "payload is not canonical JSON");
  return { payload, payloadSegment: parts[1], signature, compact };
}

export function verifySignature(parsed: ParsedAssertion, publicKey: import("node:crypto").KeyObject): void {
  const input = Buffer.from(`${ASSERTION_PREFIX}.${parsed.payloadSegment}`, "ascii");
  if (!verify(null, input, publicKey, parsed.signature)) fail("BAD_SIGNATURE", "assertion signature verification failed");
}
