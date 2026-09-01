"""Language-neutral Agent Action Assertion v1 primitives.

The protocol signs the compact payload bytes, not a reinterpreted semantic
request. The transmitted body is hashed separately by the caller.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import quote, unquote_plus, urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL_VERSION = "agent-action-assertion/v1"
ASSERTION_PREFIX = "agentctl-aav1"
MAX_TTL_SECONDS = 300
_HEX_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_JTI = re.compile(r"^[A-Za-z0-9._:-]{8,256}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_METHOD = re.compile(r"^[A-Z]+$")
_CONTROL = re.compile(r"[\x00-\x20\x7f]")
_CONTROL_ONLY = re.compile(r"[\x00-\x1f\x7f]")


class AssertionErrorCode(ValueError):
    """Structured protocol failure with a stable machine-readable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> None:
    raise AssertionErrorCode(code, message)


def _validate_json_value(value: Any) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        _fail("INVALID_JSON_NUMBER", "floating-point values are not allowed")
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("INVALID_JSON_KEY", "object keys must be strings")
            _validate_json_value(item)
        return
    _fail("INVALID_JSON_VALUE", f"unsupported JSON value type: {type(value).__name__}")


def canonical_json_bytes(value: Mapping[str, Any] | list[Any]) -> bytes:
    """Serialize values using the protocol's deterministic JSON rules."""

    _validate_json_value(value)
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        _fail("INVALID_CANONICAL_JSON", str(exc))
    return text.encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def normalize_content_type(value: str | None) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        _fail("INVALID_CONTENT_TYPE", "content type must be a string")
    normalized = value.strip().lower()
    if _CONTROL_ONLY.search(normalized):
        _fail("INVALID_CONTENT_TYPE", "content type contains control characters")
    return normalized


def _validate_percent_escapes(value: str, code: str) -> None:
    position = 0
    while position < len(value):
        if value[position] == "%":
            if position + 2 >= len(value) or not re.fullmatch(
                r"[0-9A-Fa-f]{2}", value[position + 1 : position + 3]
            ):
                _fail(code, "invalid percent escape")
            position += 3
            continue
        position += 1


def _normalize_path(path: str) -> str:
    if path == "":
        path = "/"
    if not path.startswith("/"):
        _fail("INVALID_PATH", "request path must start with '/'")
    if _CONTROL.search(path):
        _fail("INVALID_PATH", "request path contains control characters or spaces")
    _validate_percent_escapes(path, "INVALID_PATH")

    output: list[str] = []
    position = 0
    while position < len(path):
        match = _HEX_ESCAPE.match(path, position)
        if match:
            byte = int(match.group(1), 16)
            char = chr(byte)
            if (char.isalnum() and byte < 128) or char in "-._~":
                output.append(char)
            else:
                output.append(f"%{byte:02X}")
            position = match.end()
            continue
        output.append(path[position])
        position += 1
    normalized = "".join(output)
    if any(segment in {".", ".."} for segment in normalized.split("/")):
        _fail("INVALID_PATH", "dot segments are not allowed")
    return normalized


def _canonical_query(query: str) -> str:
    if query == "":
        return ""
    _validate_percent_escapes(query, "INVALID_QUERY")
    pairs: list[tuple[str, str]] = []
    for raw_pair in query.split("&"):
        name, separator, value = raw_pair.partition("=")
        if not separator:
            value = ""
        try:
            decoded_name = unquote_plus(name, encoding="utf-8", errors="strict")
            decoded_value = unquote_plus(value, encoding="utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            _fail("INVALID_QUERY", f"query is not valid UTF-8: {exc}")
        pairs.append((decoded_name, decoded_value))
    pairs.sort(key=lambda pair: (pair[0], pair[1]))
    encoded = [
        f"{quote(name, safe='-._~')}={quote(value, safe='-._~')}"
        for name, value in pairs
    ]
    return "&".join(encoded)


def canonical_request_target(target: str) -> str:
    """Return the canonical path plus sorted, percent-encoded query string."""

    if not isinstance(target, str) or not target:
        _fail("INVALID_PATH", "request target must be a non-empty string")
    try:
        parsed = urlsplit(target)
        if parsed.netloc:
            _ = parsed.port
    except ValueError as exc:
        _fail("INVALID_PATH", f"invalid request target: {exc}")
    if "#" in target or parsed.fragment:
        _fail("INVALID_PATH", "URL fragments are not allowed")
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        _fail("INVALID_PATH", "only HTTP and HTTPS URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        _fail("INVALID_PATH", "URL userinfo is not allowed")
    path = _normalize_path(parsed.path)
    query = _canonical_query(parsed.query)
    return f"{path}?{query}" if query else path


def _require_string(payload: Mapping[str, Any], field: str, *, pattern: re.Pattern[str] | None = None) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        _fail("MALFORMED_ASSERTION", f"{field} must be a non-empty string")
    if value != value.strip():
        _fail("MALFORMED_ASSERTION", f"{field} must be trimmed")
    if _CONTROL.search(value):
        _fail("MALFORMED_ASSERTION", f"{field} contains control characters")
    if pattern and not pattern.fullmatch(value):
        _fail("MALFORMED_ASSERTION", f"{field} has an invalid format")
    return value


def _require_int(payload: Mapping[str, Any], field: str) -> int:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail("MALFORMED_ASSERTION", f"{field} must be a non-negative integer")
    return value


def validate_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "version", "iss", "sub", "aud", "environment", "scope", "iat", "nbf", "exp",
        "jti", "kid", "http_method", "canonical_path", "content_type", "body_sha256",
        "request_id", "principal_epoch", "key_epoch", "resource", "project",
    }
    unknown = set(payload) - allowed
    if unknown:
        _fail("MALFORMED_ASSERTION", f"unknown assertion fields: {sorted(unknown)}")
    if payload.get("version") != PROTOCOL_VERSION:
        _fail("WRONG_VERSION", "unsupported assertion version")
    for field in ("iss", "sub", "aud", "environment", "scope", "kid", "request_id"):
        _require_string(payload, field)
    _require_string(payload, "jti", pattern=_JTI)
    _require_string(payload, "http_method", pattern=_METHOD)
    canonical_path = _require_string(payload, "canonical_path")
    if canonical_path != canonical_request_target(canonical_path):
        _fail("MALFORMED_ASSERTION", "canonical_path is not canonical")
    content_type = payload.get("content_type")
    if not isinstance(content_type, str) or content_type != normalize_content_type(content_type):
        _fail("MALFORMED_ASSERTION", "content_type is not normalized")
    body_sha256 = _require_string(payload, "body_sha256")
    if not _SHA256.fullmatch(body_sha256):
        _fail("MALFORMED_ASSERTION", "body_sha256 must be lowercase SHA-256 hex")
    for field in ("iat", "nbf", "exp", "principal_epoch", "key_epoch"):
        _require_int(payload, field)
    if payload["iss"] != payload["sub"]:
        _fail("ISSUER_SUBJECT_MISMATCH", "V1 does not support delegated subjects")
    if payload["iat"] > payload["nbf"] or payload["exp"] <= payload["nbf"]:
        _fail("INVALID_TIME_WINDOW", "iat <= nbf < exp is required")
    if payload["exp"] - payload["iat"] > MAX_TTL_SECONDS:
        _fail("TTL_EXCEEDED", "assertion TTL exceeds the V1 maximum")
    for field in ("resource", "project"):
        if field in payload:
            _require_string(payload, field)
    return dict(payload)


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64_decode(value: str) -> bytes:
    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        _fail("MALFORMED_ASSERTION", "invalid base64url segment")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        _fail("MALFORMED_ASSERTION", f"invalid base64url segment: {exc}")


@dataclass(frozen=True)
class ParsedAssertion:
    payload: dict[str, Any]
    payload_segment: str
    signature: bytes
    compact: str


def build_assertion(
    *,
    principal_id: str,
    audience: str,
    environment: str,
    scope: str,
    http_method: str,
    target: str,
    body: bytes,
    key_id: str,
    principal_epoch: int,
    key_epoch: int,
    private_key: Ed25519PrivateKey,
    content_type: str | None = None,
    resource: str | None = None,
    project: str | None = None,
    request_id: str | None = None,
    jti: str | None = None,
    now: int | None = None,
    ttl_seconds: int = 300,
) -> str:
    created = int(time.time()) if now is None else now
    if isinstance(created, bool) or not isinstance(created, int) or created < 0:
        _fail("INVALID_TIME_WINDOW", "now must be a non-negative integer")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        _fail("TTL_EXCEEDED", "ttl_seconds must be an integer")
    if ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
        _fail("TTL_EXCEEDED", "ttl_seconds must be between 1 and 300")
    if not isinstance(http_method, str):
        _fail("INVALID_METHOD", "HTTP method must be a string")
    payload: dict[str, Any] = {
        "aud": _require_string({"value": audience}, "value"),
        "body_sha256": sha256_hex(body),
        "canonical_path": canonical_request_target(target),
        "content_type": normalize_content_type(content_type),
        "environment": _require_string({"value": environment}, "value"),
        "exp": created + ttl_seconds,
        "iat": created,
        "iss": _require_string({"value": principal_id}, "value"),
        "jti": str(uuid.uuid4()) if jti is None else jti,
        "kid": _require_string({"value": key_id}, "value"),
        "nbf": created,
        "http_method": http_method.upper(),
        "principal_epoch": principal_epoch,
        "request_id": str(uuid.uuid4()) if request_id is None else request_id,
        "scope": _require_string({"value": scope}, "value"),
        "sub": _require_string({"value": principal_id}, "value"),
        "version": PROTOCOL_VERSION,
        "key_epoch": key_epoch,
    }
    if resource is not None:
        payload["resource"] = resource
    if project is not None:
        payload["project"] = project
    payload = validate_payload(payload)
    payload_segment = _b64_encode(canonical_json_bytes(payload))
    signing_input = f"{ASSERTION_PREFIX}.{payload_segment}".encode("ascii")
    signature = private_key.sign(signing_input)
    return f"{ASSERTION_PREFIX}.{payload_segment}.{_b64_encode(signature)}"


def parse_assertion(compact: str) -> ParsedAssertion:
    if not isinstance(compact, str):
        _fail("MALFORMED_ASSERTION", "assertion must be a string")
    parts = compact.split(".")
    if len(parts) != 3 or parts[0] != ASSERTION_PREFIX:
        _fail("MALFORMED_ASSERTION", "invalid assertion envelope")
    payload_bytes = _b64_decode(parts[1])
    signature = _b64_decode(parts[2])
    if len(signature) != 64:
        _fail("MALFORMED_ASSERTION", "Ed25519 signatures must be 64 bytes")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail("MALFORMED_ASSERTION", f"invalid payload JSON: {exc}")
    if not isinstance(payload, dict):
        _fail("MALFORMED_ASSERTION", "payload must be a JSON object")
    validate_payload(payload)
    if canonical_json_bytes(payload) != payload_bytes:
        _fail("MALFORMED_ASSERTION", "payload is not canonical JSON")
    return ParsedAssertion(
        payload=dict(payload),
        payload_segment=parts[1],
        signature=signature,
        compact=compact,
    )


def serialize_assertion(parsed: ParsedAssertion) -> str:
    return parsed.compact


def verify_signature(parsed: ParsedAssertion, public_key: Ed25519PublicKey) -> None:
    signing_input = f"{ASSERTION_PREFIX}.{parsed.payload_segment}".encode("ascii")
    try:
        public_key.verify(parsed.signature, signing_input)
    except Exception as exc:  # cryptography uses InvalidSignature without a common base.
        _fail("BAD_SIGNATURE", f"assertion signature verification failed: {exc}")
