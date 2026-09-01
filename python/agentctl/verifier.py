"""Reference fail-closed verifier for Agent Action Assertion v1."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .audit import AuditEvent, AuditSink
from .models import AuthorizationEvidence, PrincipalRecord, RequestContext
from .protocol import (
    MAX_TTL_SECONDS,
    AssertionErrorCode,
    canonical_request_target,
    normalize_content_type,
    parse_assertion,
    sha256_hex,
    verify_signature,
)
from .registry import Registry, decode_public_key
from .replay import ReplayStore


class VerificationError(ValueError):
    """Structured verifier denial."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class VerificationResult:
    principal: PrincipalRecord
    scopes: tuple[str, ...]
    evidence: AuthorizationEvidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal.to_dict(),
            "scopes": list(self.scopes),
            "evidence": self.evidence.to_dict(),
        }


def _parse_registry_time(value: str | None, field: str) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerificationError("INVALID_REGISTRY", f"{field} is not valid RFC3339") from exc


class Verifier:
    def __init__(
        self,
        registry: Registry,
        replay_store: ReplayStore,
        *,
        expected_audience: str,
        expected_environment: str,
        audit_sink: AuditSink | None = None,
        max_ttl_seconds: int = MAX_TTL_SECONDS,
        clock_skew_seconds: int = 0,
    ) -> None:
        if not expected_audience or not expected_environment:
            raise ValueError("expected audience and environment are required")
        if max_ttl_seconds <= 0 or max_ttl_seconds > MAX_TTL_SECONDS:
            raise ValueError("max_ttl_seconds must be between 1 and 300")
        if clock_skew_seconds < 0:
            raise ValueError("clock_skew_seconds cannot be negative")
        self.registry = registry
        self.replay_store = replay_store
        self.expected_audience = expected_audience
        self.expected_environment = expected_environment
        self.audit_sink = audit_sink
        self.max_ttl_seconds = max_ttl_seconds
        self.clock_skew_seconds = clock_skew_seconds

    def _audit(self, event: AuditEvent) -> None:
        if self.audit_sink is not None:
            self.audit_sink.append(event)

    def _reject(
        self,
        code: str,
        message: str,
        *,
        payload: dict[str, Any] | None = None,
        request: RequestContext | None = None,
        action: str = "verify_agent_request",
    ) -> None:
        safe = payload or {}
        method = ""
        canonical_path = ""
        body_digest = ""
        if request is not None:
            method = request.method.upper() if isinstance(request.method, str) else ""
            try:
                canonical_path = canonical_request_target(request.target)
            except Exception:
                canonical_path = ""
            body_digest = sha256_hex(request.body) if isinstance(request.body, bytes) else ""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            principal_type="machine",
            principal_id=str(safe.get("iss", "")) if isinstance(safe.get("iss", ""), str) else "",
            key_id=str(safe.get("kid", "")) if isinstance(safe.get("kid", ""), str) else "",
            environment=str(safe.get("environment", "")) if isinstance(safe.get("environment", ""), str) else "",
            audience=str(safe.get("aud", "")) if isinstance(safe.get("aud", ""), str) else "",
            scope=str(safe.get("scope", "")) if isinstance(safe.get("scope", ""), str) else "",
            action=action,
            http_method=method or str(safe.get("http_method", "")),
            canonical_path=canonical_path or str(safe.get("canonical_path", "")),
            body_sha256=body_digest or str(safe.get("body_sha256", "")),
            resource=safe.get("resource") if isinstance(safe.get("resource"), str) else None,
            request_id=request.request_id or str(safe.get("request_id", "")) if request else str(safe.get("request_id", "")),
            jti=str(safe.get("jti", "")) if isinstance(safe.get("jti", ""), str) else "",
            result="REJECTED",
            result_code=code,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        )
        self._audit(event)
        raise VerificationError(code, message)

    def verify(self, assertion: str, request: RequestContext, *, now: int, action: str = "verify_agent_request") -> VerificationResult:
        payload: dict[str, Any] | None = None
        try:
            parsed = parse_assertion(assertion)
            payload = parsed.payload
        except AssertionErrorCode as exc:
            self._reject(exc.code, exc.message, request=request, action=action)
        assert payload is not None
        try:
            if isinstance(now, bool) or not isinstance(now, int) or now < 0:
                self._reject("INVALID_CLOCK", "verifier now must be a non-negative integer", payload=payload, request=request, action=action)
            if payload["exp"] - payload["iat"] > self.max_ttl_seconds:
                self._reject("TTL_EXCEEDED", "assertion exceeds verifier TTL", payload=payload, request=request, action=action)
            if now + self.clock_skew_seconds < payload["nbf"]:
                self._reject("NOT_YET_VALID", "assertion is not yet valid", payload=payload, request=request, action=action)
            if now - self.clock_skew_seconds >= payload["exp"]:
                self._reject("EXPIRED", "assertion has expired", payload=payload, request=request, action=action)

            key_record = self.registry.keys.get(payload["kid"])
            if key_record is None:
                self._reject("UNKNOWN_KEY", "key is not registered", payload=payload, request=request, action=action)
            if key_record.algorithm != "Ed25519":
                self._reject("UNSUPPORTED_KEY_ALGORITHM", "key algorithm is not Ed25519", payload=payload, request=request, action=action)
            if not key_record.enabled:
                self._reject("KEY_DISABLED", "key is disabled", payload=payload, request=request, action=action)
            if key_record.revoked_at is not None:
                self._reject("KEY_REVOKED", "key is revoked", payload=payload, request=request, action=action)
            expires_at = _parse_registry_time(key_record.expires_at, "key expires_at")
            if expires_at is not None and datetime.now(expires_at.tzinfo) >= expires_at:
                self._reject("KEY_EXPIRED", "key is expired", payload=payload, request=request, action=action)

            principal = self.registry.principals.get(key_record.principal_id)
            if principal is None:
                self._reject("UNKNOWN_PRINCIPAL", "key owner principal is not registered", payload=payload, request=request, action=action)
            if not principal.enabled:
                self._reject("PRINCIPAL_DISABLED", "principal is disabled", payload=payload, request=request, action=action)
            if principal.revoked_at is not None:
                self._reject("PRINCIPAL_REVOKED", "principal is revoked", payload=payload, request=request, action=action)
            if payload["principal_epoch"] != principal.revocation_epoch:
                self._reject("PRINCIPAL_EPOCH_MISMATCH", "principal revocation epoch is stale", payload=payload, request=request, action=action)
            if payload["key_epoch"] != key_record.key_epoch:
                self._reject("KEY_EPOCH_MISMATCH", "key epoch is stale", payload=payload, request=request, action=action)

            public_key = Ed25519PublicKey.from_public_bytes(decode_public_key(key_record.public_key))
            verify_signature(parsed, public_key)

            if payload["iss"] != principal.principal_id or payload["sub"] != principal.principal_id:
                self._reject("WRONG_ISSUER", "assertion issuer is not the registered key owner", payload=payload, request=request, action=action)
            if payload["aud"] != self.expected_audience:
                self._reject("WRONG_AUDIENCE", "assertion audience does not match verifier", payload=payload, request=request, action=action)
            if payload["environment"] != self.expected_environment or payload["environment"] != principal.environment:
                self._reject("WRONG_ENVIRONMENT", "assertion environment does not match verifier", payload=payload, request=request, action=action)
            if payload["http_method"] != request.method.upper():
                self._reject("METHOD_MISMATCH", "HTTP method is not bound by the assertion", payload=payload, request=request, action=action)
            if payload["canonical_path"] != canonical_request_target(request.target):
                self._reject("PATH_MISMATCH", "request target is not bound by the assertion", payload=payload, request=request, action=action)
            if payload["content_type"] != normalize_content_type(request.content_type):
                self._reject("CONTENT_TYPE_MISMATCH", "content type is not bound by the assertion", payload=payload, request=request, action=action)
            if payload["body_sha256"] != sha256_hex(request.body):
                self._reject("BODY_DIGEST_MISMATCH", "request body is not bound by the assertion", payload=payload, request=request, action=action)
            if request.request_id is None or payload["request_id"] != request.request_id:
                self._reject("REQUEST_ID_MISMATCH", "request ID is not bound by the assertion", payload=payload, request=request, action=action)
            if "resource" in payload and payload["resource"] != request.resource:
                self._reject("RESOURCE_MISMATCH", "resource is not bound by the assertion", payload=payload, request=request, action=action)
            if not self.registry.has_grant(
                principal_id=principal.principal_id,
                environment=payload["environment"],
                audience=payload["aud"],
                scope=payload["scope"],
                resource=payload.get("resource"),
            ):
                self._reject("SCOPE_DENIED", "no exact scope grant matches the assertion", payload=payload, request=request, action=action)
            if not self.replay_store.consume(payload["jti"], payload["exp"], now=now):
                self._reject("REPLAYED_JTI", "assertion JTI has already been consumed", payload=payload, request=request, action=action)
        except VerificationError:
            raise
        except AssertionErrorCode as exc:
            self._reject(exc.code, exc.message, payload=payload, request=request, action=action)
        except (ValueError, TypeError) as exc:
            self._reject("INVALID_REGISTRY", str(exc), payload=payload, request=request, action=action)

        evidence = AuthorizationEvidence(
            principal_id=principal.principal_id,
            key_id=key_record.key_id,
            environment=payload["environment"],
            audience=payload["aud"],
            scope=payload["scope"],
            request_id=payload["request_id"],
            jti=payload["jti"],
            canonical_path=payload["canonical_path"],
            body_sha256=payload["body_sha256"],
            resource=payload.get("resource"),
        )
        self._audit(
            AuditEvent(
                event_id=str(uuid.uuid4()),
                principal_type="machine",
                principal_id=principal.principal_id,
                key_id=key_record.key_id,
                environment=payload["environment"],
                audience=payload["aud"],
                scope=payload["scope"],
                action=action,
                http_method=payload["http_method"],
                canonical_path=payload["canonical_path"],
                body_sha256=payload["body_sha256"],
                resource=payload.get("resource"),
                request_id=payload["request_id"],
                jti=payload["jti"],
                result="AUTHORIZED",
                result_code="AUTHORIZED",
                created_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            )
        )
        return VerificationResult(principal=principal, scopes=(payload["scope"],), evidence=evidence)
