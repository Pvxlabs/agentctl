"""Trusted Development Access identity establishment.

This module is deliberately separate from the request-bound AAV1 verifier.  A
trusted DEV request establishes an application-neutral principal first; the
target application then maps that subject to its own normal user/session and
continues enforcing its existing authorization rules.
"""

from __future__ import annotations

import ipaddress
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .audit import AuditEvent, AuditSink
from .identity import LocalIdentity
from .protocol import canonical_json_bytes, sha256_hex
from .registry import Registry, decode_public_key, encode_public_key
from .replay import ReplayStore


TRUSTED_IDENTITY_VERSION = "trusted-dev-identity/v1"
TRUSTED_IDENTITY_PREFIX = "agentctl-tdi1"
MAX_TRUSTED_IDENTITY_TTL_SECONDS = 300
DEV_ENVIRONMENTS = frozenset({"dev", "development"})
KNOWN_TRANSPORTS = frozenset({"localhost", "tailscale"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


class TrustedAccessError(ValueError):
    """Stable, fail-closed error for trusted DEV access decisions."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> None:
    raise TrustedAccessError(code, message)


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or not _IDENTIFIER.fullmatch(value):
        _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"{field} must be a trimmed identifier")
    return value


def is_dev_environment(environment: str) -> bool:
    return isinstance(environment, str) and environment in DEV_ENVIRONMENTS


@dataclass(frozen=True)
class TrustedPrincipalPolicy:
    name: str
    subject: str
    scopes: tuple[str, ...]
    principal_type: str = "human"

    def __post_init__(self) -> None:
        _identifier(self.name, "principal name")
        _identifier(self.subject, "principal subject")
        if self.principal_type not in {"human", "agent", "observer"}:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "principal type is unsupported")
        if not self.scopes or len(set(self.scopes)) != len(self.scopes):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "principal scopes must be non-empty and unique")
        for scope in self.scopes:
            _identifier(scope, "principal scope")


@dataclass(frozen=True)
class TrustedAccessConfig:
    enabled: bool = False
    environment: str | None = None
    transports: tuple[str, ...] = ()
    principals: Mapping[str, TrustedPrincipalPolicy] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted access enabled must be boolean")
        if self.environment is not None:
            _identifier(self.environment, "trusted_access.environment")
        if not isinstance(self.transports, tuple):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted transports must be a tuple")
        if not isinstance(self.principals, (Mapping, type(None))):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted principals must be a mapping")
        values = self.principals or {}
        if not self.enabled:
            return
        if not self.environment or not is_dev_environment(self.environment):
            _fail("TRUSTED_ACCESS_NOT_DEV", "trusted access can only be enabled for DEV")
        if not self.transports or any(item not in KNOWN_TRANSPORTS for item in self.transports):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted transports must be localhost or tailscale")
        if len(set(self.transports)) != len(self.transports):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted transports must be unique")
        if not values:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "at least one trusted principal is required")
        for name, policy in values.items():
            if not isinstance(name, str) or not isinstance(policy, TrustedPrincipalPolicy):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted principal policy is malformed")
            if name != policy.name:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "principal policy name does not match its key")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "TrustedAccessConfig":
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access must be an object")
        enabled = value.get("enabled", False)
        if not isinstance(enabled, bool):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.enabled must be boolean")
        environment = value.get("environment")
        if environment is not None:
            _identifier(environment, "trusted_access.environment")
        raw_transports = value.get("transports", [])
        if not isinstance(raw_transports, list) or not all(isinstance(item, str) for item in raw_transports):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.transports must be a list")
        raw_principals = value.get("principals", {})
        if not isinstance(raw_principals, Mapping):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.principals must be an object")
        principals: dict[str, TrustedPrincipalPolicy] = {}
        for name, raw in raw_principals.items():
            if not isinstance(name, str) or not isinstance(raw, Mapping):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted principal policy is malformed")
            unknown_policy = set(raw) - {"subject", "scopes", "type", "principal_type"}
            if unknown_policy:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"unknown trusted principal fields: {sorted(unknown_policy)}")
            if "type" in raw and "principal_type" in raw and raw["type"] != raw["principal_type"]:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"principal {name} has ambiguous principal type")
            subject = raw.get("subject")
            scopes = raw.get("scopes")
            if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"principal {name} scopes must be a list")
            principal_type = raw.get("principal_type", raw.get("type", "agent" if name == "agent" else "human"))
            principals[name] = TrustedPrincipalPolicy(name, subject, tuple(scopes), principal_type)
        unknown = set(value) - {"enabled", "environment", "transports", "principals"}
        if unknown:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"unknown trusted_access fields: {sorted(unknown)}")
        return cls(enabled, environment, tuple(raw_transports), principals)

    def policy_for(self, name: str) -> TrustedPrincipalPolicy:
        if not self.enabled:
            _fail("TRUSTED_ACCESS_DISABLED", "trusted DEV access is not enabled")
        try:
            return (self.principals or {})[name]
        except KeyError as exc:
            _fail("UNKNOWN_TRUSTED_PRINCIPAL", "requested trusted principal is not allowed")
            raise AssertionError from exc


@dataclass(frozen=True)
class TransportObservation:
    """Server-owned connection metadata, never values copied from headers."""

    transport: str
    peer_address: str | None
    forwarded_headers_present: bool = False


@dataclass(frozen=True)
class TransportEvidence:
    transport: str
    peer_address: str
    peer_identity: str | None = None


class TransportVerifier(Protocol):
    transport: str

    def verify(self, observation: TransportObservation) -> TransportEvidence:
        ...


class LocalhostTransportVerifier:
    transport = "localhost"

    def verify(self, observation: TransportObservation) -> TransportEvidence:
        if observation.transport != self.transport or observation.forwarded_headers_present:
            _fail("UNTRUSTED_TRANSPORT", "localhost proof cannot use forwarding headers")
        if not observation.peer_address:
            _fail("UNTRUSTED_TRANSPORT", "server did not provide a peer address")
        try:
            address = ipaddress.ip_address(observation.peer_address)
        except ValueError as exc:
            _fail("UNTRUSTED_TRANSPORT", "peer address is invalid")
            raise AssertionError from exc
        if not address.is_loopback:
            _fail("UNTRUSTED_TRANSPORT", "peer is not loopback")
        return TransportEvidence(self.transport, observation.peer_address)


class TailscalePeerResolver(Protocol):
    """Resolver backed by a server-side Tailscale LocalAPI or equivalent."""

    def __call__(self, peer_address: str) -> str | None:
        ...


class TailscaleTransportVerifier:
    transport = "tailscale"

    def __init__(self, peer_resolver: TailscalePeerResolver, *, networks: tuple[str, ...] = ("100.64.0.0/10", "fd7a:115c:a1e0::/48")) -> None:
        self.peer_resolver = peer_resolver
        self.networks = tuple(ipaddress.ip_network(network) for network in networks)

    def verify(self, observation: TransportObservation) -> TransportEvidence:
        if observation.transport != self.transport or observation.forwarded_headers_present:
            _fail("UNTRUSTED_TRANSPORT", "Tailscale proof cannot use forwarding headers")
        if not observation.peer_address:
            _fail("UNTRUSTED_TRANSPORT", "server did not provide a peer address")
        try:
            address = ipaddress.ip_address(observation.peer_address)
        except ValueError as exc:
            _fail("UNTRUSTED_TRANSPORT", "peer address is invalid")
            raise AssertionError from exc
        if not any(address in network for network in self.networks):
            _fail("UNTRUSTED_TRANSPORT", "peer is outside configured Tailscale networks")
        try:
            peer_identity = self.peer_resolver(observation.peer_address)
        except Exception as exc:
            _fail("UNTRUSTED_TRANSPORT", "Tailscale peer identity could not be verified")
            raise AssertionError from exc
        if not isinstance(peer_identity, str) or not peer_identity.strip():
            _fail("UNTRUSTED_TRANSPORT", "Tailscale peer identity was not verified by the server-side resolver")
        return TransportEvidence(self.transport, observation.peer_address, peer_identity.strip())


@dataclass(frozen=True)
class TrustedIdentityEvidence:
    issuer: str
    subject: str
    principal_type: str
    scopes: tuple[str, ...]
    audience: str
    environment: str
    transport: str
    jti: str
    iat: int
    exp: int


def _b64(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    import base64

    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        _fail("MALFORMED_TRUSTED_ASSERTION", "invalid base64url segment")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        _fail("MALFORMED_TRUSTED_ASSERTION", "invalid base64url segment")
        raise AssertionError from exc


def _validate_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {"version", "iss", "sub", "principal_type", "scopes", "aud", "environment", "transport", "iat", "nbf", "exp", "jti", "kid", "principal_epoch", "key_epoch", "peer_identity"}
    unknown = set(payload) - allowed
    if unknown:
        _fail("MALFORMED_TRUSTED_ASSERTION", f"unknown trusted assertion fields: {sorted(unknown)}")
    if payload.get("version") != TRUSTED_IDENTITY_VERSION:
        _fail("WRONG_TRUSTED_ASSERTION_VERSION", "unsupported trusted identity assertion version")
    for field in ("iss", "sub", "principal_type", "aud", "environment", "transport", "jti", "kid"):
        _identifier(payload.get(field), field)
    scopes = payload.get("scopes")
    if not isinstance(scopes, list) or not scopes or any(not isinstance(scope, str) for scope in scopes) or tuple(scopes) != tuple(sorted(set(scopes))):
        _fail("MALFORMED_TRUSTED_ASSERTION", "scopes must be a sorted unique non-empty list")
    for scope in scopes:
        _identifier(scope, "scope")
    for field in ("iat", "nbf", "exp", "principal_epoch", "key_epoch"):
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            _fail("MALFORMED_TRUSTED_ASSERTION", f"{field} must be a non-negative integer")
    if payload["iat"] > payload["nbf"] or payload["exp"] <= payload["nbf"]:
        _fail("INVALID_TRUSTED_TIME_WINDOW", "iat <= nbf < exp is required")
    if payload["exp"] - payload["iat"] > MAX_TRUSTED_IDENTITY_TTL_SECONDS:
        _fail("TRUSTED_ASSERTION_TTL_EXCEEDED", "trusted identity assertion TTL is too long")
    if payload["principal_type"] not in {"human", "agent", "observer"}:
        _fail("MALFORMED_TRUSTED_ASSERTION", "unsupported principal type")
    if payload["transport"] not in KNOWN_TRANSPORTS:
        _fail("MALFORMED_TRUSTED_ASSERTION", "unsupported transport")
    if "peer_identity" in payload:
        _identifier(payload["peer_identity"], "peer_identity")
    return dict(payload)


def _sign_payload(payload: Mapping[str, Any], identity: LocalIdentity) -> str:
    segment = _b64(canonical_json_bytes(payload))
    signing_input = f"{TRUSTED_IDENTITY_PREFIX}.{segment}".encode("ascii")
    return f"{TRUSTED_IDENTITY_PREFIX}.{segment}.{_b64(identity.private_key.sign(signing_input))}"


def parse_trusted_identity_assertion(compact: str) -> tuple[dict[str, Any], bytes, str]:
    if not isinstance(compact, str):
        _fail("MALFORMED_TRUSTED_ASSERTION", "assertion must be a string")
    parts = compact.split(".")
    if len(parts) != 3 or parts[0] != TRUSTED_IDENTITY_PREFIX:
        _fail("MALFORMED_TRUSTED_ASSERTION", "invalid trusted assertion envelope")
    payload_bytes = _unb64(parts[1])
    signature = _unb64(parts[2])
    if len(signature) != 64:
        _fail("MALFORMED_TRUSTED_ASSERTION", "Ed25519 signatures must be 64 bytes")
    import json

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail("MALFORMED_TRUSTED_ASSERTION", "payload is not valid UTF-8 JSON")
        raise AssertionError from exc
    if not isinstance(payload, Mapping) or canonical_json_bytes(payload) != payload_bytes:
        _fail("MALFORMED_TRUSTED_ASSERTION", "payload is not canonical JSON")
    return _validate_payload(payload), signature, parts[1]


def _audit(sink: AuditSink | None, *, result: str, code: str, payload: Mapping[str, Any] | None = None, action: str) -> None:
    if sink is None:
        return
    value = payload or {}
    sink.append(AuditEvent(
        event_id=str(uuid.uuid4()),
        principal_type="trusted_dev",
        principal_id=value.get("sub", "") if isinstance(value.get("sub", ""), str) else "",
        key_id=value.get("kid", "") if isinstance(value.get("kid", ""), str) else "",
        environment=value.get("environment", "") if isinstance(value.get("environment", ""), str) else "",
        audience=value.get("aud", "") if isinstance(value.get("aud", ""), str) else "",
        scope=",".join(value.get("scopes", [])) if isinstance(value.get("scopes"), list) else "",
        action=action,
        http_method="",
        canonical_path="",
        body_sha256=sha256_hex(b""),
        resource=None,
        request_id=value.get("jti", "") if isinstance(value.get("jti", ""), str) else "",
        jti=value.get("jti", "") if isinstance(value.get("jti", ""), str) else "",
        result=result, result_code=code,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    ))


class TrustedAccessAuthority:
    """Issues short-lived signed identity assertions after policy evaluation."""

    def __init__(self, identity: LocalIdentity, registry: Registry, config: TrustedAccessConfig, *, replay_store: ReplayStore | None = None, audit_sink: AuditSink | None = None, transport_verifiers: Mapping[str, TransportVerifier] | None = None) -> None:
        self.identity = identity
        self.registry = registry
        self.config = config
        self.replay_store = replay_store
        self.audit_sink = audit_sink
        self.transport_verifiers = dict(transport_verifiers or {})
        if not config.enabled:
            _fail("TRUSTED_ACCESS_DISABLED", "trusted DEV access is not enabled")
        if config.environment is None or not is_dev_environment(config.environment):
            _fail("TRUSTED_ACCESS_NOT_DEV", "trusted access can only be enabled for DEV")
        principal = registry.principals.get(identity.principal_id)
        key = registry.keys.get(identity.key_id)
        if principal is None or key is None or key.principal_id != identity.principal_id:
            _fail("AUTHORITY_NOT_REGISTERED", "trusted access authority identity is not registered")
        if identity.environment != principal.environment or not is_dev_environment(identity.environment):
            _fail("AUTHORITY_NOT_DEV", "trusted access authority identity is not DEV")
        if key.public_key != encode_public_key(identity.public_key_bytes):
            _fail("AUTHORITY_KEY_MISMATCH", "authority key does not match registry")

    def issue(self, *, requested_principal: str, audience: str, scopes: Iterable[str], observation: TransportObservation, now: int | None = None, ttl_seconds: int = 60) -> str:
        payload: dict[str, Any] | None = None
        try:
            if observation.transport not in self.config.transports:
                _fail("TRANSPORT_NOT_ALLOWED", "transport is not enabled by trusted access policy")
            verifier = self.transport_verifiers.get(observation.transport)
            if verifier is None or verifier.transport != observation.transport:
                _fail("TRANSPORT_VERIFIER_MISSING", "no server-side verifier is configured for transport")
            evidence = verifier.verify(observation)
            policy = self.config.policy_for(requested_principal)
            requested_scopes = tuple(scopes)
            if not requested_scopes or len(set(requested_scopes)) != len(requested_scopes):
                _fail("SCOPE_DENIED", "requested scopes must be non-empty and unique")
            for scope in requested_scopes:
                _identifier(scope, "requested scope")
            if any(scope not in policy.scopes for scope in requested_scopes):
                _fail("SCOPE_DENIED", "requested scope is not allowed for the trusted principal")
            _identifier(audience, "audience")
            created = int(time.time()) if now is None else now
            if isinstance(created, bool) or not isinstance(created, int) or created < 0 or isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0 or ttl_seconds > MAX_TRUSTED_IDENTITY_TTL_SECONDS:
                _fail("INVALID_TRUSTED_TIME_WINDOW", "invalid trusted assertion time or TTL")
            authority_principal = self.registry.principals[self.identity.principal_id]
            authority_key = self.registry.keys[self.identity.key_id]
            if not authority_principal.enabled or authority_principal.revoked_at is not None:
                _fail("AUTHORITY_REVOKED", "trusted access authority principal is disabled or revoked")
            if not authority_key.enabled or authority_key.revoked_at is not None:
                _fail("AUTHORITY_REVOKED", "trusted access authority key is disabled or revoked")
            if authority_key.algorithm != "Ed25519":
                _fail("AUTHORITY_ALGORITHM_UNSUPPORTED", "trusted access authority key algorithm is unsupported")
            if authority_key.expires_at is not None:
                try:
                    if datetime.fromisoformat(authority_key.expires_at.replace("Z", "+00:00")) <= datetime.fromtimestamp(created, timezone.utc):
                        _fail("KEY_EXPIRED", "trusted access authority key is expired")
                except ValueError:
                    _fail("INVALID_REGISTRY", "key expires_at is not valid RFC3339")
            payload = {
                "aud": audience,
                "environment": self.config.environment,
                "exp": created + ttl_seconds,
                "iat": created,
                "iss": self.identity.principal_id,
                "jti": str(uuid.uuid4()),
                "key_epoch": authority_key.key_epoch,
                "kid": self.identity.key_id,
                "nbf": created,
                "principal_epoch": authority_principal.revocation_epoch,
                "principal_type": policy.principal_type,
                "scopes": sorted(requested_scopes),
                "sub": policy.subject,
                "transport": evidence.transport,
                "version": TRUSTED_IDENTITY_VERSION,
            }
            if evidence.peer_identity is not None:
                payload["peer_identity"] = evidence.peer_identity
            payload = _validate_payload(payload)
            assertion = _sign_payload(payload, self.identity)
            _audit(self.audit_sink, result="AUTHORIZED", code="TRUSTED_IDENTITY_ISSUED", payload=payload, action="trusted_dev.issue")
            return assertion
        except TrustedAccessError as exc:
            _audit(self.audit_sink, result="REJECTED", code=exc.code, payload=payload, action="trusted_dev.issue")
            raise


class TrustedIdentityVerifier:
    """Verifies identity assertions and keeps application authorization active."""

    def __init__(self, registry: Registry, config: TrustedAccessConfig, replay_store: ReplayStore, *, expected_audience: str, audit_sink: AuditSink | None = None, transport_verifiers: Mapping[str, TransportVerifier] | None = None) -> None:
        if not config.enabled:
            _fail("TRUSTED_ACCESS_DISABLED", "trusted DEV access is not enabled")
        if not expected_audience or config.environment is None:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted identity verifier requires audience and environment")
        self.registry = registry
        self.config = config
        self.replay_store = replay_store
        self.expected_audience = expected_audience
        self.audit_sink = audit_sink
        self.transport_verifiers = dict(transport_verifiers or {})

    def verify(self, assertion: str, *, observation: TransportObservation, now: int, action: str = "trusted_dev.verify") -> TrustedIdentityEvidence:
        payload: dict[str, Any] | None = None
        try:
            payload, signature, segment = parse_trusted_identity_assertion(assertion)
            if payload["aud"] != self.expected_audience:
                _fail("WRONG_AUDIENCE", "trusted assertion audience does not match verifier")
            if payload["environment"] != self.config.environment:
                _fail("WRONG_ENVIRONMENT", "trusted assertion environment does not match verifier")
            if not is_dev_environment(payload["environment"]):
                _fail("TRUSTED_ACCESS_NOT_DEV", "trusted identity assertions are DEV-only")
            if now < payload["nbf"]:
                _fail("NOT_YET_VALID", "trusted assertion is not yet valid")
            if now >= payload["exp"]:
                _fail("EXPIRED", "trusted assertion has expired")
            if payload["transport"] not in self.config.transports or observation.transport != payload["transport"]:
                _fail("UNTRUSTED_TRANSPORT", "asserted transport is not allowed for this request")
            verifier = self.transport_verifiers.get(observation.transport)
            if verifier is None or verifier.transport != observation.transport:
                _fail("TRANSPORT_VERIFIER_MISSING", "no server-side verifier is configured for transport")
            transport = verifier.verify(observation)
            if payload.get("peer_identity") is not None and payload["peer_identity"] != transport.peer_identity:
                _fail("UNTRUSTED_TRANSPORT", "current Tailscale peer does not match assertion")
            key = self.registry.keys.get(payload["kid"])
            if key is None:
                _fail("UNKNOWN_KEY", "trusted assertion key is not registered")
            if not key.enabled or key.revoked_at is not None:
                _fail("KEY_REVOKED", "trusted assertion key is disabled or revoked")
            if key.expires_at is not None:
                try:
                    if datetime.fromisoformat(key.expires_at.replace("Z", "+00:00")) <= datetime.fromtimestamp(now, timezone.utc):
                        _fail("KEY_EXPIRED", "trusted assertion key is expired")
                except ValueError:
                    _fail("INVALID_REGISTRY", "key expires_at is not valid RFC3339")
            principal = self.registry.principals.get(key.principal_id)
            if principal is None:
                _fail("UNKNOWN_PRINCIPAL", "trusted assertion issuer is not registered")
            if not principal.enabled or principal.revoked_at is not None:
                _fail("PRINCIPAL_REVOKED", "trusted assertion issuer is disabled or revoked")
            if payload["iss"] != principal.principal_id or payload["principal_epoch"] != principal.revocation_epoch or payload["key_epoch"] != key.key_epoch:
                _fail("STALE_AUTHORITY_EPOCH", "trusted assertion authority epoch is stale")
            Ed25519PublicKey.from_public_bytes(decode_public_key(key.public_key)).verify(signature, f"{TRUSTED_IDENTITY_PREFIX}.{segment}".encode("ascii"))
            policy = next((item for item in (self.config.principals or {}).values() if item.subject == payload["sub"] and item.principal_type == payload["principal_type"]), None)
            if policy is None or any(scope not in policy.scopes for scope in payload["scopes"]):
                _fail("SCOPE_DENIED", "trusted assertion principal or scope is not allowed")
            if self.replay_store is None or not self.replay_store.consume(payload["jti"], payload["exp"], now=now):
                _fail("REPLAYED_JTI", "trusted identity assertion has already been consumed")
            result = TrustedIdentityEvidence(payload["iss"], payload["sub"], payload["principal_type"], tuple(payload["scopes"]), payload["aud"], payload["environment"], payload["transport"], payload["jti"], payload["iat"], payload["exp"])
            _audit(self.audit_sink, result="AUTHORIZED", code="TRUSTED_IDENTITY_VERIFIED", payload=payload, action=action)
            return result
        except TrustedAccessError as exc:
            _audit(self.audit_sink, result="REJECTED", code=exc.code, payload=payload, action=action)
            raise
        except Exception as exc:
            code = "BAD_SIGNATURE" if exc.__class__.__name__ == "InvalidSignature" else "MALFORMED_TRUSTED_ASSERTION"
            _audit(self.audit_sink, result="REJECTED", code=code, payload=payload, action=action)
            _fail(code, "trusted identity assertion verification failed")


class ApplicationPrincipalResolver(Protocol):
    """Application-owned mapping from a trusted subject to a normal session principal."""

    def __call__(self, evidence: TrustedIdentityEvidence) -> Any:
        ...


def establish_application_principal(
    verifier: TrustedIdentityVerifier,
    assertion: str,
    *,
    observation: TransportObservation,
    now: int,
    resolver: ApplicationPrincipalResolver,
) -> Any:
    """Verify agentctl identity, then let the application establish its session."""

    return resolver(verifier.verify(assertion, observation=observation, now=now))
