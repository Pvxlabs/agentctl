"""ATIP v1 compatibility checks used by the CLI and reference applications."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .application import ApplicationAuthorizationError
from .identity import LocalIdentity
from .manifest import ProjectManifest
from .models import KeyRecord, PrincipalRecord
from .registry import Registry, encode_public_key
from .replay import MemoryReplayStore
from .trusted import (
    ATIP_VERSION,
    LocalhostTransportVerifier,
    TransportObservation,
    TrustedAccessAuthority,
    TrustedApplicationConfig,
    TrustedAccessConfig,
    TrustedAccessError,
    TrustedIdentityVerifier,
)


@dataclass(frozen=True)
class ConformanceCase:
    name: str
    passed: bool
    expected: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _context(
    manifest: ProjectManifest,
) -> tuple[
    TrustedAccessAuthority,
    TrustedIdentityVerifier,
    TrustedAccessConfig,
    TransportObservation,
    LocalIdentity,
    Registry,
    LocalhostTransportVerifier,
]:
    config = manifest.trusted_access
    if not config.enabled or config.environment is None:
        raise TrustedAccessError("TRUSTED_ACCESS_DISABLED", "ATIP conformance requires enabled DEV trusted access")
    key = Ed25519PrivateKey.generate()
    identity = LocalIdentity("conformance-authority", "ATIP Conformance Authority", config.environment, "conformance-key", "Ed25519", key)
    registry = Registry()
    registry.add_principal(PrincipalRecord(identity.principal_id, identity.display_name, identity.environment))
    registry.add_key(KeyRecord(identity.key_id, identity.principal_id, identity.algorithm, encode_public_key(identity.public_key_bytes)))
    localhost = LocalhostTransportVerifier()
    authority = TrustedAccessAuthority(identity, registry, config, transport_verifiers={"localhost": localhost})
    verifier = TrustedIdentityVerifier(registry, config, MemoryReplayStore(), expected_audience=_audience(manifest), transport_verifiers={"localhost": localhost})
    return authority, verifier, config, TransportObservation("localhost", "127.0.0.1"), identity, registry, localhost


def _audience(manifest: ProjectManifest) -> str:
    configured = manifest.trusted_access.application.audience if manifest.trusted_access.application else None
    if configured:
        return configured
    return next(iter(manifest.audiences.values())).audience


def _case(name: str, expected: str, operation: Callable[[], None]) -> ConformanceCase:
    try:
        operation()
    except Exception as exc:
        return ConformanceCase(name, False, expected, f"unexpected failure: {type(exc).__name__}: {exc}")
    return ConformanceCase(name, True, expected, "ok")


def _reject_case(name: str, expected_code: str, operation: Callable[[], None]) -> ConformanceCase:
    try:
        operation()
    except TrustedAccessError as exc:
        return ConformanceCase(name, exc.code == expected_code, expected_code, exc.code)
    except Exception as exc:
        return ConformanceCase(name, False, expected_code, f"unexpected error: {type(exc).__name__}: {exc}")
    return ConformanceCase(name, False, expected_code, "operation was unexpectedly authorized")


def run_conformance(manifest: ProjectManifest, *, now: int = 1_700_000_000) -> dict[str, Any]:
    """Run deterministic ATIP cases and return CI-friendly JSON data."""

    if not manifest.trusted_access.enabled:
        return {"protocol": ATIP_VERSION, "compatible": False, "passed": 0, "failed": 1, "cases": [{"name": "TRUSTED_ACCESS_ENABLED", "passed": False, "expected": "enabled DEV policy", "detail": "trusted access is disabled"}]}
    try:
        authority, verifier, config, observation, identity, registry, localhost = _context(manifest)
    except Exception as exc:
        return {"protocol": ATIP_VERSION, "compatible": False, "passed": 0, "failed": 1, "cases": [{"name": "CONTEXT_INITIALIZATION", "passed": False, "expected": "valid ATIP context", "detail": str(exc)}]}

    audience = _audience(manifest)
    policies = config.principals or {}
    cases: list[ConformanceCase] = []

    def valid(name: str, requested_scopes: list[str]) -> None:
        assertion = authority.issue(requested_principal=name, audience=audience, scopes=requested_scopes, observation=observation, now=now)
        verifier.verify(assertion, observation=observation, now=now + 1)

    for name, case_name in (("user", "VALID_DEV_USER"), ("admin", "VALID_DEV_ADMIN"), ("agent", "VALID_DEV_AGENT")):
        policy = policies.get(name)
        if policy is None:
            cases.append(ConformanceCase(case_name, False, "authorized", "required principal is not configured"))
        else:
            cases.append(_case(case_name, "authorized", lambda name=name, policy=policy: valid(name, [policy.scopes[0]])))

    cases.append(_reject_case("UNKNOWN_PRINCIPAL_REJECTED", "UNKNOWN_TRUSTED_PRINCIPAL", lambda: authority.issue(requested_principal="unknown", audience=audience, scopes=["app:read"], observation=observation, now=now)))
    agent = policies.get("agent")
    if agent is None:
        cases.append(ConformanceCase("SCOPE_ESCALATION_REJECTED", False, "SCOPE_DENIED", "agent principal is not configured"))
    else:
        cases.append(_reject_case("SCOPE_ESCALATION_REJECTED", "SCOPE_DENIED", lambda: authority.issue(requested_principal="agent", audience=audience, scopes=["app:admin"], observation=observation, now=now)))

    # The normal authority intentionally binds issuance to its configured
    # application audience. Use a second authority with the same key and
    # policy to create a validly signed wrong-audience vector for verifier
    # conformance testing without weakening that issuance invariant.
    wrong_audience_config = replace(
        config,
        application=TrustedApplicationConfig(
            config.application.identity if config.application else manifest.project,
            "wrong-audience",
        ),
    )
    wrong_audience_authority = TrustedAccessAuthority(
        identity,
        registry,
        wrong_audience_config,
        transport_verifiers={"localhost": localhost},
    )
    wrong_audience = wrong_audience_authority.issue(requested_principal=next(iter(policies)), audience="wrong-audience", scopes=[next(iter(policies.values())).scopes[0]], observation=observation, now=now)
    cases.append(_reject_case("WRONG_AUDIENCE_REJECTED", "WRONG_AUDIENCE", lambda: verifier.verify(wrong_audience, observation=observation, now=now + 1)))
    expired = authority.issue(requested_principal=next(iter(policies)), audience=audience, scopes=[next(iter(policies.values())).scopes[0]], observation=observation, now=now, ttl_seconds=1)
    cases.append(_reject_case("EXPIRED_ASSERTION_REJECTED", "EXPIRED", lambda: verifier.verify(expired, observation=observation, now=now + 1)))
    fresh = authority.issue(requested_principal=next(iter(policies)), audience=audience, scopes=[next(iter(policies.values())).scopes[0]], observation=observation, now=now)
    parts = fresh.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    cases.append(_reject_case("TAMPERED_ASSERTION_REJECTED", "BAD_SIGNATURE", lambda: verifier.verify(".".join(parts), observation=observation, now=now + 1)))
    replay = authority.issue(requested_principal=next(iter(policies)), audience=audience, scopes=[next(iter(policies.values())).scopes[0]], observation=observation, now=now)
    verifier.verify(replay, observation=observation, now=now + 1)
    cases.append(_reject_case("REPLAY_REJECTED", "REPLAYED_JTI", lambda: verifier.verify(replay, observation=observation, now=now + 1)))
    cases.append(_reject_case("PRODUCTION_TRUSTED_ACCESS_REJECTED", "TRUSTED_ACCESS_NOT_DEV", lambda: TrustedAccessConfig.from_mapping({"enabled": True, "environment": "production", "transports": ["localhost"], "principals": {"agent": {"subject": "dev-agent", "scopes": ["app:test"]}}})))
    cases.append(_reject_case("UNTRUSTED_TRANSPORT_REJECTED", "UNTRUSTED_TRANSPORT", lambda: LocalhostTransportVerifier().verify(TransportObservation("localhost", "100.90.1.2"))))
    cases.append(_reject_case("SPOOFED_FORWARDING_HEADER_REJECTED", "UNTRUSTED_TRANSPORT", lambda: LocalhostTransportVerifier().verify(TransportObservation("localhost", "127.0.0.1", forwarded_headers_present=True))))

    user = policies.get("user")
    if user is None:
        cases.append(ConformanceCase("APPLICATION_AUTHORIZATION_RETAINED", False, "SCOPE_DENIED", "user principal is not configured"))
    else:
        assertion = authority.issue(requested_principal="user", audience=audience, scopes=[user.scopes[0]], observation=observation, now=now)
        principal = verifier.verify_principal(assertion, observation=observation, now=now + 1)
        cases.append(_reject_case("APPLICATION_AUTHORIZATION_RETAINED", "SCOPE_DENIED", lambda: principal.require_scope("app:admin")))

    passed = sum(case.passed for case in cases)
    return {"protocol": ATIP_VERSION, "compatible": passed == len(cases), "passed": passed, "failed": len(cases) - passed, "cases": [case.to_dict() for case in cases]}


def run_smoke_test(manifest: ProjectManifest, *, now: int = 1_700_000_000) -> dict[str, Any]:
    """Exercise one complete issue -> verify -> principal path locally."""

    if not manifest.trusted_access.enabled:
        return {"passed": False, "result": "DISABLED", "message": "trusted access is disabled"}
    authority, verifier, config, observation, _identity, _registry, _localhost = _context(manifest)
    name = "agent" if "agent" in (config.principals or {}) else next(iter(config.principals or {}))
    policy = (config.principals or {})[name]
    assertion = authority.issue(requested_principal=name, audience=_audience(manifest), scopes=[policy.scopes[0]], observation=observation, now=now)
    principal = verifier.verify_principal(assertion, observation=observation, now=now + 1)
    return {"passed": True, "result": "AUTHORIZED", "principal": principal.to_dict()}
