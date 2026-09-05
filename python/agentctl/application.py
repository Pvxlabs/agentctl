"""Application-facing Trusted Access SDK and adapter contract.

The SDK owns assertion parsing and verification.  An application adapter owns
the final mapping into the application's normal authenticated principal or
session; no adapter is allowed to replace the application's authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Generic, Mapping, Protocol, TypeVar

from .trusted import AgentctlPrincipal, TrustedAccessError, TrustedIdentityVerifier, TransportObservation


class ApplicationAdapterError(ValueError):
    """The application has no safe identity mapping for a trusted subject."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ApplicationAuthorizationError(ValueError):
    """Application-facing authorization failure for a trusted principal."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class MappedApplicationPrincipal:
    """Reference result for the declarative mapping adapter.

    ``application_identity`` is intentionally opaque to agentctl.  The target
    application can use it to load or create its ordinary session principal.
    """

    application_identity: str
    trusted_principal: AgentctlPrincipal

    @property
    def subject(self) -> str:
        return self.trusted_principal.subject

    @property
    def scopes(self) -> tuple[str, ...]:
        return self.trusted_principal.scopes

    def has_scope(self, scope: str) -> bool:
        return self.trusted_principal.has_scope(scope)

    def require_scope(self, scope: str) -> None:
        self.trusted_principal.require_scope(scope)


class ApplicationAdapter(Protocol):
    """Application-owned subject-to-session boundary."""

    def establish(self, principal: AgentctlPrincipal) -> Any:
        """Establish the application's normal authenticated principal/session."""


class DeclarativeMappingAdapter:
    """Map trusted subjects to application identities from explicit config."""

    def __init__(self, mappings: Mapping[str, str]):
        if not isinstance(mappings, Mapping):
            raise ApplicationAdapterError("APPLICATION_ADAPTER_INVALID", "application adapter mappings must be an object")
        self.mappings: dict[str, str] = {}
        for subject, application_identity in mappings.items():
            if not isinstance(subject, str) or not subject.strip() or subject != subject.strip():
                raise ApplicationAdapterError("APPLICATION_ADAPTER_INVALID", "application adapter subject must be a trimmed string")
            if not isinstance(application_identity, str) or not application_identity.strip() or application_identity != application_identity.strip():
                raise ApplicationAdapterError("APPLICATION_ADAPTER_INVALID", "application adapter identity must be a trimmed string")
            self.mappings[subject] = application_identity

    def establish(self, principal: AgentctlPrincipal) -> MappedApplicationPrincipal:
        application_identity = self.mappings.get(principal.subject)
        if not isinstance(application_identity, str) or not application_identity.strip():
            raise ApplicationAdapterError(
                "APPLICATION_IDENTITY_MAPPING_MISSING",
                f"no application identity mapping exists for trusted subject {principal.subject}",
            )
        return MappedApplicationPrincipal(application_identity.strip(), principal)


CustomApplicationAdapter = ApplicationAdapter

TApplicationPrincipal = TypeVar("TApplicationPrincipal")


@dataclass(frozen=True)
class ApplicationAuthentication(Generic[TApplicationPrincipal]):
    """The result of trusted identity verification plus application mapping."""

    agentctl_principal: AgentctlPrincipal
    application_principal: TApplicationPrincipal


class TrustedAccessSDK(Generic[TApplicationPrincipal]):
    """High-level application API; callers do not handle cryptographic APIs."""

    def __init__(self, verifier: TrustedIdentityVerifier, adapter: ApplicationAdapter):
        self.verifier = verifier
        self.adapter = adapter

    def verify(
        self,
        assertion: str,
        *,
        observation: TransportObservation,
        now: int,
    ) -> AgentctlPrincipal:
        return self.verifier.verify_principal(assertion, observation=observation, now=now)

    def establish(self, principal: AgentctlPrincipal) -> TApplicationPrincipal:
        return self.adapter.establish(principal)

    def authenticate(
        self,
        assertion: str,
        *,
        observation: TransportObservation,
        now: int,
    ) -> TApplicationPrincipal:
        return self.authenticate_with_context(assertion, observation=observation, now=now).application_principal

    def authenticate_with_context(
        self,
        assertion: str,
        *,
        observation: TransportObservation,
        now: int,
    ) -> ApplicationAuthentication[TApplicationPrincipal]:
        principal = self.verify(assertion, observation=observation, now=now)
        return ApplicationAuthentication(principal, self.establish(principal))

    @staticmethod
    def require_scope(principal: AgentctlPrincipal, scope: str) -> None:
        principal.require_scope(scope)


def extract_trusted_assertion(authorization_header: str | None, *, scheme: str = "Agentctl-Trusted") -> str:
    """Extract the dedicated trusted identity scheme without accepting AAV1."""

    if not isinstance(authorization_header, str):
        raise TrustedAccessError("MISSING_TRUSTED_ASSERTION", "missing trusted identity assertion")
    prefix, separator, assertion = authorization_header.partition(" ")
    token = assertion.strip()
    if prefix != scheme or not separator or not token or any(character.isspace() for character in token):
        raise TrustedAccessError("MALFORMED_TRUSTED_ASSERTION", f"expected {scheme} assertion")
    return token
