"""Trusted Development Access identity establishment.

This module is deliberately separate from the request-bound AAV1 verifier.  A
trusted DEV request establishes an application-neutral principal first; the
target application then maps that subject to its own normal user/session and
continues enforcing its existing authorization rules.
"""

from __future__ import annotations

import ipaddress
import http.client
import json
import re
import socket
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol
from urllib.parse import urlencode

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .audit import AuditEvent, AuditSink
from .identity import LocalIdentity
from .protocol import canonical_json_bytes, sha256_hex
from .registry import Registry, decode_public_key, encode_public_key
from .replay import ReplayStore


TRUSTED_IDENTITY_VERSION = "trusted-dev-identity/v1"
TRUSTED_IDENTITY_PREFIX = "agentctl-tdi1"
# Public protocol name/version.  The wire version above remains the stable
# compatibility identifier for existing producers and verifiers.
ATIP_PROTOCOL_NAME = "Agentctl Trusted Identity Protocol"
ATIP_VERSION = "ATIP-v1"
ATIP_WIRE_VERSION = TRUSTED_IDENTITY_VERSION
MAX_TRUSTED_IDENTITY_TTL_SECONDS = 300
DEV_ENVIRONMENTS = frozenset({"dev", "development"})
KNOWN_TRANSPORTS = frozenset({"localhost", "tailscale"})
TAILSCALE_SOCKET_PEER_INVARIANT = (
    "Tailscale trust requires the server-observed socket peer address to be "
    "resolved by the local tailscaled LocalAPI; address range membership alone "
    "never authorizes a request."
)
TAILSCALE_LOCALAPI_RESOLVER = "tailscale-localapi/v0/whois"
TAILSCALE_LOCALAPI_SOCKET = "/run/tailscale/tailscaled.sock"
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
class TrustedApplicationConfig:
    """Optional application metadata declared by a project manifest."""

    identity: str
    audience: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.identity, "trusted_access.application.identity")
        if self.audience is not None:
            _identifier(self.audience, "trusted_access.application.audience")


@dataclass(frozen=True)
class TrustedAdapterConfig:
    """Manifest metadata for the application-owned adapter boundary."""

    type: str
    mappings: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in {"declarative_mapping", "custom"}:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "unsupported trusted access adapter type")
        if not isinstance(self.mappings, Mapping):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted adapter mappings must be an object")
        for subject, application_identity in self.mappings.items():
            _identifier(subject, "trusted adapter subject")
            if not isinstance(application_identity, str) or not application_identity.strip() or application_identity != application_identity.strip():
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted adapter application identity must be a trimmed string")
        if self.type == "declarative_mapping" and not self.mappings:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "declarative mapping adapter requires mappings")


@dataclass(frozen=True)
class DevIdentityProfile:
    """Application-owned identity mapping used by onboarding only.

    These values are deliberately outside the ATIP wire protocol.  They are
    onboarding defaults and are consumed by the application bootstrap adapter.
    """

    principal: str
    account: str
    role: str

    def __post_init__(self) -> None:
        _identifier(self.principal, "trusted_access.dev_profile.principal")
        if not isinstance(self.account, str) or not self.account.strip() or self.account != self.account.strip():
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.dev_profile.account must be a trimmed string")
        _identifier(self.role, "trusted_access.dev_profile.role")


@dataclass(frozen=True)
class TrustedCommandConfig:
    """An explicitly application-owned command allowed by onboarding."""

    command: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.command or any(not isinstance(item, str) or not item.strip() for item in self.command):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "onboarding command must contain non-empty strings")


@dataclass(frozen=True)
class TrustedIdentityBootstrapConfig:
    """How a consumer application owns DEV identity creation/inspection."""

    type: str
    command: TrustedCommandConfig | None = None
    module: str | None = None

    def __post_init__(self) -> None:
        if self.type not in {"command", "adapter"}:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "identity bootstrap type must be command or adapter")
        if self.type == "command" and self.module is not None:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "command identity bootstrap cannot declare module")
        if self.type == "adapter" and self.command is not None:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "adapter identity bootstrap cannot declare command")
        if self.type == "command" and self.command is None:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "command identity bootstrap requires command")
        if self.type == "adapter" and (not isinstance(self.module, str) or not self.module.strip()):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "adapter identity bootstrap requires module")


@dataclass(frozen=True)
class TrustedOnboardingConfig:
    """Optional, explicit consumer onboarding contracts."""

    identity_bootstrap: TrustedIdentityBootstrapConfig | None = None
    start: TrustedCommandConfig | None = None
    restart: TrustedCommandConfig | None = None
    smoke: TrustedCommandConfig | None = None


@dataclass(frozen=True)
class TrustedHandoffConfig:
    enabled: bool = False


@dataclass(frozen=True)
class TrustedIngressSurface:
    path: str
    principal: str
    audience: str
    scopes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path.startswith("/") or "?" in self.path or "#" in self.path:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress surface path must be an absolute path without query or fragment")
        _identifier(self.principal, "trusted ingress surface principal")
        _identifier(self.audience, "trusted ingress surface audience")
        if not self.scopes or len(set(self.scopes)) != len(self.scopes):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress surface scopes must be non-empty and unique")
        for scope in self.scopes:
            _identifier(scope, "trusted ingress surface scope")


@dataclass(frozen=True)
class TrustedIngressConfig:
    mode: str
    bind: str
    port: int
    upstream: str
    endpoint: str
    surfaces: Mapping[str, TrustedIngressSurface]

    def __post_init__(self) -> None:
        if self.mode != "session_bootstrap":
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress mode must be session_bootstrap")
        if not isinstance(self.bind, str) or not self.bind.strip():
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress bind must be a non-empty string")
        try:
            address = ipaddress.ip_address(self.bind)
        except ValueError:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress bind must be an IP address")
        if address.is_unspecified or not (address.is_loopback or address in ipaddress.ip_network("100.64.0.0/10") or address in ipaddress.ip_network("fd7a:115c:a1e0::/48")):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress bind must be loopback or an explicit Tailscale address")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress port must be between 1 and 65535")
        if not isinstance(self.upstream, str) or not self.upstream.startswith(("http://", "https://")):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress upstream must be an HTTP(S) URL")
        if not isinstance(self.endpoint, str) or not self.endpoint.startswith("/") or "?" in self.endpoint or "#" in self.endpoint:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress endpoint must be an absolute path without query or fragment")
        if not isinstance(self.surfaces, Mapping) or not self.surfaces:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress surfaces must be a non-empty object")
        paths: set[str] = set()
        for name, surface in self.surfaces.items():
            _identifier(name, "trusted ingress surface name")
            if not isinstance(surface, TrustedIngressSurface):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress surface is malformed")
            if surface.path in paths:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress surface paths must be unique")
            paths.add(surface.path)


@dataclass(frozen=True)
class TrustedAccessConfig:
    enabled: bool = False
    environment: str | None = None
    transports: tuple[str, ...] = ()
    principals: Mapping[str, TrustedPrincipalPolicy] | None = None
    application: TrustedApplicationConfig | None = None
    adapter: TrustedAdapterConfig | None = None
    dev_profile: Mapping[str, DevIdentityProfile] | None = None
    onboarding: TrustedOnboardingConfig | None = None
    handoff: TrustedHandoffConfig | None = None
    ingress: TrustedIngressConfig | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted access enabled must be boolean")
        if self.environment is not None:
            _identifier(self.environment, "trusted_access.environment")
        if not isinstance(self.transports, tuple):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted transports must be a tuple")
        if any(not isinstance(item, str) or item not in KNOWN_TRANSPORTS for item in self.transports):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted transports must be localhost or tailscale")
        if len(set(self.transports)) != len(self.transports):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted transports must be unique")
        if not isinstance(self.principals, (Mapping, type(None))):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted principals must be a mapping")
        if self.application is not None and not isinstance(self.application, TrustedApplicationConfig):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted application metadata is malformed")
        if self.adapter is not None and not isinstance(self.adapter, TrustedAdapterConfig):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted adapter metadata is malformed")
        if self.dev_profile is not None:
            if not isinstance(self.dev_profile, Mapping):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted dev profile must be a mapping")
            for name, profile in self.dev_profile.items():
                if not isinstance(name, str) or not isinstance(profile, DevIdentityProfile):
                    _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted dev profile entry is malformed")
        if self.onboarding is not None and not isinstance(self.onboarding, TrustedOnboardingConfig):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted onboarding metadata is malformed")
        if self.handoff is not None and not isinstance(self.handoff, TrustedHandoffConfig):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted handoff metadata is malformed")
        if self.ingress is not None and not isinstance(self.ingress, TrustedIngressConfig):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress metadata is malformed")
        if self.ingress is not None and (self.handoff is None or not self.handoff.enabled):
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress requires handoff.enabled")
        values = self.principals or {}
        identities: set[tuple[str, str]] = set()
        for name, policy in values.items():
            if not isinstance(name, str) or not isinstance(policy, TrustedPrincipalPolicy):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted principal policy is malformed")
            if name != policy.name:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "principal policy name does not match its key")
            identity = (policy.subject, policy.principal_type)
            if identity in identities:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted principal subject and type must be unique")
            identities.add(identity)
        if not self.enabled:
            return
        if not self.environment or not is_dev_environment(self.environment):
            _fail("TRUSTED_ACCESS_NOT_DEV", "trusted access can only be enabled for DEV")
        if not self.transports:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted transports must be localhost or tailscale")
        if not values:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "at least one trusted principal is required")

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
            unknown_policy = set(raw) - {"name", "subject", "scopes", "type", "principal_type"}
            if unknown_policy:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"unknown trusted principal fields: {sorted(unknown_policy)}")
            if "name" in raw and raw["name"] != name:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"principal {name} name does not match its key")
            if "type" in raw and "principal_type" in raw and raw["type"] != raw["principal_type"]:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"principal {name} has ambiguous principal type")
            subject = raw.get("subject")
            scopes = raw.get("scopes")
            if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"principal {name} scopes must be a list")
            principal_type = raw.get("principal_type", raw.get("type", "agent" if name == "agent" else "human"))
            principals[name] = TrustedPrincipalPolicy(name, subject, tuple(scopes), principal_type)
        raw_application = value.get("application")
        application = None
        if raw_application is not None:
            if not isinstance(raw_application, Mapping):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.application must be an object")
            unknown_application = set(raw_application) - {"identity", "audience"}
            if unknown_application:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"unknown trusted application fields: {sorted(unknown_application)}")
            application = TrustedApplicationConfig(raw_application.get("identity"), raw_application.get("audience"))
        raw_adapter = value.get("adapter")
        adapter = None
        if raw_adapter is not None:
            if not isinstance(raw_adapter, Mapping):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.adapter must be an object")
            unknown_adapter = set(raw_adapter) - {"type", "mappings"}
            if unknown_adapter:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"unknown trusted adapter fields: {sorted(unknown_adapter)}")
            raw_mappings = raw_adapter.get("mappings", {})
            if not isinstance(raw_mappings, Mapping):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted adapter mappings must be an object")
            adapter = TrustedAdapterConfig(raw_adapter.get("type", "custom"), dict(raw_mappings))
        raw_profile = value.get("dev_profile")
        dev_profile = None
        if raw_profile is not None:
            if not isinstance(raw_profile, Mapping):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.dev_profile must be an object")
            dev_profile = {}
            for name, raw in raw_profile.items():
                if not isinstance(name, str) or not isinstance(raw, Mapping):
                    _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted dev profile entry is malformed")
                unknown_profile = set(raw) - {"principal", "account", "role"}
                if unknown_profile:
                    _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"unknown trusted dev profile fields: {sorted(unknown_profile)}")
                dev_profile[name] = DevIdentityProfile(raw.get("principal"), raw.get("account"), raw.get("role"))

        def command_config(raw: Any, field: str) -> TrustedCommandConfig | None:
            if raw is None:
                return None
            if not isinstance(raw, Mapping) or set(raw) != {"command"}:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"{field} must contain only command")
            command = raw.get("command")
            if not isinstance(command, list):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"{field}.command must be a list")
            return TrustedCommandConfig(tuple(command))

        raw_onboarding = value.get("onboarding")
        onboarding = None
        if raw_onboarding is not None:
            if not isinstance(raw_onboarding, Mapping):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.onboarding must be an object")
            unknown_onboarding = set(raw_onboarding) - {"identity_bootstrap", "start", "restart", "smoke"}
            if unknown_onboarding:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"unknown trusted onboarding fields: {sorted(unknown_onboarding)}")
            raw_bootstrap = raw_onboarding.get("identity_bootstrap")
            identity_bootstrap = None
            if raw_bootstrap is not None:
                if not isinstance(raw_bootstrap, Mapping):
                    _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "identity_bootstrap must be an object")
                bootstrap_unknown = set(raw_bootstrap) - {"type", "command", "module"}
                if bootstrap_unknown:
                    _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"unknown identity bootstrap fields: {sorted(bootstrap_unknown)}")
                bootstrap_type = raw_bootstrap.get("type")
                bootstrap_command = command_config({"command": raw_bootstrap.get("command")}, "identity_bootstrap") if "command" in raw_bootstrap else None
                if bootstrap_type == "command" and "module" in raw_bootstrap:
                    _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "command identity bootstrap cannot declare module")
                if bootstrap_type == "adapter" and "command" in raw_bootstrap:
                    _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "adapter identity bootstrap cannot declare command")
                identity_bootstrap = TrustedIdentityBootstrapConfig(bootstrap_type, bootstrap_command, raw_bootstrap.get("module"))
            onboarding = TrustedOnboardingConfig(
                identity_bootstrap=identity_bootstrap,
                start=command_config(raw_onboarding.get("start"), "onboarding.start"),
                restart=command_config(raw_onboarding.get("restart"), "onboarding.restart"),
                smoke=command_config(raw_onboarding.get("smoke"), "onboarding.smoke"),
            )
        raw_handoff = value.get("handoff")
        handoff = None
        if raw_handoff is not None:
            if not isinstance(raw_handoff, Mapping) or set(raw_handoff) != {"enabled"} or not isinstance(raw_handoff["enabled"], bool):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.handoff must contain boolean enabled")
            handoff = TrustedHandoffConfig(raw_handoff["enabled"])

        raw_ingress = value.get("ingress")
        ingress = None
        if raw_ingress is not None:
            if not isinstance(raw_ingress, Mapping):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted_access.ingress must be an object")
            unknown_ingress = set(raw_ingress) - {"mode", "bind", "port", "upstream", "endpoint", "surfaces"}
            if unknown_ingress:
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"unknown trusted ingress fields: {sorted(unknown_ingress)}")
            raw_surfaces = raw_ingress.get("surfaces")
            if not isinstance(raw_surfaces, Mapping):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress surfaces must be an object")
            surfaces: dict[str, TrustedIngressSurface] = {}
            for name, raw_surface in raw_surfaces.items():
                if not isinstance(name, str) or not isinstance(raw_surface, Mapping):
                    _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress surface is malformed")
                if set(raw_surface) - {"path", "principal", "audience", "scopes"}:
                    _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"unknown trusted ingress surface fields: {sorted(set(raw_surface) - {'path', 'principal', 'audience', 'scopes'})}")
                raw_scopes = raw_surface.get("scopes")
                if not isinstance(raw_scopes, list) or not all(isinstance(scope, str) for scope in raw_scopes):
                    _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"trusted ingress surface {name} scopes must be a list")
                surfaces[name] = TrustedIngressSurface(raw_surface.get("path"), raw_surface.get("principal"), raw_surface.get("audience"), tuple(raw_scopes))
            ingress = TrustedIngressConfig(raw_ingress.get("mode"), raw_ingress.get("bind"), raw_ingress.get("port"), raw_ingress.get("upstream"), raw_ingress.get("endpoint"), surfaces)
        unknown = set(value) - {"enabled", "environment", "transports", "principals", "application", "adapter", "dev_profile", "onboarding", "handoff", "ingress"}
        if unknown:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"unknown trusted_access fields: {sorted(unknown)}")
        return cls(enabled, environment, tuple(raw_transports), principals, application, adapter, dev_profile, onboarding, handoff, ingress)

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
    handoff: str | None = None


@dataclass(frozen=True)
class TransportEvidence:
    transport: str
    peer_address: str
    peer_identity: str | None = None


@dataclass(frozen=True)
class TailscalePeerIdentity:
    """Normalized, provider-specific identity returned by Tailscale WhoIs.

    Raw LocalAPI JSON is intentionally not part of the public SDK contract.
    ``stable_id`` is the preferred node identity; ``node_id`` is retained for
    diagnostics and qualification output. User and capability fields are
    provider metadata and are never copied into the generic ATIP subject.
    """

    node_id: str
    stable_id: str
    node_name: str
    user_id: str | None
    login_name: str | None
    tags: tuple[str, ...]
    capabilities: tuple[str, ...]
    resolver: str = TAILSCALE_LOCALAPI_RESOLVER

    @property
    def node_identity(self) -> str:
        return f"node:{self.stable_id}"


@dataclass(frozen=True)
class TailscaleTransportEvidence(TransportEvidence):
    """TransportEvidence with Tailscale-only peer metadata."""

    tailscale_peer: TailscalePeerIdentity | None = None


@dataclass(frozen=True)
class TailscalePeerPolicy:
    """Optional provider constraints evaluated after LocalAPI WhoIs."""

    allowed_node_ids: frozenset[str] = frozenset()
    allowed_user_ids: frozenset[str] = frozenset()
    allowed_login_names: frozenset[str] = frozenset()
    required_tags: frozenset[str] = frozenset()
    required_capabilities: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        for field_name, values in (
            ("allowed_node_ids", self.allowed_node_ids),
            ("allowed_user_ids", self.allowed_user_ids),
            ("allowed_login_names", self.allowed_login_names),
            ("required_tags", self.required_tags),
            ("required_capabilities", self.required_capabilities),
        ):
            if not isinstance(values, frozenset) or any(not isinstance(value, str) or not value.strip() for value in values):
                _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", f"Tailscale {field_name} must contain non-empty strings")


class TrustedTransportVerifier(Protocol):
    transport: str

    def verify(self, observation: TransportObservation) -> TransportEvidence:
        ...


# Compatibility alias retained for integrations built against the first
# Trusted Development Access release.
TransportVerifier = TrustedTransportVerifier


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


def _tailscale_address_in_networks(peer_address: str, networks: tuple[ipaddress._BaseNetwork, ...]) -> None:
    try:
        address = ipaddress.ip_address(peer_address)
    except ValueError as exc:
        _fail("UNTRUSTED_TRANSPORT", "peer address is invalid")
        raise AssertionError from exc
    if not any(address in network for network in networks):
        _fail("UNTRUSTED_TRANSPORT", "peer is outside configured Tailscale networks")


def _tailscale_address_matches(peer_address: str, node_address: str) -> bool:
    try:
        peer = ipaddress.ip_address(peer_address)
        prefix = ipaddress.ip_interface(node_address).network
    except ValueError:
        return False
    return peer in prefix


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail("UNTRUSTED_TRANSPORT", f"Tailscale LocalAPI response is missing {field}")
    return value.strip()


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def _string_list(value: Any, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        _fail("UNTRUSTED_TRANSPORT", f"Tailscale LocalAPI response field {field} is malformed")
    return tuple(sorted(set(item.strip() for item in value)))


def _normalize_tailscale_whois(payload: Any, peer_address: str) -> TailscalePeerIdentity:
    if not isinstance(payload, Mapping):
        _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI response is not an object")
    node = payload.get("Node")
    user = payload.get("UserProfile")
    if not isinstance(node, Mapping):
        _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI response has no Node object")
    addresses = node.get("Addresses")
    if not isinstance(addresses, list) or not addresses or any(not isinstance(item, str) for item in addresses):
        _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI response has malformed node addresses")
    if not any(_tailscale_address_matches(peer_address, item) for item in addresses):
        _fail("UNTRUSTED_TRANSPORT", "Tailscale WhoIs identity does not contain the observed socket peer")

    raw_node_id = node.get("ID")
    if isinstance(raw_node_id, bool) or not isinstance(raw_node_id, (str, int)):
        _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI response has no valid node ID")
    node_id = str(raw_node_id).strip()
    if not node_id:
        _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI response has no valid node ID")
    stable_id = _required_text(node.get("StableID") or node_id, "Node.StableID")
    node_name = _required_text(node.get("Name") or node.get("ComputedName"), "Node.Name")

    raw_user_id = node.get("User")
    if isinstance(raw_user_id, bool) or (raw_user_id is not None and not isinstance(raw_user_id, (str, int))):
        _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI response has malformed node user ID")
    user_id = str(raw_user_id).strip() if raw_user_id is not None else None
    if user_id == "":
        user_id = None
    login_name = None
    if isinstance(user, Mapping):
        login_name = _optional_text(user.get("LoginName"))
        profile_id = user.get("ID")
        if profile_id is not None and (isinstance(profile_id, bool) or not isinstance(profile_id, (str, int))):
            _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI response has malformed user profile ID")
        if user_id is None and profile_id is not None:
            user_id = str(profile_id).strip() or None
    elif user is not None:
        _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI response has malformed UserProfile")

    tags = _string_list(node.get("Tags"), "Node.Tags")
    capabilities = set(_string_list(node.get("Capabilities"), "Node.Capabilities"))
    cap_map = node.get("CapMap")
    if cap_map is not None:
        if not isinstance(cap_map, Mapping) or any(not isinstance(key, str) or not key.strip() for key in cap_map):
            _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI response field Node.CapMap is malformed")
        capabilities.update(key.strip() for key in cap_map)
    return TailscalePeerIdentity(
        node_id=node_id,
        stable_id=stable_id,
        node_name=node_name,
        user_id=user_id,
        login_name=login_name,
        tags=tags,
        capabilities=tuple(sorted(capabilities)),
    )


class TailscaleLocalAPIClient:
    """Small read-only client for the server's local tailscaled Unix socket."""

    def __init__(self, socket_path: str | Path = TAILSCALE_LOCALAPI_SOCKET, *, timeout: float = 2.0, max_response_bytes: int = 1_048_576) -> None:
        if timeout <= 0:
            raise ValueError("Tailscale LocalAPI timeout must be positive")
        if max_response_bytes <= 0:
            raise ValueError("Tailscale LocalAPI response limit must be positive")
        self.socket_path = str(socket_path)
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes

    def whois(self, peer_address: str) -> TailscalePeerIdentity:
        try:
            ipaddress.ip_address(peer_address)
        except ValueError as exc:
            _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI WhoIs requires an IP socket peer")
            raise AssertionError from exc
        path = "/localapi/v0/whois?" + urlencode({"addr": peer_address})
        sock: socket.socket | None = None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
            request = (
                f"GET {path} HTTP/1.1\r\n"
                "Host: local-tailscaled.sock\r\n"
                "Connection: close\r\n"
                "Accept: application/json\r\n\r\n"
            ).encode("ascii")
            sock.sendall(request)
            response = http.client.HTTPResponse(sock)
            response.begin()
            body = response.read(self.max_response_bytes + 1)
            status = response.status
            response.close()
        except (OSError, http.client.HTTPException) as exc:
            _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI is unavailable")
            raise AssertionError from exc
        finally:
            if sock is not None:
                sock.close()
        if len(body) > self.max_response_bytes:
            _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI response is too large")
        if status == 404:
            _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI has no identity for the observed peer")
        if status != 200:
            _fail("UNTRUSTED_TRANSPORT", f"Tailscale LocalAPI WhoIs returned HTTP {status}")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            _fail("UNTRUSTED_TRANSPORT", "Tailscale LocalAPI response is not valid JSON")
            raise AssertionError from exc
        return _normalize_tailscale_whois(payload, peer_address)


def _check_tailscale_peer_policy(peer: TailscalePeerIdentity, policy: TailscalePeerPolicy) -> None:
    if policy.allowed_node_ids and not ({peer.node_id, peer.stable_id} & policy.allowed_node_ids):
        _fail("UNTRUSTED_TRANSPORT", "Tailscale node is not allowed by transport policy")
    if policy.allowed_user_ids and (peer.user_id is None or peer.user_id not in policy.allowed_user_ids):
        _fail("UNTRUSTED_TRANSPORT", "Tailscale user is not allowed by transport policy")
    if policy.allowed_login_names and (peer.login_name is None or peer.login_name not in policy.allowed_login_names):
        _fail("UNTRUSTED_TRANSPORT", "Tailscale login is not allowed by transport policy")
    if not policy.required_tags.issubset(peer.tags):
        _fail("UNTRUSTED_TRANSPORT", "Tailscale node is missing a required tag")
    if not policy.required_capabilities.issubset(peer.capabilities):
        _fail("UNTRUSTED_TRANSPORT", "Tailscale node is missing a required capability")


class TailscaleLocalAPITransportVerifier:
    """Verifies a Tailscale socket peer with LocalAPI WhoIs."""

    transport = "tailscale"

    def __init__(
        self,
        client: TailscaleLocalAPIClient,
        *,
        networks: tuple[str, ...] = ("100.64.0.0/10", "fd7a:115c:a1e0::/48"),
        peer_policy: TailscalePeerPolicy | None = None,
    ) -> None:
        self.client = client
        self.networks = tuple(ipaddress.ip_network(network) for network in networks)
        self.peer_policy = peer_policy or TailscalePeerPolicy()

    def verify(self, observation: TransportObservation) -> TailscaleTransportEvidence:
        if observation.transport != self.transport or observation.forwarded_headers_present:
            _fail("UNTRUSTED_TRANSPORT", "Tailscale proof cannot use forwarding headers")
        if not observation.peer_address:
            _fail("UNTRUSTED_TRANSPORT", "server did not provide a peer address")
        _tailscale_address_in_networks(observation.peer_address, self.networks)
        try:
            peer = self.client.whois(observation.peer_address)
        except TrustedAccessError:
            raise
        except Exception as exc:
            _fail("UNTRUSTED_TRANSPORT", "Tailscale peer identity could not be verified")
            raise AssertionError from exc
        _check_tailscale_peer_policy(peer, self.peer_policy)
        return TailscaleTransportEvidence(self.transport, observation.peer_address, peer.node_identity, peer)


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

    def to_principal(self) -> "AgentctlPrincipal":
        return AgentctlPrincipal(
            issuer=self.issuer,
            subject=self.subject,
            principal_type=self.principal_type,
            scopes=self.scopes,
            audience=self.audience,
            environment=self.environment,
            auth_method="trusted_dev",
            transport=self.transport,
            assertion_id=self.jti,
        )


@dataclass(frozen=True)
class AgentctlPrincipal:
    """Stable application-facing identity returned by the verifier SDK."""

    issuer: str
    subject: str
    principal_type: str
    scopes: tuple[str, ...]
    audience: str
    environment: str
    auth_method: str
    transport: str
    assertion_id: str

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    def require_scope(self, scope: str) -> None:
        if scope not in self.scopes:
            _fail("SCOPE_DENIED", "application scope is not granted to the trusted principal")

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "principal_type": self.principal_type,
            "scopes": list(self.scopes),
            "audience": self.audience,
            "environment": self.environment,
            "auth_method": self.auth_method,
            "transport": self.transport,
            "assertion_id": self.assertion_id,
        }


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
            try:
                evidence = verifier.verify(observation)
            except TrustedAccessError:
                raise
            except Exception as exc:
                _fail("UNTRUSTED_TRANSPORT", "trusted transport verification failed")
                raise AssertionError from exc
            policy = self.config.policy_for(requested_principal)
            requested_scopes = tuple(scopes)
            if not requested_scopes or len(set(requested_scopes)) != len(requested_scopes):
                _fail("SCOPE_DENIED", "requested scopes must be non-empty and unique")
            for scope in requested_scopes:
                _identifier(scope, "requested scope")
            if any(scope not in policy.scopes for scope in requested_scopes):
                _fail("SCOPE_DENIED", "requested scope is not allowed for the trusted principal")
            _identifier(audience, "audience")
            configured_audience = self.config.application.audience if self.config.application else None
            if configured_audience is not None and audience != configured_audience:
                _fail("WRONG_AUDIENCE", "requested audience does not match trusted access application policy")
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
        _identifier(expected_audience, "expected audience")
        configured_audience = config.application.audience if config.application else None
        if configured_audience is not None and expected_audience != configured_audience:
            _fail("INVALID_TRUSTED_ACCESS_CONFIGURATION", "expected audience does not match trusted access application policy")
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
            if observation.handoff is not None:
                if observation.handoff != "trusted-ingress" or self.config.handoff is None or not self.config.handoff.enabled:
                    _fail("UNTRUSTED_TRANSPORT", "trusted ingress handoff is not enabled")
                transport = TransportEvidence(
                    observation.transport,
                    observation.peer_address or "trusted-ingress",
                    payload.get("peer_identity"),
                )
            else:
                verifier = self.transport_verifiers.get(observation.transport)
                if verifier is None or verifier.transport != observation.transport:
                    _fail("TRANSPORT_VERIFIER_MISSING", "no server-side verifier is configured for transport")
                try:
                    transport = verifier.verify(observation)
                except TrustedAccessError:
                    raise
                except Exception as exc:
                    _fail("UNTRUSTED_TRANSPORT", "trusted transport verification failed")
                    raise AssertionError from exc
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

    def verify_principal(self, assertion: str, *, observation: TransportObservation, now: int, action: str = "trusted_dev.verify") -> AgentctlPrincipal:
        """Verify once and return the application-facing principal contract."""

        return self.verify(assertion, observation=observation, now=now, action=action).to_principal()

    def verify_handoff(self, assertion: str, *, now: int, action: str = "trusted_dev.handoff") -> TrustedIdentityEvidence:
        payload, _signature, _segment = parse_trusted_identity_assertion(assertion)
        return self.verify(
            assertion,
            observation=TransportObservation(payload["transport"], None, handoff="trusted-ingress"),
            now=now,
            action=action,
        )


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
