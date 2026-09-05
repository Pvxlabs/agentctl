from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentctl.application import (
    ApplicationAdapterError,
    DeclarativeMappingAdapter,
    TrustedAccessSDK,
    extract_trusted_assertion,
)
from agentctl.identity import LocalIdentity
from agentctl.integrations.fastapi import create_fastapi_dependency, get_agentctl_principal
from agentctl.models import KeyRecord, PrincipalRecord
from agentctl.registry import Registry, encode_public_key
from agentctl.replay import MemoryReplayStore
from agentctl.trusted import (
    LocalhostTransportVerifier,
    TransportObservation,
    TrustedAccessAuthority,
    TrustedAccessConfig,
    TrustedAccessError,
    TrustedIdentityVerifier,
)


def setup() -> tuple[TrustedAccessSDK[object], TrustedAccessAuthority, TransportObservation]:
    key = Ed25519PrivateKey.generate()
    identity = LocalIdentity("dev-authority", "DEV Authority", "dev", "dev-key", "Ed25519", key)
    registry = Registry()
    registry.add_principal(PrincipalRecord("dev-authority", "DEV Authority", "dev"))
    registry.add_key(KeyRecord("dev-key", "dev-authority", "Ed25519", encode_public_key(identity.public_key_bytes)))
    config = TrustedAccessConfig.from_mapping({
        "enabled": True,
        "environment": "dev",
        "transports": ["localhost"],
        "application": {"identity": "example-app", "audience": "example-dev"},
        "adapter": {"type": "declarative_mapping", "mappings": {"dev-user": "app-user"}},
        "principals": {"user": {"subject": "dev-user", "type": "human", "scopes": ["app:read"]}},
    })
    transport = LocalhostTransportVerifier()
    authority = TrustedAccessAuthority(identity, registry, config, transport_verifiers={"localhost": transport})
    verifier = TrustedIdentityVerifier(registry, config, MemoryReplayStore(), expected_audience="example-dev", transport_verifiers={"localhost": transport})
    sdk = TrustedAccessSDK(verifier, DeclarativeMappingAdapter({"dev-user": "app-user"}))
    return sdk, authority, TransportObservation("localhost", "127.0.0.1")


def test_sdk_establishes_application_principal_and_keeps_scope_contract() -> None:
    sdk, authority, observation = setup()
    assertion = authority.issue(requested_principal="user", audience="example-dev", scopes=["app:read"], observation=observation, now=1_700_000_000)
    result = sdk.authenticate_with_context(assertion, observation=observation, now=1_700_000_001)
    assert result.agentctl_principal.subject == "dev-user"
    assert result.agentctl_principal.auth_method == "trusted_dev"
    assert result.application_principal.application_identity == "app-user"
    assert result.application_principal.has_scope("app:read")
    with pytest.raises(TrustedAccessError, match="not granted"):
        result.agentctl_principal.require_scope("app:admin")


def test_declarative_mapping_fails_closed_for_missing_subject() -> None:
    sdk, authority, observation = setup()
    assertion = authority.issue(requested_principal="user", audience="example-dev", scopes=["app:read"], observation=observation, now=1_700_000_000)
    missing = TrustedAccessSDK(sdk.verifier, DeclarativeMappingAdapter({"other": "app-user"}))
    with pytest.raises(ApplicationAdapterError) as raised:
        missing.authenticate(assertion, observation=observation, now=1_700_000_001)
    assert raised.value.code == "APPLICATION_IDENTITY_MAPPING_MISSING"


def test_custom_adapter_receives_verified_principal() -> None:
    sdk, authority, observation = setup()
    seen: list[str] = []

    class Adapter:
        def establish(self, principal):
            seen.append(principal.subject)
            return {"login": "normal-session", "scopes": principal.scopes}

    custom = TrustedAccessSDK(sdk.verifier, Adapter())
    assertion = authority.issue(requested_principal="user", audience="example-dev", scopes=["app:read"], observation=observation, now=1_700_000_000)
    assert custom.authenticate(assertion, observation=observation, now=1_700_000_001) == {"login": "normal-session", "scopes": ("app:read",)}
    assert seen == ["dev-user"]


def test_fastapi_dependency_sets_both_principals_without_framework_import_on_success() -> None:
    sdk, authority, observation = setup()
    assertion = authority.issue(requested_principal="user", audience="example-dev", scopes=["app:read"], observation=observation, now=1_700_000_000)

    @dataclass
    class Client:
        host: str

    class State:
        pass

    class Request:
        headers = {"authorization": f"Agentctl-Trusted {assertion}"}
        client = Client("127.0.0.1")
        state = State()

    dependency = create_fastapi_dependency(sdk, now=lambda: 1_700_000_001)
    application_principal = asyncio.run(dependency(Request()))
    assert application_principal.application_identity == "app-user"
    assert get_agentctl_principal(Request()).subject == "dev-user"


def test_fastapi_dependency_is_classified_as_request_by_fastapi() -> None:
    pytest.importorskip("fastapi")
    from fastapi.dependencies.utils import get_dependant

    sdk, _authority, _observation = setup()
    dependency = create_fastapi_dependency(sdk)
    dependant = get_dependant(path="/me", call=dependency)

    assert dependant.request_param_name == "request"
    assert dependant.query_params == []


def test_fastapi_dependency_supports_a_custom_authorization_header() -> None:
    sdk, authority, observation = setup()
    assertion = authority.issue(requested_principal="user", audience="example-dev", scopes=["app:read"], observation=observation, now=1_700_000_000)

    @dataclass
    class Client:
        host: str

    class State:
        pass

    class Request:
        headers = {"x-agentctl-trusted": f"Agentctl-Trusted {assertion}"}
        client = Client("127.0.0.1")
        state = State()

    dependency = create_fastapi_dependency(sdk, authorization_header="X-Agentctl-Trusted", now=lambda: 1_700_000_001)
    result = asyncio.run(dependency(Request()))
    assert result.application_identity == "app-user"


def test_assertion_extractor_rejects_wrong_scheme_and_whitespace_token() -> None:
    with pytest.raises(TrustedAccessError):
        extract_trusted_assertion("Agentctl abc")
    with pytest.raises(TrustedAccessError):
        extract_trusted_assertion("Agentctl-Trusted abc def")
    with pytest.raises(TrustedAccessError):
        extract_trusted_assertion("Agentctl-Trusted")
