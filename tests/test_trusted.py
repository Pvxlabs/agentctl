from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentctl.identity import LocalIdentity
from agentctl.audit import JsonlAuditSink, verify_audit_file
from agentctl.models import KeyRecord, PrincipalRecord
from agentctl.registry import Registry, encode_public_key
from agentctl.replay import MemoryReplayStore
from agentctl.trusted import (
    LocalhostTransportVerifier,
    TailscaleTransportVerifier,
    TransportObservation,
    TrustedAccessAuthority,
    TrustedAccessConfig,
    TrustedAccessError,
    TrustedIdentityVerifier,
    establish_application_principal,
)


def setup() -> tuple[LocalIdentity, Registry, TrustedAccessConfig]:
    key = Ed25519PrivateKey.generate()
    identity = LocalIdentity("dev-authority", "DEV Authority", "dev", "dev-authority-key", "Ed25519", key)
    registry = Registry()
    registry.add_principal(PrincipalRecord("dev-authority", "DEV Authority", "dev"))
    registry.add_key(KeyRecord("dev-authority-key", "dev-authority", "Ed25519", encode_public_key(identity.public_key_bytes)))
    config = TrustedAccessConfig.from_mapping({
        "enabled": True,
        "environment": "dev",
        "transports": ["localhost", "tailscale"],
        "principals": {
            "user": {"subject": "dev-user", "type": "human", "scopes": ["app:read"]},
            "admin": {"subject": "dev-admin", "type": "human", "scopes": ["app:admin", "app:read"]},
            "agent": {"subject": "dev-agent", "type": "agent", "scopes": ["app:test", "app:read"]},
        },
    })
    return identity, registry, config


def authority_and_verifier():
    identity, registry, config = setup()
    localhost = LocalhostTransportVerifier()
    authority = TrustedAccessAuthority(identity, registry, config, transport_verifiers={"localhost": localhost})
    verifier = TrustedIdentityVerifier(registry, config, MemoryReplayStore(), expected_audience="orion-dev", transport_verifiers={"localhost": localhost})
    return authority, verifier


def test_valid_human_identity_assertion_establishes_application_principal() -> None:
    authority, verifier = authority_and_verifier()
    observation = TransportObservation("localhost", "127.0.0.1")
    assertion = authority.issue(requested_principal="user", audience="orion-dev", scopes=["app:read"], observation=observation, now=1_700_000_000)
    app_principal = establish_application_principal(
        verifier, assertion, observation=observation, now=1_700_000_001,
        resolver=lambda evidence: {"login": "user@test.local", "scope": evidence.scopes[0]},
    )
    assert app_principal == {"login": "user@test.local", "scope": "app:read"}


def test_agent_identity_can_request_only_explicit_scopes_and_is_replay_protected() -> None:
    authority, verifier = authority_and_verifier()
    observation = TransportObservation("localhost", "::1")
    assertion = authority.issue(requested_principal="agent", audience="orion-dev", scopes=["app:test", "app:read"], observation=observation, now=1_700_000_000)
    evidence = verifier.verify(assertion, observation=observation, now=1_700_000_001)
    assert evidence.subject == "dev-agent"
    assert evidence.scopes == ("app:read", "app:test")
    with pytest.raises(TrustedAccessError, match="already been consumed") as raised:
        verifier.verify(assertion, observation=observation, now=1_700_000_001)
    assert raised.value.code == "REPLAYED_JTI"

    with pytest.raises(TrustedAccessError) as raised:
        authority.issue(requested_principal="agent", audience="orion-dev", scopes=["app:admin"], observation=observation, now=1_700_000_000)
    assert raised.value.code == "SCOPE_DENIED"


@pytest.mark.parametrize(
    "value",
    [
        {"enabled": True, "environment": "production", "transports": ["localhost"], "principals": {"agent": {"subject": "dev-agent", "scopes": ["app:test"]}}},
        {"enabled": True, "environment": "dev", "transports": ["localhost"], "principals": {}},
        {"enabled": True, "environment": "dev", "transports": ["proxy"], "principals": {"agent": {"subject": "dev-agent", "scopes": ["app:test"]}}},
    ],
)
def test_configuration_fails_closed(value: dict[str, object]) -> None:
    with pytest.raises(TrustedAccessError):
        TrustedAccessConfig.from_mapping(value)


def test_trusted_access_disabled_and_missing_transport_verifier_fail_closed() -> None:
    identity, registry, _config = setup()
    with pytest.raises(TrustedAccessError) as raised:
        TrustedAccessAuthority(identity, registry, TrustedAccessConfig())
    assert raised.value.code == "TRUSTED_ACCESS_DISABLED"
    config = TrustedAccessConfig.from_mapping({"enabled": True, "environment": "dev", "transports": ["localhost"], "principals": {"agent": {"subject": "dev-agent", "scopes": ["app:test"]}}})
    authority = TrustedAccessAuthority(identity, registry, config)
    with pytest.raises(TrustedAccessError) as raised:
        authority.issue(requested_principal="agent", audience="orion-dev", scopes=["app:test"], observation=TransportObservation("localhost", "127.0.0.1"), now=1_700_000_000)
    assert raised.value.code == "TRANSPORT_VERIFIER_MISSING"


def test_localhost_does_not_trust_tailscale_ip_or_forwarded_headers() -> None:
    verifier = LocalhostTransportVerifier()
    with pytest.raises(TrustedAccessError) as raised:
        verifier.verify(TransportObservation("localhost", "100.90.1.2"))
    assert raised.value.code == "UNTRUSTED_TRANSPORT"
    with pytest.raises(TrustedAccessError):
        verifier.verify(TransportObservation("localhost", "127.0.0.1", forwarded_headers_present=True))


def test_tailscale_requires_server_side_peer_identity_proof() -> None:
    verifier = TailscaleTransportVerifier(lambda address: "node:alice" if address == "100.90.1.2" else None)
    evidence = verifier.verify(TransportObservation("tailscale", "100.90.1.2"))
    assert evidence.peer_identity == "node:alice"
    with pytest.raises(TrustedAccessError):
        TailscaleTransportVerifier(lambda _address: None).verify(TransportObservation("tailscale", "100.90.1.2"))
    with pytest.raises(TrustedAccessError):
        verifier.verify(TransportObservation("tailscale", "100.90.1.2", forwarded_headers_present=True))


def test_unknown_principal_expired_and_tampered_assertions_fail_closed() -> None:
    authority, verifier = authority_and_verifier()
    observation = TransportObservation("localhost", "127.0.0.1")
    with pytest.raises(TrustedAccessError) as raised:
        authority.issue(requested_principal="unknown", audience="orion-dev", scopes=["app:read"], observation=observation, now=1_700_000_000)
    assert raised.value.code == "UNKNOWN_TRUSTED_PRINCIPAL"
    assertion = authority.issue(requested_principal="user", audience="orion-dev", scopes=["app:read"], observation=observation, now=1_700_000_000, ttl_seconds=1)
    with pytest.raises(TrustedAccessError) as raised:
        verifier.verify(assertion, observation=observation, now=1_700_000_001)
    assert raised.value.code == "EXPIRED"
    fresh = authority.issue(requested_principal="user", audience="orion-dev", scopes=["app:read"], observation=observation, now=1_700_000_000, ttl_seconds=60)
    parts = fresh.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    with pytest.raises(TrustedAccessError) as raised:
        verifier.verify(".".join(parts), observation=observation, now=1_700_000_000)
    assert raised.value.code == "BAD_SIGNATURE"


def test_production_cannot_activate_trusted_dev_semantics() -> None:
    with pytest.raises(TrustedAccessError) as raised:
        TrustedAccessConfig.from_mapping({"enabled": True, "environment": "production", "transports": ["localhost"], "principals": {"agent": {"subject": "dev-agent", "scopes": ["app:test"]}}})
    assert raised.value.code == "TRUSTED_ACCESS_NOT_DEV"


def test_trusted_identity_decisions_are_hash_chained_in_audit(tmp_path) -> None:
    identity, registry, config = setup()
    audit_path = tmp_path / "trusted-audit.jsonl"
    sink = JsonlAuditSink(audit_path)
    transport = LocalhostTransportVerifier()
    authority = TrustedAccessAuthority(identity, registry, config, audit_sink=sink, transport_verifiers={"localhost": transport})
    verifier = TrustedIdentityVerifier(registry, config, MemoryReplayStore(), expected_audience="orion-dev", audit_sink=sink, transport_verifiers={"localhost": transport})
    observation = TransportObservation("localhost", "127.0.0.1")
    assertion = authority.issue(requested_principal="user", audience="orion-dev", scopes=["app:read"], observation=observation, now=1_700_000_000)
    verifier.verify(assertion, observation=observation, now=1_700_000_001)
    with pytest.raises(TrustedAccessError) as raised:
        verifier.verify(assertion, observation=observation, now=1_700_000_001)
    assert raised.value.code == "REPLAYED_JTI"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert '"result":"AUTHORIZED"' in lines[0]
    assert '"result":"AUTHORIZED"' in lines[1]
    assert '"result":"REJECTED"' in lines[2]
    assert verify_audit_file(audit_path) == (True, "audit chain valid")


def test_tailscale_resolver_errors_fail_closed() -> None:
    def resolver(_address: str) -> str | None:
        raise RuntimeError("resolver unavailable")

    with pytest.raises(TrustedAccessError) as raised:
        TailscaleTransportVerifier(resolver).verify(TransportObservation("tailscale", "100.90.1.2"))
    assert raised.value.code == "UNTRUSTED_TRANSPORT"
