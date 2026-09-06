from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentctl.identity import LocalIdentity
from agentctl.audit import JsonlAuditSink, verify_audit_file
from agentctl.models import KeyRecord, PrincipalRecord
from agentctl.registry import Registry, encode_public_key
from agentctl.replay import MemoryReplayStore
from agentctl.trusted import (
    LocalhostTransportVerifier,
    TailscaleLocalAPIClient,
    TailscaleLocalAPITransportVerifier,
    TailscalePeerPolicy,
    TailscaleTransportVerifier,
    TransportObservation,
    TrustedAccessAuthority,
    TrustedAccessConfig,
    TrustedAccessError,
    TrustedIdentityVerifier,
    establish_application_principal,
)


def _localapi_server(tmp_path: Path, payload: object, *, status: int = 200) -> tuple[Path, threading.Thread]:
    socket_path = tmp_path / "tailscaled.sock"
    ready = threading.Event()

    def serve() -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        server.listen(1)
        ready.set()
        connection, _ = server.accept()
        with connection:
            connection.recv(4096)
            body = json.dumps(payload).encode("utf-8")
            connection.sendall(
                f"HTTP/1.1 {status} test\r\nContent-Length: {len(body)}\r\n"
                "Content-Type: application/json\r\nConnection: close\r\n\r\n".encode("ascii") + body
            )
        server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(1)
    return socket_path, thread


def _whois_payload(peer: str = "100.90.1.2") -> dict[str, object]:
    return {
        "Node": {
            "ID": 123,
            "StableID": "node-stable-123",
            "Name": "dev-host.example.ts.net.",
            "User": 456,
            "Addresses": [f"{peer}/32"],
            "Tags": ["tag:dev"],
            "Capabilities": ["cap:test"],
            "CapMap": {"cap:read": []},
        },
        "UserProfile": {"ID": 456, "LoginName": "developer@example.test"},
    }


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


def test_handoff_requires_explicit_config_and_preserves_signed_peer_identity() -> None:
    identity, registry, _ = setup()
    transport = TailscaleTransportVerifier(lambda _address: "node:dev-host")
    config = TrustedAccessConfig.from_mapping({
        "enabled": True,
        "environment": "dev",
        "transports": ["tailscale"],
        "handoff": {"enabled": True},
        "principals": {"agent": {"subject": "dev-agent", "type": "agent", "scopes": ["app:read"]}},
    })
    authority = TrustedAccessAuthority(identity, registry, config, transport_verifiers={"tailscale": transport})
    verifier = TrustedIdentityVerifier(registry, config, MemoryReplayStore(), expected_audience="orion-dev")
    assertion = authority.issue(
        requested_principal="agent",
        audience="orion-dev",
        scopes=["app:read"],
        observation=TransportObservation("tailscale", "100.90.1.2"),
        now=1_700_000_000,
    )
    evidence = verifier.verify_handoff(assertion, now=1_700_000_001)
    assert evidence.subject == "dev-agent"
    with pytest.raises(TrustedAccessError) as raised:
        verifier.verify_handoff(assertion, now=1_700_000_001)
    assert raised.value.code == "REPLAYED_JTI"

    disabled_config = TrustedAccessConfig.from_mapping({
        "enabled": True,
        "environment": "dev",
        "transports": ["localhost"],
        "principals": {"agent": {"subject": "dev-agent", "type": "agent", "scopes": ["app:read"]}},
    })
    disabled_verifier = TrustedIdentityVerifier(
        registry,
        disabled_config,
        MemoryReplayStore(),
        expected_audience="orion-dev",
        transport_verifiers={"localhost": LocalhostTransportVerifier()},
    )
    with pytest.raises(TrustedAccessError) as raised:
        disabled_verifier.verify_handoff(assertion, now=1_700_000_001)
    assert raised.value.code == "UNTRUSTED_TRANSPORT"


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
    with pytest.raises(TrustedAccessError) as raised:
        TrustedAccessConfig.from_mapping({"enabled": False, "transports": ["proxy"]})
    assert raised.value.code == "INVALID_TRUSTED_ACCESS_CONFIGURATION"
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


def test_application_audience_is_enforced_at_issue_and_verifier_setup() -> None:
    identity, registry, _ = setup()
    config = TrustedAccessConfig.from_mapping({
        "enabled": True,
        "environment": "dev",
        "transports": ["localhost"],
        "application": {"identity": "example", "audience": "example-dev"},
        "principals": {"agent": {"subject": "dev-agent", "type": "agent", "scopes": ["app:test"]}},
    })
    transport = LocalhostTransportVerifier()
    authority = TrustedAccessAuthority(identity, registry, config, transport_verifiers={"localhost": transport})
    with pytest.raises(TrustedAccessError) as raised:
        authority.issue(
            requested_principal="agent",
            audience="other-dev",
            scopes=["app:test"],
            observation=TransportObservation("localhost", "127.0.0.1"),
            now=1_700_000_000,
        )
    assert raised.value.code == "WRONG_AUDIENCE"
    with pytest.raises(TrustedAccessError) as raised:
        TrustedIdentityVerifier(
            registry,
            config,
            MemoryReplayStore(),
            expected_audience="other-dev",
            transport_verifiers={"localhost": transport},
        )
    assert raised.value.code == "INVALID_TRUSTED_ACCESS_CONFIGURATION"


def test_configuration_rejects_ambiguous_type_and_name_metadata() -> None:
    with pytest.raises(TrustedAccessError) as raised:
        TrustedAccessConfig.from_mapping({
            "enabled": True,
            "environment": "dev",
            "transports": ["localhost"],
            "principals": {"agent": {"name": "worker", "subject": "dev-agent", "type": "agent", "principal_type": "human", "scopes": ["app:test"]}},
        })
    assert raised.value.code == "INVALID_TRUSTED_ACCESS_CONFIGURATION"
    with pytest.raises(TrustedAccessError) as raised:
        TrustedAccessConfig.from_mapping({
            "enabled": True,
            "environment": "dev",
            "transports": ["localhost"],
            "principals": {"agent": {"name": "worker", "subject": "dev-agent", "scopes": ["app:test"]}},
        })
    assert raised.value.code == "INVALID_TRUSTED_ACCESS_CONFIGURATION"


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


def test_custom_transport_verifier_errors_fail_closed() -> None:
    identity, registry, config = setup()

    class BrokenVerifier:
        transport = "localhost"

        def verify(self, _observation: TransportObservation) -> object:
            raise RuntimeError("resolver unavailable")

    authority = TrustedAccessAuthority(identity, registry, config, transport_verifiers={"localhost": BrokenVerifier()})
    with pytest.raises(TrustedAccessError) as raised:
        authority.issue(
            requested_principal="agent",
            audience="orion-dev",
            scopes=["app:test"],
            observation=TransportObservation("localhost", "127.0.0.1"),
            now=1_700_000_000,
        )
    assert raised.value.code == "UNTRUSTED_TRANSPORT"

    localhost = LocalhostTransportVerifier()
    valid_authority = TrustedAccessAuthority(identity, registry, config, transport_verifiers={"localhost": localhost})
    assertion = valid_authority.issue(
        requested_principal="agent",
        audience="orion-dev",
        scopes=["app:test"],
        observation=TransportObservation("localhost", "127.0.0.1"),
        now=1_700_000_000,
    )
    verifier = TrustedIdentityVerifier(
        registry,
        config,
        MemoryReplayStore(),
        expected_audience="orion-dev",
        transport_verifiers={"localhost": BrokenVerifier()},
    )
    with pytest.raises(TrustedAccessError) as raised:
        verifier.verify(assertion, observation=TransportObservation("localhost", "127.0.0.1"), now=1_700_000_001)
    assert raised.value.code == "UNTRUSTED_TRANSPORT"


def test_tailscale_accepts_configured_ipv4_and_ipv6_ranges_only() -> None:
    verifier = TailscaleTransportVerifier(lambda address: f"node:{address}")
    assert verifier.verify(TransportObservation("tailscale", "100.90.1.2")).peer_identity == "node:100.90.1.2"
    assert verifier.verify(TransportObservation("tailscale", "fd7a:115c:a1e0::42")).peer_identity == "node:fd7a:115c:a1e0::42"
    with pytest.raises(TrustedAccessError):
        verifier.verify(TransportObservation("tailscale", "100.63.1.2"))
    with pytest.raises(TrustedAccessError):
        verifier.verify(TransportObservation("tailscale", "fd7a:115c:a1e1::42"))


def test_tailscale_localapi_provider_uses_socket_peer_and_normalizes_identity(tmp_path: Path) -> None:
    socket_path, thread = _localapi_server(tmp_path, _whois_payload())
    client = TailscaleLocalAPIClient(socket_path)
    evidence = TailscaleLocalAPITransportVerifier(
        client,
        peer_policy=TailscalePeerPolicy(
            allowed_node_ids=frozenset({"node-stable-123"}),
            allowed_user_ids=frozenset({"456"}),
            allowed_login_names=frozenset({"developer@example.test"}),
            required_tags=frozenset({"tag:dev"}),
            required_capabilities=frozenset({"cap:test", "cap:read"}),
        ),
    ).verify(TransportObservation("tailscale", "100.90.1.2"))
    thread.join(1)
    assert evidence.peer_identity == "node:node-stable-123"
    assert evidence.tailscale_peer is not None
    assert evidence.tailscale_peer.node_id == "123"
    assert evidence.tailscale_peer.login_name == "developer@example.test"
    assert evidence.tailscale_peer.tags == ("tag:dev",)
    assert evidence.tailscale_peer.capabilities == ("cap:read", "cap:test")


@pytest.mark.parametrize(
    "payload,status,peer,expected",
    [
        ({"Node": {"ID": 123, "StableID": "node-stable-123", "Name": "host", "Addresses": ["100.90.1.3/32"]}}, 200, "100.90.1.2", "UNTRUSTED_TRANSPORT"),
        ({"Node": {"ID": 123, "StableID": "node-stable-123", "Name": "host", "Addresses": ["100.90.1.2/32"]}}, 404, "100.90.1.2", "UNTRUSTED_TRANSPORT"),
        ({"malformed": True}, 200, "100.90.1.2", "UNTRUSTED_TRANSPORT"),
    ],
)
def test_tailscale_localapi_provider_fails_closed_for_unknown_or_malformed_peer(
    tmp_path: Path, payload: object, status: int, peer: str, expected: str
) -> None:
    socket_path, thread = _localapi_server(tmp_path, payload, status=status)
    with pytest.raises(TrustedAccessError) as raised:
        TailscaleLocalAPITransportVerifier(TailscaleLocalAPIClient(socket_path)).verify(
            TransportObservation("tailscale", peer)
        )
    thread.join(1)
    assert raised.value.code == expected


def test_tailscale_localapi_provider_rejects_forwarded_headers_and_unavailable_socket(tmp_path: Path) -> None:
    client = TailscaleLocalAPIClient(tmp_path / "missing.sock")
    verifier = TailscaleLocalAPITransportVerifier(client)
    with pytest.raises(TrustedAccessError) as raised:
        verifier.verify(TransportObservation("tailscale", "100.90.1.2", forwarded_headers_present=True))
    assert raised.value.code == "UNTRUSTED_TRANSPORT"
    with pytest.raises(TrustedAccessError) as raised:
        verifier.verify(TransportObservation("tailscale", "100.90.1.2"))
    assert raised.value.code == "UNTRUSTED_TRANSPORT"


def test_tailscale_localapi_provider_never_authorizes_ip_only(tmp_path: Path) -> None:
    socket_path, thread = _localapi_server(tmp_path, _whois_payload())
    client = TailscaleLocalAPIClient(socket_path)
    with pytest.raises(TrustedAccessError):
        TailscaleLocalAPITransportVerifier(client).verify(TransportObservation("tailscale", "100.90.1.3"))
    thread.join(1)
