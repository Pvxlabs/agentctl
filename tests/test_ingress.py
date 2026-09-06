from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import agentctl.ingress as ingress_module
from agentctl.identity import LocalIdentity
from agentctl.ingress import IngressResponse, TrustedIngress
from agentctl.manifest import ProjectManifest
from agentctl.models import KeyRecord, PrincipalRecord
from agentctl.registry import Registry, encode_public_key
from agentctl.trusted import TrustedAccessConfig, TrustedAccessError


class FakeRuntime:
    tailscale_socket = "/nonexistent/tailscaled.sock"

    def __init__(self, identity: LocalIdentity, registry: Registry) -> None:
        self.identity = identity
        self.registry = registry

    def load_identity_registry(self, _manifest: ProjectManifest):
        return self.identity, self.registry, self.registry.principals[self.identity.principal_id], self.registry.keys[self.identity.key_id]

    def audit_sink(self):
        return None


def _manifest(bind: str = "127.0.0.1") -> tuple[ProjectManifest, FakeRuntime]:
    key = Ed25519PrivateKey.generate()
    identity = LocalIdentity("dev-authority", "DEV Authority", "dev", "dev-key", "Ed25519", key)
    registry = Registry()
    registry.add_principal(PrincipalRecord("dev-authority", "DEV Authority", "dev"))
    registry.add_key(KeyRecord("dev-key", "dev-authority", "Ed25519", encode_public_key(identity.public_key_bytes)))
    config = TrustedAccessConfig.from_mapping({
        "enabled": True,
        "environment": "dev",
        "transports": ["localhost"],
        "handoff": {"enabled": True},
        "application": {"identity": "terminal", "audience": "terminal-dev"},
        "principals": {
            "user": {"subject": "dev-user", "type": "human", "scopes": ["app:read"]},
            "admin": {"subject": "dev-admin", "type": "human", "scopes": ["app:read", "app:admin"]},
        },
        "ingress": {
            "mode": "session_bootstrap",
            "bind": bind,
            "port": 3100,
            "upstream": "http://127.0.0.1:3302",
            "endpoint": "/api/v1/auth/trusted-access/session",
            "surfaces": {
                "user": {"path": "/trusted-access/user", "principal": "user", "audience": "terminal-dev", "scopes": ["app:read"]},
                "operator": {"path": "/trusted-access/operator", "principal": "admin", "audience": "terminal-dev", "scopes": ["app:read", "app:admin"]},
            },
        },
    })
    return ProjectManifest("terminal", {}, {}, Path(".agent-control.yaml"), config), FakeRuntime(identity, registry)


def test_ingress_accepts_only_declared_surface_and_forwards_signed_assertion() -> None:
    manifest, runtime = _manifest()
    forwarded: list[tuple[str, str, bytes, dict[str, str]]] = []

    def forwarder(assertion: str, endpoint: str, body: bytes, headers):
        forwarded.append((assertion, endpoint, body, dict(headers)))
        return IngressResponse(204, (("Set-Cookie", "terminal_session=a"),), b"")

    ingress = TrustedIngress(manifest, runtime, forwarder=forwarder)
    response = ingress.handle(
        method="POST",
        target="/trusted-access/user",
        body=b"",
        headers={"Host": "localhost", "Content-Length": "0"},
        peer_address="127.0.0.1",
    )
    assert response.status == 204
    assert forwarded[0][1:] == (
        "/api/v1/auth/trusted-access/session",
        b"",
        {"content-type": "application/json"},
    )

    assert ingress.handle(method="POST", target="/other", body=b"", headers={}, peer_address="127.0.0.1").status == 404
    assert ingress.handle(method="GET", target="/trusted-access/user", body=b"", headers={}, peer_address="127.0.0.1").status == 405


@pytest.mark.parametrize(
    "target,body,headers",
    [
        ("/trusted-access/user?x=1", b"", {}),
        ("/trusted-access/user", b"{}", {}),
        ("/trusted-access/user", b"", {"cOnTeNt-LeNgTh": "1"}),
        ("/trusted-access/user", b"", {"Transfer-Encoding": "chunked"}),
        ("/trusted-access/user", b"", {"Cookie": "terminal_session=bad"}),
        ("/trusted-access/user", b"", {"Authorization": "Bearer bad"}),
        ("/trusted-access/user", b"", {"X-Forwarded-For": "127.0.0.1"}),
    ],
)
def test_ingress_rejects_body_query_cookie_authorization_and_forwarding_headers(target, body, headers) -> None:
    manifest, runtime = _manifest()
    ingress = TrustedIngress(manifest, runtime, forwarder=lambda *_args: pytest.fail("forwarder must not run"))
    response = ingress.handle(method="POST", target=target, body=body, headers=headers, peer_address="127.0.0.1")
    assert response.status in {400, 404}


def test_ingress_preserves_multiple_set_cookie_headers(monkeypatch) -> None:
    manifest, runtime = _manifest()
    ingress = TrustedIngress(manifest, runtime)

    class FakeResponse:
        status = 201

        def getheaders(self):
            return [
                ("Content-Type", "application/json"),
                ("Set-Cookie", "terminal_session=a; Path=/"),
                ("Set-Cookie", "terminal_session_hint=b; Path=/"),
            ]

        def read(self, _limit):
            return b'{"ok":true}'

    class FakeConnection:
        def request(self, method, path, body, headers):
            assert method == "POST"
            assert path == "/api/v1/auth/trusted-access/session"
            assert body == b""
            assert headers["Authorization"].startswith("Agentctl-Trusted ")

        def getresponse(self):
            return FakeResponse()

        def close(self):
            return None

    monkeypatch.setattr(ingress_module.http.client, "HTTPConnection", lambda *_args, **_kwargs: FakeConnection())
    response = ingress._forward("assertion", "/api/v1/auth/trusted-access/session", b"", {})
    assert response.headers == (
        ("Content-Type", "application/json"),
        ("Set-Cookie", "terminal_session=a; Path=/"),
        ("Set-Cookie", "terminal_session_hint=b; Path=/"),
    )


@pytest.mark.parametrize("bind", ["0.0.0.0", "::", "192.0.2.1", "2001:db8::1"])
def test_ingress_rejects_wildcard_and_public_bind(bind: str) -> None:
    with pytest.raises(TrustedAccessError) as raised:
        _manifest(bind)
    assert raised.value.code == "INVALID_TRUSTED_ACCESS_CONFIGURATION"


def test_ingress_rejects_production_policy() -> None:
    with pytest.raises(TrustedAccessError) as raised:
        TrustedAccessConfig.from_mapping({
            "enabled": True,
            "environment": "production",
            "transports": ["localhost"],
            "handoff": {"enabled": True},
            "principals": {"user": {"subject": "dev-user", "scopes": ["app:read"]}},
        })
    assert raised.value.code == "TRUSTED_ACCESS_NOT_DEV"
