"""Narrow host-side Trusted Access session bootstrap ingress."""

from __future__ import annotations

import http.client
import ipaddress
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from typing import Callable, Mapping

from .manifest import ProjectManifest
from .runtime import TrustedAccessRuntime
from .trusted import (
    LocalhostTransportVerifier,
    TailscaleLocalAPIClient,
    TailscaleLocalAPITransportVerifier,
    TransportObservation,
    TrustedAccessAuthority,
    TrustedAccessError,
)


MAX_UPSTREAM_RESPONSE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class IngressResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


def _transport_for_peer(peer_address: str) -> str:
    try:
        address = ipaddress.ip_address(peer_address)
    except ValueError as exc:
        raise TrustedAccessError("UNTRUSTED_TRANSPORT", "ingress peer address is invalid") from exc
    if address.is_loopback:
        return "localhost"
    if address in ipaddress.ip_network("100.64.0.0/10") or address in ipaddress.ip_network("fd7a:115c:a1e0::/48"):
        return "tailscale"
    raise TrustedAccessError("UNTRUSTED_TRANSPORT", "ingress peer is not localhost or Tailscale")


class TrustedIngress:
    def __init__(self, manifest: ProjectManifest, runtime: TrustedAccessRuntime, *, forwarder: Callable[[str, str, bytes, Mapping[str, str]], IngressResponse] | None = None) -> None:
        config = manifest.trusted_access
        if not config.enabled or config.environment not in {"dev", "development"}:
            raise TrustedAccessError("TRUSTED_ACCESS_NOT_DEV", "trusted ingress can only run for DEV")
        if config.ingress is None or config.handoff is None or not config.handoff.enabled:
            raise TrustedAccessError("INVALID_TRUSTED_ACCESS_CONFIGURATION", "trusted ingress requires handoff.enabled and ingress configuration")
        self.manifest = manifest
        self.config = config
        self.ingress = config.ingress
        identity, registry, _principal, _key = runtime.load_identity_registry(manifest)
        self.authority = TrustedAccessAuthority(
            identity,
            registry,
            config,
            audit_sink=runtime.audit_sink(),
            transport_verifiers={
                "localhost": LocalhostTransportVerifier(),
                "tailscale": TailscaleLocalAPITransportVerifier(TailscaleLocalAPIClient(runtime.tailscale_socket)),
            },
        )
        self._forwarder = forwarder or self._forward

    def handle(self, *, method: str, target: str, body: bytes, headers: Mapping[str, str], peer_address: str) -> IngressResponse:
        parsed = urlsplit(target)
        if method != "POST":
            return IngressResponse(405, (("Allow", "POST"),), b"method not allowed\n")
        if parsed.scheme or parsed.netloc:
            return IngressResponse(400, (), b"absolute request targets are not allowed\n")
        surface = next((item for item in self.ingress.surfaces.values() if item.path == parsed.path), None)
        if surface is None or parsed.query or parsed.fragment:
            return IngressResponse(404, (), b"not found\n")
        normalized_headers = {key.lower(): value for key, value in headers.items()}
        if body or normalized_headers.get("content-length", "0") not in {"", "0"}:
            return IngressResponse(400, (), b"request body is not allowed\n")
        if "transfer-encoding" in normalized_headers or "content-encoding" in normalized_headers:
            return IngressResponse(400, (), b"request body is not allowed\n")
        if any(key in {"authorization", "cookie", "x-agentctl-trusted", "x-forwarded-for", "x-real-ip", "forwarded"} for key in normalized_headers):
            return IngressResponse(400, (), b"request headers are not allowed\n")
        transport = _transport_for_peer(peer_address)
        assertion = self.authority.issue(
            requested_principal=surface.principal,
            audience=surface.audience,
            scopes=surface.scopes,
            observation=TransportObservation(transport, peer_address),
            ttl_seconds=60,
        )
        return self._forwarder(assertion, self.ingress.endpoint, b"", {"content-type": "application/json"})

    def _forward(self, assertion: str, endpoint: str, body: bytes, headers: Mapping[str, str]) -> IngressResponse:
        parsed = urlsplit(self.ingress.upstream)
        connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(parsed.hostname, parsed.port, timeout=5)
        try:
            path = (parsed.path.rstrip("/") + endpoint) if parsed.path not in {"", "/"} else endpoint
            request_headers = {"Authorization": f"Agentctl-Trusted {assertion}", "Content-Length": str(len(body)), **headers}
            connection.request("POST", path, body=body, headers=request_headers)
            response = connection.getresponse()
            payload = response.read(MAX_UPSTREAM_RESPONSE_BYTES + 1)
            if len(payload) > MAX_UPSTREAM_RESPONSE_BYTES:
                raise TrustedAccessError("UPSTREAM_RESPONSE_TOO_LARGE", "trusted ingress upstream response is too large")
            return IngressResponse(response.status, tuple((key, value) for key, value in response.getheaders() if key.lower() in {"content-type", "content-length", "set-cookie"}), payload)
        finally:
            connection.close()


def serve_ingress(ingress: TrustedIngress) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            response = ingress.handle(method="POST", target=self.path, body=body, headers=dict(self.headers.items()), peer_address=self.client_address[0])
            self.send_response(response.status)
            for key, value in response.headers:
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.body)

        def do_GET(self) -> None:  # noqa: N802
            response = ingress.handle(method="GET", target=self.path, body=b"", headers=dict(self.headers.items()), peer_address=self.client_address[0])
            self.send_response(response.status)
            for key, value in response.headers:
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer((ingress.ingress.bind, ingress.ingress.port), Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()
