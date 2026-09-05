"""Runnable FastAPI Trusted Development Access reference application."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request

from agentctl.application import DeclarativeMappingAdapter, MappedApplicationPrincipal, TrustedAccessSDK
from agentctl.integrations.fastapi import create_fastapi_dependency, get_agentctl_principal
from agentctl.manifest import load_manifest
from agentctl.registry import load_registry
from agentctl.replay import SQLiteReplayStore
from agentctl.trusted import (
    LocalhostTransportVerifier,
    TailscaleTransportVerifier,
    TrustedIdentityVerifier,
    TrustedAccessError,
)


ROOT = Path(__file__).resolve().parent
MANIFEST = load_manifest(ROOT / ".agent-control.yaml")
CONFIG = MANIFEST.trusted_access
STATE = ROOT / ".agentctl"


def _server_side_tailscale_resolver(peer_address: str) -> str | None:
    """Demo resolver backed by deployment-provided server configuration.

    Replace this function with a Tailscale LocalAPI call in a real deployment.
    It never reads forwarding headers or trusts the peer address by itself.
    """

    raw = os.environ.get("AGENTCTL_TAILSCALE_PEERS_JSON", "{}")
    try:
        peers = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return peers.get(peer_address) if isinstance(peers, dict) else None


def _build_sdk() -> TrustedAccessSDK[MappedApplicationPrincipal]:
    if not CONFIG.enabled or CONFIG.application is None or CONFIG.adapter is None:
        raise RuntimeError("trusted access requires an explicit application and adapter configuration")
    verifiers: dict[str, Any] = {}
    if "localhost" in CONFIG.transports:
        verifiers["localhost"] = LocalhostTransportVerifier()
    if "tailscale" in CONFIG.transports:
        verifiers["tailscale"] = TailscaleTransportVerifier(_server_side_tailscale_resolver)
    verifier = TrustedIdentityVerifier(
        load_registry(STATE / "registry.json"),
        CONFIG,
        SQLiteReplayStore(STATE / "trusted-replay.sqlite"),
        expected_audience=CONFIG.application.audience or next(iter(MANIFEST.audiences.values())).audience,
        transport_verifiers=verifiers,
    )
    if CONFIG.adapter.type != "declarative_mapping":
        raise RuntimeError("this reference app intentionally uses its declarative application adapter")
    return TrustedAccessSDK(verifier, DeclarativeMappingAdapter(CONFIG.adapter.mappings))


SDK = _build_sdk()
TRANSPORT = os.environ.get("AGENTCTL_TRANSPORT", "localhost")
trusted_principal = create_fastapi_dependency(SDK, transport=TRANSPORT)
app = FastAPI(title="agentctl Trusted Access FastAPI example")


def require_application_scope(principal: MappedApplicationPrincipal, scope: str) -> None:
    """Normal application authorization remains active after identity mapping."""

    if not principal.has_scope(scope):
        raise HTTPException(status_code=403, detail={"code": "SCOPE_DENIED", "scope": scope})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/me")
async def me(request: Request, principal: MappedApplicationPrincipal = Depends(trusted_principal)) -> dict[str, Any]:
    agentctl_principal = get_agentctl_principal(request)
    require_application_scope(principal, "app:read")
    return {
        "application_identity": principal.application_identity,
        "subject": agentctl_principal.subject,
        "principal_type": agentctl_principal.principal_type,
        "scopes": list(agentctl_principal.scopes),
        "auth_method": agentctl_principal.auth_method,
    }


@app.get("/admin")
async def admin(principal: MappedApplicationPrincipal = Depends(trusted_principal)) -> dict[str, str]:
    require_application_scope(principal, "app:admin")
    return {"status": "admin-authorized", "application_identity": principal.application_identity}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=int(os.environ.get("PORT", "8000")), reload=False)
