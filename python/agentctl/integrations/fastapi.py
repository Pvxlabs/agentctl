"""FastAPI dependency integration for Trusted Development Access.

FastAPI remains an optional dependency.  Applications install it themselves;
importing this module does not require FastAPI to be installed.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from ..application import TrustedAccessSDK, extract_trusted_assertion
from ..trusted import AgentctlPrincipal, TrustedAccessError, TransportObservation


def create_fastapi_dependency(
    sdk: TrustedAccessSDK[Any],
    *,
    transport: str = "localhost",
    now: Callable[[], int] | None = None,
    authorization_scheme: str = "Agentctl-Trusted",
    authorization_header: str | None = None,
):
    """Return a FastAPI dependency that establishes normal app identity.

    The transport is configured by the server operator.  It is never selected
    from a client header.  Forwarding headers are treated as untrusted input.
    """

    clock = now or (lambda: int(time.time()))
    header_name = (authorization_header or "authorization").lower()

    async def dependency(request: Any) -> Any:
        try:
            assertion = extract_trusted_assertion(request.headers.get(header_name), scheme=authorization_scheme)
            peer_address = request.client.host if request.client is not None else None
            forwarded = any(name in request.headers for name in ("forwarded", "x-forwarded-for", "x-real-ip"))
            context = sdk.authenticate_with_context(
                assertion,
                observation=TransportObservation(transport, peer_address, forwarded_headers_present=forwarded),
                now=clock(),
            )
        except TrustedAccessError as exc:
            from fastapi import HTTPException

            raise HTTPException(status_code=401, detail={"code": exc.code, "message": exc.message}) from exc
        except ValueError as exc:
            from fastapi import HTTPException

            raise HTTPException(status_code=403, detail={"code": "APPLICATION_ADAPTER_REJECTED", "message": str(exc)}) from exc
        request.state.agentctl_principal = context.agentctl_principal
        request.state.application_principal = context.application_principal
        return context.application_principal

    # FastAPI distinguishes framework request objects from ordinary dependency
    # parameters by their runtime annotation. Keep the import optional so the
    # SDK remains usable without FastAPI installed.
    try:
        from starlette.requests import Request as FrameworkRequest
    except ImportError:
        pass
    else:
        dependency.__annotations__["request"] = FrameworkRequest

    return dependency


def get_agentctl_principal(request: Any) -> AgentctlPrincipal:
    """Read the verified principal set by the dependency."""

    principal = getattr(getattr(request, "state", None), "agentctl_principal", None)
    if not isinstance(principal, AgentctlPrincipal):
        raise RuntimeError("trusted access dependency has not established a principal")
    return principal
