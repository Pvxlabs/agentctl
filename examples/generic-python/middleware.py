"""Framework-neutral verifier adapter example."""

from pathlib import Path

from agentctl.models import RequestContext
from agentctl.registry import load_registry
from agentctl.replay import SQLiteReplayStore
from agentctl.verifier import VerificationResult, Verifier


def verify_agent_request(
    *,
    authorization_header: str,
    request_id_header: str | None,
    method: str,
    target: str,
    body: bytes,
    content_type: str | None,
    environment: str,
    audience: str,
    registry_file: str | Path,
    replay_db: str | Path,
    now: int,
) -> VerificationResult:
    scheme, separator, assertion = authorization_header.partition(" ")
    if scheme != "Agentctl" or not separator or not assertion:
        raise ValueError("missing Agentctl assertion")
    verifier = Verifier(
        load_registry(registry_file),
        SQLiteReplayStore(replay_db),
        expected_audience=audience,
        expected_environment=environment,
    )
    return verifier.verify(
        assertion,
        RequestContext(
            method=method,
            target=target,
            body=body,
            content_type=content_type,
            request_id=request_id_header,
        ),
        now=now,
    )


# The target application still performs domain authorization and transactions
# after this function returns successfully.
