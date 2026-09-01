"""The agentctl command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .audit import AuditEvent, JsonlAuditSink, verify_audit_file
from .identity import create_identity, load_identity
from .manifest import find_manifest, load_manifest
from .models import KeyRecord, PrincipalRecord, RequestContext, ScopeGrant
from .protocol import build_assertion, canonical_request_target, parse_assertion, sha256_hex
from .registry import Registry, encode_public_key, load_registry, save_registry
from .replay import SQLiteReplayStore
from .verifier import VerificationError, Verifier


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _emit(value: Any, *, json_output: bool = False) -> None:
    if json_output:
        sys.stdout.write(_json(value))
    elif isinstance(value, str):
        sys.stdout.write(value + ("" if value.endswith("\n") else "\n"))
    else:
        sys.stdout.write(_json(value))


def _read_body(args: argparse.Namespace) -> bytes:
    if args.body is not None and args.body_file is not None:
        raise ValueError("use only one of --body and --body-file")
    if args.body is not None:
        return args.body.encode("utf-8")
    if args.body_file:
        return Path(args.body_file).read_bytes()
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read()
    return b""


def _parse_params(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        name, separator, parameter = value.partition("=")
        if not separator or not name:
            raise ValueError(f"invalid --param {value!r}; expected name=value")
        if name in result:
            raise ValueError(f"duplicate action parameter: {name}")
        result[name] = parameter
    return result


def _identity_registry_context(identity_file: str, registry_file: str) -> tuple[Any, Registry, PrincipalRecord, KeyRecord]:
    identity = load_identity(identity_file)
    registry = load_registry(registry_file)
    principal = registry.principals.get(identity.principal_id)
    if principal is None:
        raise ValueError(f"principal is not registered: {identity.principal_id}")
    key = registry.keys.get(identity.key_id)
    if key is None:
        raise ValueError(f"key is not registered: {identity.key_id}")
    if key.principal_id != identity.principal_id:
        raise ValueError("identity key does not belong to its principal")
    if key.public_key != encode_public_key(identity.public_key_bytes):
        raise ValueError("identity public key does not match registry")
    return identity, registry, principal, key


def _build_signer_assertion(args: argparse.Namespace, *, target: str, body: bytes, scope: str, audience: str, project: str | None = None) -> tuple[str, str]:
    identity, _registry, principal, key = _identity_registry_context(args.identity_file, args.registry_file)
    environment = args.environment or identity.environment
    if environment != identity.environment or environment != principal.environment:
        raise ValueError("requested environment does not match the registered identity")
    request_id = args.request_id or str(uuid.uuid4())
    assertion = build_assertion(
        principal_id=identity.principal_id,
        audience=audience,
        environment=environment,
        scope=scope,
        http_method=args.method,
        target=target,
        body=body,
        key_id=identity.key_id,
        principal_epoch=principal.revocation_epoch,
        key_epoch=key.key_epoch,
        private_key=identity.private_key,
        content_type=args.content_type,
        resource=args.resource,
        project=project,
        request_id=request_id,
        jti=args.jti,
        now=args.now,
        ttl_seconds=args.ttl,
    )
    return assertion, request_id


def _cmd_identity(args: argparse.Namespace) -> int:
    if args.identity_action == "create":
        identity = create_identity(
            args.out,
            principal_id=args.principal_id,
            display_name=args.display_name,
            environment=args.environment,
            key_id=args.key_id,
        )
        _emit(
            {
                "identity_file": str(Path(args.out).resolve()),
                "principal_id": identity.principal_id,
                "key_id": identity.key_id,
                "algorithm": identity.algorithm,
                "environment": identity.environment,
                "public_key": encode_public_key(identity.public_key_bytes),
            },
            json_output=True,
        )
        return 0
    raise ValueError("identity subcommand is required")


def _cmd_principals(args: argparse.Namespace) -> int:
    registry = load_registry(args.registry_file)
    if args.principals_action == "list":
        _emit(registry.to_dict(), json_output=True)
        return 0
    if args.principals_action == "add":
        identity = load_identity(args.identity_file)
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        principal = registry.principals.get(identity.principal_id)
        if principal is None:
            principal = PrincipalRecord(
                principal_id=identity.principal_id,
                display_name=identity.display_name,
                environment=identity.environment,
                created_at=now,
                updated_at=now,
            )
            registry.add_principal(principal)
        key = KeyRecord(
            key_id=identity.key_id,
            principal_id=identity.principal_id,
            algorithm=identity.algorithm,
            public_key=encode_public_key(identity.public_key_bytes),
        )
        registry.add_key(key)
        grants = list(args.grant)
        if args.audience or args.scope or args.resource:
            if not args.audience or not args.scope:
                raise ValueError("--audience and --scope must be supplied together")
            grants.append(",".join(filter(None, [args.audience, args.scope, args.resource])))
        for value in grants:
            parts = value.split(",")
            if len(parts) not in {2, 3} or not all(parts[:2]):
                raise ValueError(f"invalid --grant {value!r}; expected audience,scope[,resource]")
            registry.add_grant(
                ScopeGrant(
                    principal_id=identity.principal_id,
                    environment=identity.environment,
                    audience=parts[0],
                    scope=parts[1],
                    resource=parts[2] if len(parts) == 3 and parts[2] else None,
                )
            )
        save_registry(args.registry_file, registry)
        _emit({"registry_file": str(Path(args.registry_file).resolve()), **identity.public_record(), "grants": len(registry.grants)}, json_output=True)
        return 0
    if args.principals_action == "revoke":
        principal = registry.principals.get(args.principal_id)
        if principal is None:
            raise ValueError(f"principal is not registered: {args.principal_id}")
        principal.enabled = False
        principal.revoked_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        principal.revocation_epoch += 1
        principal.updated_at = principal.revoked_at
        save_registry(args.registry_file, registry)
        _emit({"principal_id": principal.principal_id, "enabled": principal.enabled, "revocation_epoch": principal.revocation_epoch}, json_output=True)
        return 0
    raise ValueError("principals subcommand is required")


def _cmd_capabilities(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest or find_manifest())
    _emit(
        {
            "project": manifest.project,
            "manifest": str(manifest.source),
            "audiences": {name: config.__dict__ for name, config in manifest.audiences.items()},
            "actions": {name: config.__dict__ for name, config in manifest.actions.items()},
        },
        json_output=True,
    )
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    body = _read_body(args)
    assertion, request_id = _build_signer_assertion(
        args,
        target=args.target,
        body=body,
        scope=args.scope,
        audience=args.audience,
    )
    if args.out:
        destination = Path(args.out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(assertion + "\n", encoding="utf-8")
        _emit({"assertion_file": str(destination.resolve()), "request_id": request_id}, json_output=True)
    elif args.json_output:
        _emit({"assertion": assertion, "request_id": request_id}, json_output=True)
    else:
        _emit(assertion)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    assertion = Path(args.assertion_file).read_text(encoding="utf-8").strip()
    body = _read_body(args)
    sink = JsonlAuditSink(args.audit_file) if args.audit_file else None
    verifier = Verifier(
        load_registry(args.registry_file),
        SQLiteReplayStore(args.replay_db),
        expected_audience=args.audience,
        expected_environment=args.environment,
        audit_sink=sink,
    )
    try:
        result = verifier.verify(
            assertion,
            RequestContext(
                method=args.method,
                target=args.target,
                body=body,
                content_type=args.content_type,
                request_id=args.request_id,
                resource=args.resource,
            ),
            now=args.now,
            action=args.action,
        )
    except VerificationError as exc:
        _emit({"authorized": False, "result": "REJECTED", "result_code": exc.code, "message": exc.message}, json_output=True)
        return 1
    _emit({"authorized": True, "result": "AUTHORIZED", **result.to_dict()}, json_output=True)
    return 0


def _call_audit(args: argparse.Namespace, *, assertion: str, request_id: str, result: str, result_code: str, body: bytes, target: str, response_status: int | None = None) -> None:
    if not args.audit_file:
        return
    identity, _registry, _principal, key = _identity_registry_context(args.identity_file, args.registry_file)
    payload = parse_assertion(assertion).payload
    sink = JsonlAuditSink(args.audit_file)
    sink.append(
        AuditEvent(
            event_id=str(uuid.uuid4()),
            principal_type="machine",
            principal_id=identity.principal_id,
            key_id=key.key_id,
            environment=payload["environment"],
            audience=payload["aud"],
            scope=payload["scope"],
            action=args.action,
            http_method=args.method,
            canonical_path=canonical_request_target(target),
            body_sha256=sha256_hex(body),
            resource=payload.get("resource"),
            request_id=request_id,
            jti=payload["jti"],
            result=result,
            result_code=result_code if response_status is None else f"{result_code}:{response_status}",
            created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
    )


def _cmd_call(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest or find_manifest())
    params = _parse_params(args.param)
    action, audience_config, target = manifest.resolve_action(args.action, params=params)
    if args.scope and args.scope != action.scope:
        raise ValueError("--scope must exactly match the manifest action scope")
    args.scope = action.scope
    args.audience = audience_config.audience
    args.method = action.method
    args.content_type = args.content_type or action.content_type
    args.resource = args.resource or action.resource
    body = _read_body(args)
    assertion, request_id = _build_signer_assertion(args, target=target, body=body, scope=args.scope, audience=args.audience, project=manifest.project)
    headers = {
        "Authorization": f"Agentctl {assertion}",
        "X-Agentctl-Request-ID": request_id,
        "Accept": "application/json",
    }
    if args.content_type:
        headers["Content-Type"] = args.content_type
    request = Request(target, data=body if body else None, headers=headers, method=args.method)
    try:
        with urlopen(request, timeout=args.timeout) as response:
            response_body = response.read()
            _call_audit(args, assertion=assertion, request_id=request_id, result="EXECUTED", result_code="TRANSPORT_RESPONSE", body=body, target=target, response_status=response.status)
            output: dict[str, Any] = {
                "result": "EXECUTED",
                "transport_response": True,
                "http_status": response.status,
                "request_id": request_id,
                "response_body_sha256": sha256_hex(response_body),
            }
            if args.include_response_body:
                output["response_body"] = response_body.decode("utf-8", errors="replace")
            _emit(output, json_output=True)
            return 0
    except HTTPError as exc:
        response_body = exc.read()
        _call_audit(args, assertion=assertion, request_id=request_id, result="EXECUTED", result_code="TRANSPORT_RESPONSE", body=body, target=target, response_status=exc.code)
        output = {"result": "EXECUTED", "transport_response": True, "http_status": exc.code, "request_id": request_id, "response_body_sha256": sha256_hex(response_body)}
        if args.include_response_body:
            output["response_body"] = response_body.decode("utf-8", errors="replace")
        _emit(output, json_output=True)
        return 0
    except (OSError, URLError) as exc:
        _call_audit(args, assertion=assertion, request_id=request_id, result="FAILED", result_code="TRANSPORT_FAILURE", body=body, target=target)
        _emit({"result": "FAILED", "transport_response": False, "result_code": "TRANSPORT_FAILURE", "message": str(exc), "request_id": request_id}, json_output=True)
        return 1


def _cmd_audit(args: argparse.Namespace) -> int:
    valid, message = verify_audit_file(args.file)
    _emit({"valid": valid, "message": message, "file": str(Path(args.file).resolve())}, json_output=True)
    return 0 if valid else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentctl", description="Request-bound machine authorization for AI agents")
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser("identity")
    identity_sub = identity.add_subparsers(dest="identity_action", required=True)
    create = identity_sub.add_parser("create")
    create.add_argument("--principal-id", required=True)
    create.add_argument("--display-name")
    create.add_argument("--environment", default="development")
    create.add_argument("--key-id")
    create.add_argument("--out", required=True)

    principals = subparsers.add_parser("principals")
    principals_sub = principals.add_subparsers(dest="principals_action", required=True)
    principal_list = principals_sub.add_parser("list")
    principal_list.add_argument("--registry-file", required=True)
    add = principals_sub.add_parser("add")
    add.add_argument("--identity-file", required=True)
    add.add_argument("--registry-file", required=True)
    add.add_argument("--audience")
    add.add_argument("--scope")
    add.add_argument("--resource")
    add.add_argument("--grant", action="append", default=[])
    revoke = principals_sub.add_parser("revoke")
    revoke.add_argument("--principal-id", required=True)
    revoke.add_argument("--registry-file", required=True)

    capabilities = subparsers.add_parser("capabilities")
    capabilities.add_argument("--manifest")

    sign = subparsers.add_parser("sign")
    sign.add_argument("--identity-file", required=True)
    sign.add_argument("--registry-file", required=True)
    sign.add_argument("--environment")
    sign.add_argument("--audience", required=True)
    sign.add_argument("--scope", required=True)
    sign.add_argument("--content-type")
    sign.add_argument("--resource")
    sign.add_argument("--project")
    sign.add_argument("--request-id")
    sign.add_argument("--jti")
    sign.add_argument("--now", type=int)
    sign.add_argument("--ttl", type=int, default=300)
    sign.add_argument("--body")
    sign.add_argument("--body-file")
    sign.add_argument("--out")
    sign.add_argument("--json", dest="json_output", action="store_true")
    sign.add_argument("method")
    sign.add_argument("target")

    verify = subparsers.add_parser("verify")
    verify.add_argument("--assertion-file", required=True)
    verify.add_argument("--registry-file", required=True)
    verify.add_argument("--replay-db", required=True)
    verify.add_argument("--environment", required=True)
    verify.add_argument("--audience", required=True)
    verify.add_argument("--content-type")
    verify.add_argument("--resource")
    verify.add_argument("--request-id", required=True)
    verify.add_argument("--now", type=int, required=True)
    verify.add_argument("--action", default="verify_agent_request")
    verify.add_argument("--audit-file")
    verify.add_argument("--body")
    verify.add_argument("--body-file")
    verify.add_argument("method")
    verify.add_argument("target")

    call = subparsers.add_parser("call")
    call.add_argument("--manifest")
    call.add_argument("--action", required=True)
    call.add_argument("--identity-file", required=True)
    call.add_argument("--registry-file", required=True)
    call.add_argument("--environment", required=True)
    call.add_argument("--scope")
    call.add_argument("--content-type")
    call.add_argument("--resource")
    call.add_argument("--request-id")
    call.add_argument("--jti")
    call.add_argument("--now", type=int)
    call.add_argument("--ttl", type=int, default=300)
    call.add_argument("--param", action="append", default=[])
    call.add_argument("--body")
    call.add_argument("--body-file")
    call.add_argument("--timeout", type=float, default=30.0)
    call.add_argument("--audit-file")
    call.add_argument("--include-response-body", action="store_true")

    audit = subparsers.add_parser("audit")
    audit_sub = audit.add_subparsers(dest="audit_action", required=True)
    audit_verify = audit_sub.add_parser("verify")
    audit_verify.add_argument("--file", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "identity":
            return _cmd_identity(args)
        if args.command == "principals":
            return _cmd_principals(args)
        if args.command == "capabilities":
            return _cmd_capabilities(args)
        if args.command == "sign":
            return _cmd_sign(args)
        if args.command == "verify":
            return _cmd_verify(args)
        if args.command == "call":
            return _cmd_call(args)
        if args.command == "audit":
            return _cmd_audit(args)
    except (OSError, ValueError, TypeError) as exc:
        _emit({"result": "FAILED", "result_code": "CLI_ERROR", "message": str(exc)}, json_output=True)
        return 2
    return 2
