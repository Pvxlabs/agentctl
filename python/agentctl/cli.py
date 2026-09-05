"""The agentctl command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml

from .audit import AuditEvent, JsonlAuditSink, verify_audit_file
from .conformance import run_conformance, run_smoke_test
from .identity import create_identity, load_identity
from .manifest import find_manifest, load_manifest
from .models import KeyRecord, PrincipalRecord, RequestContext, ScopeGrant
from .protocol import build_assertion, canonical_request_target, parse_assertion, sha256_hex
from .registry import Registry, encode_public_key, load_registry, save_registry
from .replay import SQLiteReplayStore
from .runtime import TrustedAccessRuntime, TrustedAccessRuntimePaths
from .trusted import (
    LocalhostTransportVerifier,
    TAILSCALE_LOCALAPI_SOCKET,
    TransportObservation,
    TrustedAccessAuthority,
    TrustedAccessConfig,
    TrustedAccessError,
    parse_trusted_identity_assertion,
)
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
            "trusted_access": {
                "enabled": manifest.trusted_access.enabled,
                "environment": manifest.trusted_access.environment,
                "transports": list(manifest.trusted_access.transports),
                "principals": {
                    name: {
                        "subject": policy.subject,
                        "type": policy.principal_type,
                        "scopes": list(policy.scopes),
                    }
                    for name, policy in (manifest.trusted_access.principals or {}).items()
                },
            },
        },
        json_output=True,
    )
    return 0


def _cmd_trusted_access(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest or find_manifest())
    config = manifest.trusted_access
    _emit(
        {
            "project": manifest.project,
            "manifest": str(manifest.source),
            "trusted_access": {
                "enabled": config.enabled,
                "environment": config.environment,
                "transports": list(config.transports),
                "application": config.application.__dict__ if config.application else None,
                "adapter": {
                    "type": config.adapter.type,
                    "mappings": dict(config.adapter.mappings),
                } if config.adapter else None,
                "principals": {
                    name: {"subject": policy.subject, "type": policy.principal_type, "scopes": list(policy.scopes)}
                    for name, policy in (config.principals or {}).items()
                },
            },
            "status": "ENABLED" if config.enabled else "DISABLED",
            "protocol": "ATIP-v1",
            "valid": True,
        },
        json_output=True,
    )
    return 0


def _project_slug(path: Path) -> str:
    value = "".join(character.lower() if character.isalnum() else "-" for character in path.name)
    value = "-".join(part for part in value.split("-") if part)
    return value or "trusted-app"


def _detect_framework(root: Path) -> str:
    package = root / "package.json"
    if package.exists():
        try:
            value = json.loads(package.read_text(encoding="utf-8"))
            dependencies = {**value.get("dependencies", {}), **value.get("devDependencies", {})}
            if "express" in dependencies or (root / "tsconfig.json").exists():
                return "express"
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            pass
    for candidate in (root / "pyproject.toml", root / "requirements.txt", root / "requirements-dev.txt"):
        if candidate.exists():
            try:
                if "fastapi" in candidate.read_text(encoding="utf-8").lower():
                    return "fastapi"
            except (OSError, UnicodeError):
                pass
    return "fastapi" if list(root.glob("*.py")) else "express"


def _cmd_trusted_access_init(args: argparse.Namespace) -> int:
    root = Path(args.path or ".").resolve()
    root.mkdir(parents=True, exist_ok=True)
    state = root / ".agentctl"
    identity_path = state / "dev-authority.json"
    registry_path = state / "registry.json"
    identity_exists = identity_path.exists()
    registry_exists = registry_path.exists()
    if identity_exists != registry_exists:
        raise ValueError(
            "trusted access state is incomplete; both .agentctl/dev-authority.json "
            "and .agentctl/registry.json must exist together"
        )
    manifest_path = root / ".agent-control.yaml"
    if manifest_path.exists() and not args.force:
        _emit({"result": "EXISTS", "manifest": str(manifest_path), "message": "manifest already exists; use --force to replace the scaffold"}, json_output=True)
        return 0
    framework = _detect_framework(root)
    project = _project_slug(root)
    port = 8000 if framework == "fastapi" else 3000
    audience = f"{project}-dev"
    manifest = {
        "project": project,
        "audiences": {"dev": {"base_url": f"http://127.0.0.1:{port}", "audience": audience}},
        "actions": {"health.read": {"method": "GET", "path": "/", "scope": "app:read", "audience": "dev"}},
        "trusted_access": {
            "enabled": True,
            "environment": "dev",
            "transports": ["localhost", "tailscale"],
            "application": {"identity": project, "audience": audience},
            "adapter": {
                "type": "declarative_mapping",
                "mappings": {
                    "dev-user": "app-dev-user",
                    "dev-admin": "app-dev-admin",
                    "dev-agent": "app-dev-agent",
                },
            },
            "principals": {
                "user": {"subject": "dev-user", "type": "human", "scopes": ["app:read"]},
                "admin": {"subject": "dev-admin", "type": "human", "scopes": ["app:admin", "app:read"]},
                "agent": {"subject": "dev-agent", "type": "agent", "scopes": ["app:read", "app:test"]},
            },
        },
    }
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    created_state = False
    if not identity_exists and not registry_exists:
        identity = create_identity(identity_path, principal_id="dev-authority", display_name="DEV Authority", environment="dev", key_id="dev-authority-key")
        registry = Registry()
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        registry.add_principal(PrincipalRecord(identity.principal_id, identity.display_name, identity.environment, created_at=now, updated_at=now))
        registry.add_key(KeyRecord(identity.key_id, identity.principal_id, identity.algorithm, encode_public_key(identity.public_key_bytes)))
        save_registry(registry_path, registry)
        created_state = True
    guide = state / "trusted-access.integration.md"
    guide.parent.mkdir(parents=True, exist_ok=True)
    guide.write_text(
        """# agentctl Trusted Development Access

Generated scaffold. The application must install the optional framework integration,
construct a `TrustedAccessSDK` with its verifier and adapter, and keep normal application
authorization after the adapter establishes the application principal.

The generated `app-dev-*` mapping values are placeholders owned by the target
application. Replace them with that application's normal DEV identities; agentctl
core does not know or store application account names.

```text
agentctl trusted-access validate
agentctl trusted-access doctor
agentctl trusted-access test
agentctl trusted-access conformance
```

Use the dedicated `Agentctl-Trusted <assertion>` authorization scheme. Do not accept
forwarding headers as transport proof and do not put application credentials in the
manifest. See `docs/trusted-access.md` for framework examples.
""",
        encoding="utf-8",
    )
    _emit({"result": "CREATED", "framework": framework, "manifest": str(manifest_path), "identity_file": str(identity_path), "registry_file": str(registry_path), "integration_guide": str(guide), "state_created": created_state}, json_output=True)
    return 0


def _doctor_check(name: str, status: str, message: str) -> dict[str, str]:
    return {"name": name, "status": status, "message": message}


def _tailscale_localapi_check(socket_path: str) -> tuple[str, str]:
    """Check the configured LocalAPI endpoint without trusting request data."""

    path = Path(socket_path)
    if not path.exists():
        return "FAIL", f"LocalAPI socket does not exist: {path}"
    try:
        if not stat.S_ISSOCK(path.stat().st_mode):
            return "FAIL", f"LocalAPI path is not a Unix socket: {path}"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(1.0)
            client.connect(str(path))
    except OSError as exc:
        return "FAIL", f"LocalAPI socket is not reachable: {exc}"
    return "PASS", f"reachable LocalAPI socket: {path}"


def _cmd_trusted_access_doctor(args: argparse.Namespace) -> int:
    if _use_runtime_doctor(args):
        manifest = load_manifest(args.manifest or find_manifest())
        runtime = TrustedAccessRuntime(
            TrustedAccessRuntimePaths.from_dir(args.runtime_dir),
            tailscale_socket=args.tailscale_socket or os.environ.get("TAILSCALE_SOCKET"),
        )
        result = runtime.doctor(manifest)
        _emit(result, json_output=True)
        return 0 if result["overall"] == "PASS" else 1
    manifest = load_manifest(args.manifest or find_manifest())
    config = manifest.trusted_access
    checks: list[dict[str, str]] = []
    if not config.enabled:
        checks.append(_doctor_check("environment", "DISABLED", "trusted access is explicitly disabled"))
        checks.append(_doctor_check("production_isolation", "PASS", "disabled policy cannot activate trusted DEV access"))
        _emit({"protocol": "ATIP-v1", "overall": "DISABLED", "checks": checks}, json_output=True)
        return 0
    checks.append(_doctor_check("environment", "PASS" if config.environment in {"dev", "development"} else "FAIL", f"environment={config.environment}"))
    identity_path = Path(args.identity_file or manifest.source.parent / ".agentctl/dev-authority.json")
    registry_path = Path(args.registry_file or manifest.source.parent / ".agentctl/registry.json")
    try:
        identity, registry, principal, key = _identity_registry_context(str(identity_path), str(registry_path))
        authority_ok = identity.environment in {"dev", "development"} and principal.environment == config.environment and key.algorithm == "Ed25519"
        checks.append(_doctor_check("authority", "PASS" if authority_ok else "FAIL", f"identity={identity.principal_id}"))
    except (OSError, ValueError) as exc:
        checks.append(_doctor_check("authority", "FAIL", str(exc)))
    provider_ok = bool(config.transports) and all(item in {"localhost", "tailscale"} for item in config.transports)
    provider_message = "server-side Tailscale LocalAPI verifier required" if "tailscale" in config.transports else "localhost socket peer verification configured"
    checks.append(_doctor_check("transport_provider", "PASS" if provider_ok else "FAIL", provider_message))
    if "tailscale" in config.transports:
        tailscale_socket = args.tailscale_socket or os.environ.get("TAILSCALE_SOCKET", TAILSCALE_LOCALAPI_SOCKET)
        socket_status, socket_message = _tailscale_localapi_check(tailscale_socket)
        checks.append(_doctor_check("tailscale_localapi", socket_status, socket_message))
    audiences = {item.audience for item in manifest.audiences.values()}
    selected_audience = config.application.audience if config.application else next(iter(audiences), None)
    audience_ok = selected_audience in audiences
    checks.append(_doctor_check("audience", "PASS" if audience_ok else "FAIL", f"audience={selected_audience}"))
    adapter_ok = config.adapter is not None and config.adapter.type in {"declarative_mapping", "custom"}
    if adapter_ok and config.adapter and config.adapter.type == "declarative_mapping":
        subjects = {item.subject for item in (config.principals or {}).values()}
        adapter_ok = subjects.issubset(config.adapter.mappings)
    checks.append(_doctor_check("application_adapter", "PASS" if adapter_ok else "FAIL", "explicit adapter and mappings are present" if adapter_ok else "adapter mapping is incomplete"))
    scope_ok = all(policy.scopes for policy in (config.principals or {}).values())
    checks.append(_doctor_check("scope_policy", "PASS" if scope_ok else "FAIL", "explicit scopes only"))
    isolation_ok = config.environment in {"dev", "development"}
    checks.append(_doctor_check("production_isolation", "PASS" if isolation_ok else "FAIL", "trusted DEV semantics are isolated from production"))
    failed = [check for check in checks if check["status"] == "FAIL"]
    _emit({"protocol": "ATIP-v1", "overall": "FAIL" if failed else "PASS", "checks": checks, "manifest": str(manifest.source)}, json_output=True)
    return 1 if failed else 0


def _use_runtime_doctor(args: argparse.Namespace) -> bool:
    """Keep the original project-local doctor compatible with ``init``.

    Explicit runtime paths always select the lifecycle doctor.  With no path,
    an existing project-local init state retains the legacy behavior; a host
    without that state uses the standard XDG runtime.
    """

    if args.runtime_dir or args.identity_file or args.registry_file:
        return bool(args.runtime_dir)
    try:
        manifest = load_manifest(args.manifest or find_manifest())
    except (OSError, ValueError):
        return True
    local_state = manifest.source.parent / ".agentctl"
    return not (local_state.joinpath("dev-authority.json").exists() and local_state.joinpath("registry.json").exists())


def _runtime(args: argparse.Namespace) -> TrustedAccessRuntime:
    return TrustedAccessRuntime(
        TrustedAccessRuntimePaths.from_dir(args.runtime_dir),
        tailscale_socket=args.tailscale_socket or os.environ.get("TAILSCALE_SOCKET"),
    )


def _cmd_trusted_access_bootstrap(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest or find_manifest())
    result = _runtime(args).bootstrap(
        manifest,
        authority_id=args.authority_id,
        key_id=args.key_id,
    )
    _emit(result, json_output=True)
    return 0


def _cmd_trusted_access_status(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest or find_manifest())
    result = _runtime(args).status(manifest)
    _emit(result, json_output=True)
    return 0 if result.get("runtime_ready") else 1


def _cmd_trusted_access_rotate(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest or find_manifest())
    result = _runtime(args).rotate_authority(manifest)
    _emit(result, json_output=True)
    return 0


def _cmd_trusted_access_revoke(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest or find_manifest())
    result = _runtime(args).revoke_authority(manifest, key_id=args.key_id)
    _emit(result, json_output=True)
    return 0


def _cmd_trusted_access_test(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest or find_manifest())
    try:
        result = run_smoke_test(manifest)
    except (TrustedAccessError, ValueError) as exc:
        _emit({"result": "FAILED", "result_code": getattr(exc, "code", "CLI_ERROR"), "message": str(exc)}, json_output=True)
        return 1
    _emit(result, json_output=True)
    return 0 if result.get("passed") else 1


def _cmd_trusted_access_issue(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest or find_manifest())
    config = manifest.trusted_access
    runtime: TrustedAccessRuntime | None = None
    if args.runtime_dir is not None or (args.identity_file is None and args.registry_file is None):
        if args.identity_file is not None or args.registry_file is not None:
            raise ValueError("use either --runtime-dir or both --identity-file and --registry-file")
        runtime = _runtime(args)
        identity, registry, _principal, _key = runtime.load_identity_registry(manifest)
    else:
        if args.identity_file is None or args.registry_file is None:
            raise ValueError("--identity-file and --registry-file must be provided together")
        identity, registry, _principal, _key = _identity_registry_context(args.identity_file, args.registry_file)
    if config.application and config.application.audience:
        default_audience = config.application.audience
    elif len(manifest.audiences) == 1:
        default_audience = next(iter(manifest.audiences.values())).audience
    else:
        raise ValueError("trusted access issue requires --audience when the manifest has multiple audiences")
    authority = TrustedAccessAuthority(
        identity,
        registry,
        config,
        audit_sink=runtime.audit_sink() if runtime is not None else None,
        transport_verifiers={"localhost": LocalhostTransportVerifier()},
    )
    assertion = authority.issue(
        requested_principal=args.principal,
        audience=args.audience or default_audience,
        scopes=args.scope,
        observation=TransportObservation("localhost", "127.0.0.1"),
        now=args.now,
        ttl_seconds=args.ttl,
    )
    payload, _signature, _segment = parse_trusted_identity_assertion(assertion)
    if args.out:
        destination = Path(args.out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(assertion + "\n", encoding="utf-8")
        _emit({"assertion_file": str(destination.resolve()), "jti": payload["jti"], "subject": payload["sub"], "scopes": payload["scopes"], "expires_at": payload["exp"]}, json_output=True)
    else:
        _emit({"assertion": assertion, "jti": payload["jti"], "subject": payload["sub"], "scopes": payload["scopes"], "expires_at": payload["exp"]}, json_output=True)
    return 0


def _cmd_trusted_access_conformance(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest or find_manifest())
    result = run_conformance(manifest)
    _emit(result, json_output=True)
    return 0 if result["compatible"] else 1


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

    trusted_access = subparsers.add_parser("trusted-access")
    trusted_access_sub = trusted_access.add_subparsers(dest="trusted_access_action", required=True)
    trusted_access_validate = trusted_access_sub.add_parser("validate")
    trusted_access_validate.add_argument("--manifest")
    trusted_access_init = trusted_access_sub.add_parser("init")
    trusted_access_init.add_argument("--path", default=".")
    trusted_access_init.add_argument("--force", action="store_true")
    trusted_access_doctor = trusted_access_sub.add_parser("doctor")
    trusted_access_doctor.add_argument("--manifest")
    trusted_access_doctor.add_argument("--identity-file")
    trusted_access_doctor.add_argument("--registry-file")
    trusted_access_doctor.add_argument("--tailscale-socket")
    trusted_access_doctor.add_argument("--runtime-dir")
    trusted_access_doctor.add_argument("--json", dest="json_output", action="store_true")
    trusted_access_bootstrap = trusted_access_sub.add_parser("bootstrap")
    trusted_access_bootstrap.add_argument("--manifest")
    trusted_access_bootstrap.add_argument("--runtime-dir", default=None)
    trusted_access_bootstrap.add_argument("--tailscale-socket")
    trusted_access_bootstrap.add_argument("--authority-id", default="dev-authority")
    trusted_access_bootstrap.add_argument("--key-id", default="dev-authority-key")
    trusted_access_bootstrap.add_argument("--json", dest="json_output", action="store_true")
    trusted_access_status = trusted_access_sub.add_parser("status")
    trusted_access_status.add_argument("--manifest")
    trusted_access_status.add_argument("--runtime-dir", default=None)
    trusted_access_status.add_argument("--tailscale-socket")
    trusted_access_status.add_argument("--json", dest="json_output", action="store_true")
    trusted_access_rotate = trusted_access_sub.add_parser("rotate-authority")
    trusted_access_rotate.add_argument("--manifest")
    trusted_access_rotate.add_argument("--runtime-dir", default=None)
    trusted_access_rotate.add_argument("--tailscale-socket")
    trusted_access_rotate.add_argument("--json", dest="json_output", action="store_true")
    trusted_access_revoke = trusted_access_sub.add_parser("revoke-authority")
    trusted_access_revoke.add_argument("--manifest")
    trusted_access_revoke.add_argument("--runtime-dir", default=None)
    trusted_access_revoke.add_argument("--tailscale-socket")
    trusted_access_revoke.add_argument("--key-id")
    trusted_access_revoke.add_argument("--json", dest="json_output", action="store_true")
    trusted_access_issue = trusted_access_sub.add_parser("issue")
    trusted_access_issue.add_argument("--manifest")
    trusted_access_issue.add_argument("--runtime-dir")
    trusted_access_issue.add_argument("--identity-file")
    trusted_access_issue.add_argument("--registry-file")
    trusted_access_issue.add_argument("--tailscale-socket")
    trusted_access_issue.add_argument("--principal", required=True)
    trusted_access_issue.add_argument("--audience")
    trusted_access_issue.add_argument("--scope", action="append", required=True)
    trusted_access_issue.add_argument("--now", type=int)
    trusted_access_issue.add_argument("--ttl", type=int, default=60)
    trusted_access_issue.add_argument("--out")
    trusted_access_issue.add_argument("--json", dest="json_output", action="store_true")
    trusted_access_sub.add_parser("test").add_argument("--manifest")
    trusted_access_sub.add_parser("conformance").add_argument("--manifest")

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
        if args.command == "trusted-access":
            if args.trusted_access_action == "validate":
                return _cmd_trusted_access(args)
            if args.trusted_access_action == "init":
                return _cmd_trusted_access_init(args)
            if args.trusted_access_action == "doctor":
                return _cmd_trusted_access_doctor(args)
            if args.trusted_access_action == "bootstrap":
                return _cmd_trusted_access_bootstrap(args)
            if args.trusted_access_action == "status":
                return _cmd_trusted_access_status(args)
            if args.trusted_access_action == "rotate-authority":
                return _cmd_trusted_access_rotate(args)
            if args.trusted_access_action == "revoke-authority":
                return _cmd_trusted_access_revoke(args)
            if args.trusted_access_action == "issue":
                return _cmd_trusted_access_issue(args)
            if args.trusted_access_action == "test":
                return _cmd_trusted_access_test(args)
            if args.trusted_access_action == "conformance":
                return _cmd_trusted_access_conformance(args)
            raise ValueError("trusted-access subcommand is required")
        if args.command == "sign":
            return _cmd_sign(args)
        if args.command == "verify":
            return _cmd_verify(args)
        if args.command == "call":
            return _cmd_call(args)
        if args.command == "audit":
            return _cmd_audit(args)
    except (OSError, ValueError, TypeError) as exc:
        _emit({"result": "FAILED", "result_code": getattr(exc, "code", "CLI_ERROR"), "message": str(exc)}, json_output=True)
        return 2
    return 2
