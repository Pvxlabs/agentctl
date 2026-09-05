"""Durable Trusted Development Access authority runtime lifecycle.

The runtime layer owns host-local state only.  It deliberately reuses the
existing identity, registry, replay, and audit implementations; it does not
define another authentication protocol or become an HTTP gateway.
"""

from __future__ import annotations

import json
import os
import stat
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import AuditEvent, JsonlAuditSink, verify_audit_file
from .identity import LocalIdentity, create_identity, load_identity
from .manifest import ProjectManifest
from .models import KeyRecord, PrincipalRecord
from .registry import Registry, encode_public_key, load_registry, save_registry
from .replay import SQLiteReplayStore
from .trusted import (
    DEV_ENVIRONMENTS,
    TAILSCALE_LOCALAPI_SOCKET,
    TrustedAccessError,
    is_dev_environment,
)


RUNTIME_LAYOUT_VERSION = "trusted-access-runtime/v1"
DEFAULT_AUTHORITY_ID = "dev-authority"
DEFAULT_AUTHORITY_KEY_ID = "dev-authority-key"


class RuntimeError(TrustedAccessError):
    """Stable fail-closed error for runtime state and lifecycle failures."""


def _fail(code: str, message: str) -> None:
    raise RuntimeError(code, message)


def default_runtime_dir() -> Path:
    """Return the standard host-local runtime directory.

    XDG_STATE_HOME is preferred when configured.  The fallback is deliberately
    under the user's home directory rather than the project checkout so a
    second project cannot accidentally create a second authority.
    """

    configured = os.environ.get("AGENTCTL_RUNTIME_DIR")
    if configured:
        return Path(configured).expanduser()
    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        return Path(state_home).expanduser() / "agentctl" / "trusted-access"
    return Path.home() / ".local" / "state" / "agentctl" / "trusted-access"


@dataclass(frozen=True)
class TrustedAccessRuntimePaths:
    root: Path
    identity: Path
    registry: Path
    replay_store: Path
    audit: Path
    metadata: Path

    @classmethod
    def from_dir(cls, runtime_dir: str | Path | None = None) -> "TrustedAccessRuntimePaths":
        root = Path(runtime_dir).expanduser() if runtime_dir is not None else default_runtime_dir()
        # Make the path absolute without resolving the final component.  The
        # runtime must be able to reject a symlink at its security boundary.
        root = Path(os.path.abspath(root))
        return cls(
            root=root,
            identity=root / "authority.json",
            registry=root / "registry.json",
            replay_store=root / "replay.sqlite",
            audit=root / "audit.jsonl",
            metadata=root / "runtime.json",
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "runtime_dir": str(self.root),
            "identity_path": str(self.identity),
            "registry_path": str(self.registry),
            "replay_store_path": str(self.replay_store),
            "audit_path": str(self.audit),
            "metadata_path": str(self.metadata),
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _mode(path: Path) -> int:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return -1


def _is_safe_file(path: Path) -> bool:
    try:
        value = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(value.st_mode) and not stat.S_ISLNK(value.st_mode)


def _write_json_private(path: Path, value: dict[str, Any]) -> None:
    if os.path.lexists(path) and not _is_safe_file(path):
        _fail("RUNTIME_PATH_INVALID", f"runtime state path is not a regular file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    if os.path.lexists(temporary) and not _is_safe_file(temporary):
        _fail("RUNTIME_PATH_INVALID", f"runtime temporary path is not a regular file: {temporary}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    os.chmod(path, 0o600)


def _read_metadata(path: Path) -> dict[str, Any]:
    if not _is_safe_file(path):
        _fail("RUNTIME_METADATA_MISSING", f"runtime metadata is missing: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail("RUNTIME_METADATA_INVALID", f"cannot load runtime metadata {path}: {exc}")
    if not isinstance(value, dict) or value.get("version") != RUNTIME_LAYOUT_VERSION:
        _fail("RUNTIME_METADATA_INVALID", "runtime metadata version is unsupported")
    return value


def _ensure_runtime_dir(paths: TrustedAccessRuntimePaths) -> None:
    if os.path.islink(paths.root):
        _fail("RUNTIME_PATH_INVALID", f"runtime directory must not be a symlink: {paths.root}")
    paths.root.mkdir(parents=True, exist_ok=True)
    if paths.root.is_symlink() or not paths.root.is_dir():
        _fail("RUNTIME_PATH_INVALID", f"runtime directory is not a real directory: {paths.root}")
    os.chmod(paths.root, 0o700)


def _restrict_runtime_files(paths: TrustedAccessRuntimePaths) -> None:
    """Keep mutable runtime state private to the service account."""

    for path in (paths.identity, paths.registry, paths.replay_store, paths.audit, paths.metadata):
        if path.exists() and _is_safe_file(path):
            os.chmod(path, 0o600)


def _reject_invalid_runtime_files(paths: TrustedAccessRuntimePaths) -> None:
    for path in (paths.identity, paths.registry, paths.replay_store, paths.audit, paths.metadata):
        if os.path.lexists(path) and not _is_safe_file(path):
            _fail("RUNTIME_PATH_INVALID", f"runtime state path is not a regular file: {path}")


def _check_private_permissions(path: Path) -> tuple[bool, str]:
    if not path.exists():
        return False, f"missing: {path}"
    if not _is_safe_file(path):
        return False, f"not a regular file: {path}"
    mode = _mode(path)
    if mode < 0 or mode & 0o077:
        return False, f"permissions are too broad: {path} mode={mode:04o}"
    return True, f"mode={mode:04o}: {path}"


def _configured_environment(manifest: ProjectManifest) -> str:
    config = manifest.trusted_access
    if not config.enabled:
        _fail("TRUSTED_ACCESS_DISABLED", "trusted DEV access is not enabled")
    if config.environment is None or not is_dev_environment(config.environment):
        _fail("TRUSTED_ACCESS_NOT_DEV", "trusted access can only be enabled for DEV")
    return config.environment


def _authority_record(identity: LocalIdentity, *, now: str | None = None) -> tuple[PrincipalRecord, KeyRecord]:
    created_at = now or _now()
    return (
        PrincipalRecord(identity.principal_id, identity.display_name, identity.environment, created_at=created_at, updated_at=created_at),
        KeyRecord(identity.key_id, identity.principal_id, identity.algorithm, encode_public_key(identity.public_key_bytes), created_at=created_at),
    )


def _validate_identity_registry(identity: LocalIdentity, registry: Registry, environment: str) -> tuple[PrincipalRecord, KeyRecord]:
    if not is_dev_environment(identity.environment) or identity.environment != environment:
        _fail("AUTHORITY_NOT_DEV", "runtime authority identity is not in the configured DEV environment")
    principal = registry.principals.get(identity.principal_id)
    key = registry.keys.get(identity.key_id)
    if principal is None or key is None:
        _fail("AUTHORITY_NOT_REGISTERED", "runtime authority identity is not registered")
    if principal.environment != identity.environment or key.principal_id != identity.principal_id:
        _fail("AUTHORITY_REGISTRY_MISMATCH", "runtime authority registry entries do not match identity")
    if key.algorithm != "Ed25519" or key.public_key != encode_public_key(identity.public_key_bytes):
        _fail("AUTHORITY_KEY_MISMATCH", "runtime authority key does not match registry")
    return principal, key


def _append_runtime_audit(paths: TrustedAccessRuntimePaths, *, action: str, code: str, identity: LocalIdentity, key_id: str) -> None:
    JsonlAuditSink(paths.audit).append(
        AuditEvent(
            event_id=str(uuid.uuid4()),
            principal_type="authority",
            principal_id=identity.principal_id,
            key_id=key_id,
            environment=identity.environment,
            audience="runtime",
            scope="",
            action=action,
            http_method="",
            canonical_path="",
            body_sha256="",
            resource=None,
            request_id=str(uuid.uuid4()),
            jti="",
            result="AUTHORIZED",
            result_code=code,
            created_at=_now(),
        )
    )


class TrustedAccessRuntime:
    """Host-local lifecycle manager for one reusable DEV authority."""

    def __init__(self, paths: TrustedAccessRuntimePaths, *, tailscale_socket: str | None = None) -> None:
        self.paths = paths
        self.tailscale_socket = tailscale_socket or TAILSCALE_LOCALAPI_SOCKET
        self._tailscale_socket_explicit = tailscale_socket is not None

    def _effective_tailscale_socket(self, metadata: dict[str, Any] | None = None) -> str:
        if not self._tailscale_socket_explicit and metadata is not None:
            configured = metadata.get("tailscale_socket")
            if isinstance(configured, str) and configured:
                return configured
        return self.tailscale_socket

    def _metadata(self, *, identity: LocalIdentity, environment: str, created_at: str, updated_at: str, tailscale_socket: str) -> dict[str, Any]:
        return {
            "version": RUNTIME_LAYOUT_VERSION,
            "authority_id": identity.principal_id,
            "authority_key_id": identity.key_id,
            "environment": environment,
            "tailscale_socket": tailscale_socket,
            "created_at": created_at,
            "updated_at": updated_at,
            **self.paths.as_dict(),
        }

    def bootstrap(self, manifest: ProjectManifest, *, authority_id: str = DEFAULT_AUTHORITY_ID, key_id: str = DEFAULT_AUTHORITY_KEY_ID) -> dict[str, Any]:
        environment = _configured_environment(manifest)
        _ensure_runtime_dir(self.paths)
        _reject_invalid_runtime_files(self.paths)
        identity_exists = self.paths.identity.exists()
        registry_exists = self.paths.registry.exists()
        if registry_exists and not identity_exists:
            _fail("RUNTIME_STATE_INCOMPLETE", "registry exists without the authority private identity")

        created = False
        recovered_registry = False
        if identity_exists:
            if not _is_safe_file(self.paths.identity):
                _fail("RUNTIME_IDENTITY_INVALID", f"authority identity is not a regular private file: {self.paths.identity}")
            try:
                identity = load_identity(self.paths.identity)
            except ValueError as exc:
                _fail("RUNTIME_IDENTITY_INVALID", str(exc))
            if identity.principal_id != authority_id:
                _fail("AUTHORITY_ID_MISMATCH", "existing authority identity does not match requested authority id")
            if not is_dev_environment(identity.environment) or identity.environment != environment:
                _fail("AUTHORITY_NOT_DEV", "existing authority identity is not in the configured DEV environment")
        else:
            identity = create_identity(
                self.paths.identity,
                principal_id=authority_id,
                display_name="DEV Authority",
                environment=environment,
                key_id=key_id,
            )
            created = True

        if registry_exists:
            if not _is_safe_file(self.paths.registry):
                _fail("RUNTIME_REGISTRY_INVALID", f"registry is not a regular file: {self.paths.registry}")
            try:
                registry = load_registry(self.paths.registry)
            except ValueError as exc:
                _fail("RUNTIME_REGISTRY_INVALID", str(exc))
        else:
            registry = Registry()
            recovered_registry = identity_exists

        principal = registry.principals.get(identity.principal_id)
        key = registry.keys.get(identity.key_id)
        if principal is None and key is None:
            principal, key = _authority_record(identity)
            registry.add_principal(principal)
            registry.add_key(key)
            created = True
        elif principal is None or key is None:
            _fail("RUNTIME_REGISTRY_INCOMPLETE", "authority registry is missing a principal or key entry")
        else:
            _validate_identity_registry(identity, registry, environment)

        if not principal.enabled or principal.revoked_at is not None or not key.enabled or key.revoked_at is not None:
            _fail("AUTHORITY_REVOKED", "existing runtime authority is disabled or revoked; rotate it explicitly")

        # A missing registry is recoverable only by registering the valid
        # identity above.  Existing unrelated registry entries are preserved.
        save_registry(self.paths.registry, registry)
        SQLiteReplayStore(self.paths.replay_store)
        self.paths.audit.touch(exist_ok=True)
        _restrict_runtime_files(self.paths)

        previous_metadata: dict[str, Any] | None = None
        if self.paths.metadata.exists():
            previous_metadata = _read_metadata(self.paths.metadata)
            if previous_metadata.get("authority_id") != identity.principal_id:
                _fail("RUNTIME_METADATA_INVALID", "runtime metadata authority id does not match identity")
            if previous_metadata.get("authority_key_id") != identity.key_id:
                _fail("RUNTIME_METADATA_INVALID", "runtime metadata authority key id does not match identity")
            if previous_metadata.get("environment") != environment:
                _fail("RUNTIME_METADATA_INVALID", "runtime metadata environment does not match manifest")
            created_at = str(previous_metadata.get("created_at") or _now())
        else:
            created_at = _now()
        effective_socket = self._effective_tailscale_socket(previous_metadata)
        metadata = self._metadata(
            identity=identity,
            environment=environment,
            created_at=created_at,
            updated_at=_now(),
            tailscale_socket=effective_socket,
        )
        _write_json_private(self.paths.metadata, metadata)
        _append_runtime_audit(self.paths, action="trusted_dev.runtime.bootstrap", code="RUNTIME_BOOTSTRAPPED", identity=identity, key_id=identity.key_id)
        return {
            "result": "RECOVERED" if recovered_registry else ("CREATED" if created else "REUSED"),
            "runtime_ready": True,
            "authority_id": identity.principal_id,
            "authority_key_id": identity.key_id,
            "environment": environment,
            "tailscale_socket": effective_socket,
            "registry_path": str(self.paths.registry),
            "replay_store_path": str(self.paths.replay_store),
            "audit_path": str(self.paths.audit),
            "runtime_dir": str(self.paths.root),
        }

    def _load(self, manifest: ProjectManifest) -> tuple[str, LocalIdentity, Registry, PrincipalRecord, KeyRecord, dict[str, Any]]:
        environment = _configured_environment(manifest)
        if not self.paths.root.is_dir() or self.paths.root.is_symlink() or _mode(self.paths.root) & 0o077:
            _fail("RUNTIME_PERMISSIONS_UNSAFE", f"runtime directory is missing or permissions are too broad: {self.paths.root}")
        if not _is_safe_file(self.paths.identity):
            _fail("RUNTIME_IDENTITY_MISSING", f"authority identity is missing: {self.paths.identity}")
        if not _is_safe_file(self.paths.registry):
            _fail("RUNTIME_REGISTRY_MISSING", f"authority registry is missing: {self.paths.registry}")
        for path in (self.paths.identity, self.paths.registry, self.paths.replay_store, self.paths.audit, self.paths.metadata):
            permissions_ok, permission_message = _check_private_permissions(path)
            if not permissions_ok:
                _fail("RUNTIME_PERMISSIONS_UNSAFE", permission_message)
        try:
            identity = load_identity(self.paths.identity)
            registry = load_registry(self.paths.registry)
        except ValueError as exc:
            _fail("RUNTIME_STATE_INVALID", str(exc))
        principal, key = _validate_identity_registry(identity, registry, environment)
        metadata = _read_metadata(self.paths.metadata)
        if metadata.get("authority_id") != identity.principal_id:
            _fail("RUNTIME_METADATA_INVALID", "runtime metadata authority id does not match identity")
        if metadata.get("authority_key_id") != identity.key_id:
            _fail("RUNTIME_METADATA_INVALID", "runtime metadata authority key id does not match identity")
        if metadata.get("environment") != environment:
            _fail("RUNTIME_METADATA_INVALID", "runtime metadata environment does not match manifest")
        return environment, identity, registry, principal, key, metadata

    def load_identity_registry(self, manifest: ProjectManifest) -> tuple[LocalIdentity, Registry, PrincipalRecord, KeyRecord]:
        """Load the validated canonical authority context for an application.

        Consumers should use this instead of reconstructing paths from the
        runtime layout.  Validation includes the DEV policy, identity/registry
        binding, and runtime metadata consistency.
        """

        _environment, identity, registry, principal, key, _metadata = self._load(manifest)
        return identity, registry, principal, key

    def replay_store(self) -> SQLiteReplayStore:
        """Open the durable replay store created by ``bootstrap``."""

        _ensure_runtime_dir(self.paths)
        if not _is_safe_file(self.paths.replay_store):
            _fail("RUNTIME_REPLAY_STORE_MISSING", f"replay store is missing or invalid: {self.paths.replay_store}")
        return SQLiteReplayStore(self.paths.replay_store)

    def audit_sink(self) -> JsonlAuditSink:
        """Return the append-only audit sink for this runtime."""

        _ensure_runtime_dir(self.paths)
        if not _is_safe_file(self.paths.audit):
            _fail("RUNTIME_AUDIT_MISSING", f"audit file is missing or invalid: {self.paths.audit}")
        return JsonlAuditSink(self.paths.audit)

    def status(self, manifest: ProjectManifest) -> dict[str, Any]:
        output: dict[str, Any] = {
            "runtime_ready": False,
            "authority_id": None,
            "authority_key_id": None,
            "registry_path": str(self.paths.registry),
            "replay_store_path": str(self.paths.replay_store),
            "audit_path": str(self.paths.audit),
            "tailscale_socket": self.tailscale_socket,
            "environment": manifest.trusted_access.environment,
            "runtime_dir": str(self.paths.root),
        }
        try:
            environment, identity, registry, principal, key, metadata = self._load(manifest)
            output.update({
                "runtime_ready": principal.enabled and principal.revoked_at is None and key.enabled and key.revoked_at is None,
                "authority_id": identity.principal_id,
                "authority_key_id": identity.key_id,
                "environment": environment,
                "authority_enabled": principal.enabled,
                "authority_revocation_epoch": principal.revocation_epoch,
                "authority_key_enabled": key.enabled,
                "authority_key_revoked": key.revoked_at is not None,
                "registered_principals": len(registry.principals),
                "registered_keys": len(registry.keys),
                "metadata_updated_at": metadata.get("updated_at"),
                "tailscale_socket": self._effective_tailscale_socket(metadata),
            })
        except RuntimeError as exc:
            output.update({"result": "FAILED", "result_code": exc.code, "message": exc.message})
        return output

    def doctor(self, manifest: ProjectManifest) -> dict[str, Any]:
        checks: list[dict[str, str]] = []

        def check(name: str, passed: bool, message: str) -> None:
            checks.append({"name": name, "status": "PASS" if passed else "FAIL", "message": message})

        config = manifest.trusted_access
        if not config.enabled:
            check("environment", False, "trusted access is explicitly disabled")
        elif config.environment in DEV_ENVIRONMENTS:
            check("environment", True, f"environment={config.environment}")
        else:
            check("environment", False, f"environment={config.environment}")

        check("runtime_directory", self.paths.root.exists() and self.paths.root.is_dir(), str(self.paths.root))
        identity_ok, identity_message = _check_private_permissions(self.paths.identity)
        check("identity_permissions", identity_ok, identity_message)
        for name, path in (("registry", self.paths.registry), ("replay_store", self.paths.replay_store), ("audit", self.paths.audit), ("metadata", self.paths.metadata)):
            check(name, _is_safe_file(path), str(path) if _is_safe_file(path) else f"missing or invalid: {path}")
        metadata_ok = False
        effective_socket = self.tailscale_socket
        try:
            metadata = _read_metadata(self.paths.metadata)
            effective_socket = self._effective_tailscale_socket(metadata)
            metadata_ok = isinstance(metadata.get("tailscale_socket"), str) and metadata.get("tailscale_socket") == effective_socket
            check("metadata", metadata_ok, "runtime metadata is valid" if metadata_ok else "metadata socket does not match configured socket")
        except RuntimeError as exc:
            check("metadata", False, exc.message)

        authority_ok = False
        try:
            environment, identity, registry, principal, key, _metadata = self._load(manifest)
            authority_ok = principal.enabled and principal.revoked_at is None and key.enabled and key.revoked_at is None
            check("authority", authority_ok, f"identity={identity.principal_id}, key={identity.key_id}")
            check("registry_identity", True, "identity and registry public key match")
        except RuntimeError as exc:
            check("authority", False, exc.message)
            check("registry_identity", False, exc.message)

        replay_ok = False
        if _is_safe_file(self.paths.replay_store):
            try:
                connection = sqlite3.connect(f"file:{self.paths.replay_store}?mode=ro", uri=True)
                try:
                    connection.execute("SELECT 1 FROM consumed_jti LIMIT 1")
                finally:
                    connection.close()
                replay_ok = True
            except sqlite3.Error as exc:
                check("replay_schema", False, f"replay store is not readable: {exc}")
        if replay_ok:
            check("replay_schema", True, "durable consumed_jti schema is readable")

        audit_ok = False
        if _is_safe_file(self.paths.audit):
            audit_ok, audit_message = verify_audit_file(self.paths.audit)
            check("audit_chain", audit_ok, audit_message)

        permissions_ok = all(
            _check_private_permissions(path)[0]
            for path in (self.paths.identity, self.paths.registry, self.paths.replay_store, self.paths.audit, self.paths.metadata)
        ) and _mode(self.paths.root) >= 0 and not (_mode(self.paths.root) & 0o077)
        check("filesystem_permissions", permissions_ok, f"runtime directory mode={_mode(self.paths.root):04o}")

        if config.enabled and "tailscale" in config.transports:
            socket_path = Path(effective_socket)
            try:
                socket_ok = socket_path.exists() and not socket_path.is_symlink() and stat.S_ISSOCK(socket_path.lstat().st_mode)
            except OSError:
                socket_ok = False
            check("tailscale_localapi", socket_ok, str(socket_path) if socket_ok else f"missing or not a Unix socket: {socket_path}")
        else:
            check("tailscale_localapi", True, "not required by the configured transport policy")

        failed = [item for item in checks if item["status"] == "FAIL"]
        return {
            "protocol": "ATIP-v1",
            "overall": "FAIL" if failed else "PASS",
            "runtime_ready": not failed,
            "authority_id": self.status(manifest).get("authority_id"),
            "registry_path": str(self.paths.registry),
            "replay_store_path": str(self.paths.replay_store),
            "audit_path": str(self.paths.audit),
            "tailscale_socket": effective_socket,
            "environment": config.environment,
            "checks": checks,
        }

    def rotate_authority(self, manifest: ProjectManifest) -> dict[str, Any]:
        environment, old_identity, registry, principal, old_key, metadata = self._load(manifest)
        del principal
        timestamp = _now()
        new_identity_path = self.paths.identity.with_name(self.paths.identity.name + ".next")
        if os.path.lexists(new_identity_path) and not _is_safe_file(new_identity_path):
            _fail("RUNTIME_PATH_INVALID", f"runtime temporary path is not a regular file: {new_identity_path}")
        new_identity = create_identity(
            new_identity_path,
            principal_id=old_identity.principal_id,
            display_name=old_identity.display_name,
            environment=environment,
            key_id=f"{old_identity.principal_id}-key-{uuid.uuid4().hex[:12]}",
        )
        _new_principal, new_key = _authority_record(new_identity, now=timestamp)
        # Keep the prior key enabled.  Existing short-lived assertions remain
        # verifiable until expiry; the new identity is selected for issuance.
        registry.add_key(new_key)
        save_registry(self.paths.registry, registry)
        new_identity_path.replace(self.paths.identity)
        os.chmod(self.paths.identity, 0o600)
        updated = self._metadata(
            identity=new_identity,
            environment=environment,
            created_at=str(metadata.get("created_at") or timestamp),
            updated_at=timestamp,
            tailscale_socket=self._effective_tailscale_socket(metadata),
        )
        _write_json_private(self.paths.metadata, updated)
        _restrict_runtime_files(self.paths)
        _append_runtime_audit(self.paths, action="trusted_dev.runtime.rotate", code="AUTHORITY_ROTATED", identity=new_identity, key_id=new_identity.key_id)
        return {
            "result": "ROTATED",
            "runtime_ready": True,
            "authority_id": new_identity.principal_id,
            "authority_key_id": new_identity.key_id,
            "previous_authority_key_id": old_key.key_id,
            "previous_key_preserved": True,
            "environment": environment,
            "registry_path": str(self.paths.registry),
            "replay_store_path": str(self.paths.replay_store),
            "audit_path": str(self.paths.audit),
            "tailscale_socket": self._effective_tailscale_socket(metadata),
        }

    def revoke_authority(self, manifest: ProjectManifest, *, key_id: str | None = None) -> dict[str, Any]:
        environment, identity, registry, _principal, current_key, metadata = self._load(manifest)
        target_id = key_id or current_key.key_id
        target = registry.keys.get(target_id)
        if target is None or target.principal_id != identity.principal_id:
            _fail("UNKNOWN_AUTHORITY_KEY", "requested authority key is not registered for this authority")
        if target.revoked_at is not None or not target.enabled:
            return {
                "result": "ALREADY_REVOKED",
                "runtime_ready": False if target_id == identity.key_id else True,
                "authority_id": identity.principal_id,
                "authority_key_id": identity.key_id,
                "revoked_key_id": target_id,
                "environment": environment,
            }
        target.enabled = False
        target.revoked_at = _now()
        target.key_epoch += 1
        save_registry(self.paths.registry, registry)
        _restrict_runtime_files(self.paths)
        _append_runtime_audit(self.paths, action="trusted_dev.runtime.revoke", code="AUTHORITY_REVOKED", identity=identity, key_id=target_id)
        return {
            "result": "REVOKED",
            "runtime_ready": False if target_id == identity.key_id else True,
            "authority_id": identity.principal_id,
            "authority_key_id": identity.key_id,
            "revoked_key_id": target_id,
            "environment": environment,
            "registry_path": str(self.paths.registry),
            "replay_store_path": str(self.paths.replay_store),
            "audit_path": str(self.paths.audit),
            "tailscale_socket": metadata.get("tailscale_socket", self.tailscale_socket),
        }
