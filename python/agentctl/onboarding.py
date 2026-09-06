"""Consumer-facing Trusted Access onboarding orchestration.

This module is intentionally an orchestration layer, not a second
authentication implementation.  It detects only facts needed for onboarding,
reuses the canonical runtime, and delegates application identity lifecycle to
an explicit application-owned adapter or command contract.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.error import URLError
from urllib.request import Request, urlopen

import yaml

from .application import DevIdentityBootstrapAdapter
from .conformance import run_smoke_test
from .manifest import ProjectManifest, load_manifest
from .runtime import TrustedAccessRuntime, TrustedAccessRuntimePaths
from .trusted import (
    DevIdentityProfile,
    TrustedAccessError,
    is_dev_environment,
)


DEFAULT_DEV_PROFILE: dict[str, DevIdentityProfile] = {
    "user": DevIdentityProfile("dev-user", "user@test.local", "user"),
    "admin": DevIdentityProfile("dev-admin", "admin@test.local", "admin"),
    "agent": DevIdentityProfile("dev-agent", "agent@test.local", "user"),
}

DEFAULT_ADAPTER_MODULE = "agentctl_trusted_access_adapter:adapter"


class OnboardingError(TrustedAccessError):
    """A stable blocker that prevents onboarding from claiming readiness."""


@dataclass(frozen=True)
class ProjectFacts:
    root: Path
    language: str
    framework: str
    package_manager: str
    python_environment: str | None
    entrypoint: str | None
    manifest: Path | None
    existing_integration: str
    bootstrap_candidates: tuple[str, ...]
    start_candidates: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "language": self.language,
            "framework": self.framework,
            "package_manager": self.package_manager,
            "python_environment": self.python_environment,
            "entrypoint": self.entrypoint,
            "manifest": str(self.manifest) if self.manifest else None,
            "existing_integration": self.existing_integration,
            "bootstrap_candidates": list(self.bootstrap_candidates),
            "start_candidates": list(self.start_candidates),
        }

    @property
    def dev_environment(self) -> str:
        if self.manifest is None:
            return "unknown"
        try:
            value = yaml.safe_load(self.manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError):
            return "invalid"
        trusted_access = value.get("trusted_access") if isinstance(value, Mapping) else None
        environment = trusted_access.get("environment") if isinstance(trusted_access, Mapping) else None
        return environment if isinstance(environment, str) and environment else "unknown"


@dataclass
class OnboardingResult:
    facts: ProjectFacts
    ready: bool = False
    blocker: dict[str, str] | None = None
    manifest: dict[str, Any] = field(default_factory=dict)
    runtime: dict[str, Any] = field(default_factory=dict)
    identities: dict[str, Any] = field(default_factory=dict)
    integration: dict[str, Any] = field(default_factory=dict)
    smoke: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        project = self.facts.to_dict()
        onboarding = self.manifest.get("onboarding", {}) if isinstance(self.manifest, Mapping) else {}
        bootstrap_strategy = "configured" if self.identities else "adapter-required"
        start_strategy = "configured" if isinstance(onboarding, Mapping) and onboarding.get("start") else "reuse-or-explicit-start-required"
        return {
            "ready": self.ready,
            "project": project,
            "PROJECT_ROOT": project["root"],
            "LANGUAGE": project["language"],
            "FRAMEWORK": project["framework"],
            "DEV_ENVIRONMENT": self.facts.dev_environment,
            "EXISTING_INTEGRATION": project["existing_integration"],
            "BOOTSTRAP_STRATEGY": bootstrap_strategy,
            "START_STRATEGY": start_strategy,
            "manifest": self.manifest,
            "runtime": self.runtime,
            "identities": self.identities,
            "integration": self.integration,
            "smoke": self.smoke,
            "blocker": self.blocker,
        }


def _find_root(start: str | Path) -> Path:
    path = Path(start).expanduser().resolve()
    if path.is_file():
        path = path.parent
    for candidate in (path, *path.parents):
        if (candidate / ".git").exists():
            return candidate
    return path


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _detect_python(root: Path) -> tuple[str, str, str | None, str | None]:
    candidates = [root / "pyproject.toml", root / "requirements.txt", root / "requirements-dev.txt"]
    contents = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in candidates
        if path.exists()
    ).lower()
    language = "python" if contents or list(root.glob("*.py")) else "unknown"
    framework = "fastapi" if "fastapi" in contents else ("python" if language == "python" else "unknown")
    environment = next((str(root / name) for name in (".venv", "venv", "env") if (root / name).is_dir()), None)
    entrypoint = next(
        (name for name in ("main.py", "app.py", "server.py", "src/main.py", "src/app.py") if (root / name).exists()),
        None,
    )
    return language, framework, environment, entrypoint


def _detect_project_manager(root: Path, language: str) -> str:
    if (root / "pnpm-lock.yaml").exists():
        return "pnpm"
    if (root / "yarn.lock").exists():
        return "yarn"
    if (root / "package-lock.json").exists():
        return "npm"
    if (root / "package.json").exists():
        return "npm"
    if (root / "uv.lock").exists():
        return "uv"
    if (root / "poetry.lock").exists():
        return "poetry"
    if language == "python":
        return "pip"
    return "unknown"


def _detect_project(start: str | Path) -> ProjectFacts:
    root = _find_root(start)
    package = _read_json(root / "package.json")
    python_language, python_framework, python_env, python_entrypoint = _detect_python(root)
    if package is not None:
        dependencies = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
        framework = "express" if "express" in dependencies else ("node" if (root / "tsconfig.json").exists() else "node")
        language = "typescript" if (root / "tsconfig.json").exists() else "javascript"
        entrypoint = next((name for name in ("src/index.ts", "src/server.ts", "index.ts", "server.ts", "index.js", "server.js") if (root / name).exists()), None)
    else:
        language, framework, python_env, entrypoint = python_language, python_framework, python_env, python_entrypoint

    manifest = next(
        (
            candidate
            for candidate in (root / ".agent-control.yaml", root / ".agent-control.yml")
            if candidate.exists()
        ),
        None,
    )
    integration = "configured" if manifest and "trusted_access:" in manifest.read_text(encoding="utf-8", errors="ignore") else "missing"
    bootstrap_candidates: list[str] = []
    for relative in ("scripts/local-cluster.sh", "scripts/dev-bootstrap", "scripts/bootstrap-dev", "scripts/seed-dev", "scripts/create-test-users"):
        if (root / relative).exists():
            bootstrap_candidates.append(relative)
    start_candidates: list[str] = []
    for relative in ("docker-compose.yml", "compose.yml", "docker-compose.dev.yml", "containers/local-cluster/compose.dev.yml", "scripts/dev-run", "scripts/dev-restart"):
        if (root / relative).exists():
            start_candidates.append(relative)
    return ProjectFacts(
        root=root,
        language=language,
        framework=framework,
        package_manager=_detect_project_manager(root, language),
        python_environment=python_env,
        entrypoint=entrypoint,
        manifest=manifest,
        existing_integration=integration,
        bootstrap_candidates=tuple(bootstrap_candidates),
        start_candidates=tuple(start_candidates),
    )


def _profile_mapping(profile: Mapping[str, DevIdentityProfile]) -> dict[str, Any]:
    return {
        name: {"principal": item.principal, "account": item.account, "role": item.role}
        for name, item in profile.items()
    }


def _fresh_manifest(facts: ProjectFacts) -> dict[str, Any]:
    port = 8000 if facts.framework == "fastapi" else 3000
    project = facts.root.name.lower().replace("_", "-").replace(" ", "-") or "trusted-app"
    audience = f"{project}-dev"
    value: dict[str, Any] = {
        "project": project,
        "audiences": {"dev": {"base_url": f"http://127.0.0.1:{port}", "audience": audience}},
        "actions": {"health.read": {"method": "GET", "path": "/", "scope": "app:read", "audience": "dev"}},
        "trusted_access": {
            "enabled": True,
            "environment": "dev",
            "transports": ["localhost", "tailscale"],
            "application": {"identity": project, "audience": audience},
            "adapter": {"type": "declarative_mapping", "mappings": {item.principal: item.account for item in DEFAULT_DEV_PROFILE.values()}},
            "principals": {
                "user": {"subject": "dev-user", "type": "human", "scopes": ["app:read"]},
                "admin": {"subject": "dev-admin", "type": "human", "scopes": ["app:read", "app:admin"]},
                "agent": {"subject": "dev-agent", "type": "agent", "scopes": ["app:read", "app:test"]},
            },
            "dev_profile": _profile_mapping(DEFAULT_DEV_PROFILE),
        },
    }
    # This is an explicit, application-owned convention rather than broad
    # script discovery.  The file is never generated or executed by agentctl;
    # it is only wired into a new manifest when the consumer already provides
    # the documented adapter seam.
    if (facts.root / "agentctl_trusted_access_adapter.py").is_file():
        value["trusted_access"]["onboarding"] = {
            "identity_bootstrap": {"type": "adapter", "module": DEFAULT_ADAPTER_MODULE},
        }
    return value


def _write_manifest(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    temporary.replace(path)


def _manifest_value(manifest: ProjectManifest) -> dict[str, Any]:
    value = yaml.safe_load(manifest.source.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise OnboardingError("INVALID_MANIFEST", "manifest must contain an object")
    return value


def _profile_from_manifest(manifest: ProjectManifest) -> dict[str, DevIdentityProfile]:
    configured = manifest.trusted_access.dev_profile
    if configured:
        return dict(configured)
    adapter = manifest.trusted_access.adapter
    policies = manifest.trusted_access.principals or {}
    result: dict[str, DevIdentityProfile] = {}
    for name in ("user", "admin", "agent"):
        policy = policies.get(name)
        account = adapter.mappings.get(policy.subject) if adapter else None
        if policy and account:
            result[name] = DevIdentityProfile(policy.subject, account, "admin" if name == "admin" else "user")
    return result


def _load_adapter(spec: str, root: Path) -> DevIdentityBootstrapAdapter:
    module_name, separator, attribute = spec.partition(":")
    if not separator or not module_name or not attribute:
        raise OnboardingError("INVALID_IDENTITY_ADAPTER", "adapter module must use module:attribute")
    old_path = list(sys.path)
    sys.path.insert(0, str(root))
    try:
        value = getattr(importlib.import_module(module_name), attribute)
    except (ImportError, AttributeError) as exc:
        raise OnboardingError("IDENTITY_ADAPTER_LOAD_FAILED", str(exc)) from exc
    finally:
        sys.path[:] = old_path
    try:
        adapter = value() if isinstance(value, type) else value
    except Exception as exc:
        raise OnboardingError("IDENTITY_ADAPTER_LOAD_FAILED", str(exc)) from exc
    required = ("inspect_identity", "ensure_identity", "validate_role", "validate_active")
    if any(not callable(getattr(adapter, name, None)) for name in required):
        raise OnboardingError("INVALID_IDENTITY_ADAPTER", "adapter must implement inspect_identity, ensure_identity, validate_role, validate_active")
    return adapter


def _run_command(command: tuple[str, ...], root: Path, *, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    if not command or any(not item or item.startswith("-") and index == 0 for index, item in enumerate(command)):
        raise OnboardingError("INVALID_ONBOARDING_COMMAND", "onboarding commands must be explicit executable arguments")
    try:
        return subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=timeout, check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OnboardingError("ONBOARDING_COMMAND_FAILED", str(exc)) from exc


def _command_identity_status(output: str, profile: Mapping[str, DevIdentityProfile]) -> dict[str, Any]:
    try:
        value = json.loads(output) if output.strip() else None
    except json.JSONDecodeError as exc:
        raise OnboardingError("IDENTITY_STATUS_UNVERIFIED", "identity bootstrap command must return JSON identity status") from exc
    if not isinstance(value, dict) or not isinstance(value.get("identities"), Mapping):
        raise OnboardingError("IDENTITY_STATUS_UNVERIFIED", "identity bootstrap output must contain identities")
    result: dict[str, Any] = {}
    for name, item in profile.items():
        state = value["identities"].get(item.account)
        if not isinstance(state, Mapping):
            result[name] = {"account": item.account, "status": "FAIL", "message": "identity missing from bootstrap result"}
            continue
        active = state.get("active") is True
        role = state.get("role") == item.role
        result[name] = {"account": item.account, "status": "PASS" if active and role else "FAIL", "active": active, "role": state.get("role"), "expected_role": item.role}
    return result


def _identity_checks(facts: ProjectFacts, manifest: ProjectManifest, *, execute: bool) -> dict[str, Any]:
    profile = _profile_from_manifest(manifest)
    if not profile:
        raise OnboardingError("DEV_PROFILE_REQUIRED", "no application-owned DEV identity profile is configured")
    onboarding = manifest.trusted_access.onboarding
    bootstrap = onboarding.identity_bootstrap if onboarding else None
    if bootstrap is None:
        return {name: {"account": item.account, "status": "BLOCKED", "message": "identity bootstrap adapter is not configured"} for name, item in profile.items()}
    if not execute:
        return {name: {"account": item.account, "status": "READY_TO_CHECK", "role": item.role} for name, item in profile.items()}
    if bootstrap.type == "command":
        assert bootstrap.command is not None
        completed = _run_command(bootstrap.command.command, facts.root)
        if completed.returncode != 0:
            raise OnboardingError("IDENTITY_BOOTSTRAP_FAILED", completed.stderr.strip() or f"command exited {completed.returncode}")
        return _command_identity_status(completed.stdout, profile)
    assert bootstrap.module is not None
    adapter = _load_adapter(bootstrap.module, facts.root)
    result: dict[str, Any] = {}
    for name, item in profile.items():
        try:
            state = adapter.inspect_identity(item.account)
            if state is None:
                adapter.ensure_identity(item.account, item.role, active=True, fallback_password="000000")
                state = adapter.inspect_identity(item.account)
            active = adapter.validate_active(item.account)
            role = adapter.validate_role(item.account, item.role)
        except Exception as exc:
            raise OnboardingError("IDENTITY_ADAPTER_FAILED", f"{name}: {exc}") from exc
        result[name] = {"account": item.account, "status": "PASS" if state is not None and active and role else "FAIL", "active": active, "role": item.role}
    return result


def _integration_checks(manifest: ProjectManifest) -> dict[str, Any]:
    config = manifest.trusted_access
    if not config.enabled or not is_dev_environment(config.environment or ""):
        raise OnboardingError("TRUSTED_ACCESS_NOT_DEV", "Trusted Access onboarding requires enabled DEV configuration")
    profile = _profile_from_manifest(manifest)
    if config.adapter is None:
        return {"status": "BLOCKED", "message": "application adapter is not configured"}
    missing = [item.principal for item in profile.values() if item.principal not in config.adapter.mappings]
    return {"status": "PASS" if not missing else "FAIL", "adapter": config.adapter.type, "missing_mappings": missing}


def _health_check(manifest: ProjectManifest, *, timeout: float = 1.0) -> bool:
    try:
        audience = next(iter(manifest.audiences.values()))
        request = Request(audience.base_url, method="GET")
        with urlopen(request, timeout=timeout):
            return True
    except (OSError, URLError):
        return False


def _start_application(manifest: ProjectManifest, facts: ProjectFacts) -> dict[str, Any]:
    """Reuse a healthy app or execute only an explicit project command.

    Discovery is informational.  A candidate filename is never executed as a
    startup command.  Explicit commands are expected to detach or otherwise
    return promptly; agentctl does not create a daemon or supervisor.
    """

    if _health_check(manifest):
        return {"status": "PASS", "action": "reused", "message": "DEV application is already reachable"}
    onboarding = manifest.trusted_access.onboarding
    if onboarding is None or onboarding.start is None:
        return {
            "status": "NOT_CONFIGURED",
            "action": "none",
            "message": "application is not reachable and no explicit onboarding.start command is configured",
            "candidates": list(facts.start_candidates),
        }
    completed = _run_command(onboarding.start.command, facts.root)
    if completed.returncode == 0:
        for _ in range(10):
            if _health_check(manifest, timeout=1.0):
                return {"status": "PASS", "action": "started", "command": list(onboarding.start.command)}
            time.sleep(0.2)
    if onboarding.restart is not None:
        completed = _run_command(onboarding.restart.command, facts.root)
        if completed.returncode == 0:
            for _ in range(10):
                if _health_check(manifest, timeout=1.0):
                    return {"status": "PASS", "action": "restarted", "command": list(onboarding.restart.command)}
                time.sleep(0.2)
    detail = completed.stderr.strip() or f"command exited {completed.returncode}"
    raise OnboardingError("DEV_START_FAILED", detail)


def _smoke(manifest: ProjectManifest, facts: ProjectFacts, *, execute: bool) -> dict[str, Any]:
    if not execute:
        return {"passed": None, "protocol": "READY_TO_RUN", "user_no_login": "READY_TO_RUN", "admin_no_login": "READY_TO_RUN", "agent_access": "READY_TO_RUN", "user_admin_denied": "READY_TO_RUN"}
    protocol = run_smoke_test(manifest)
    result: dict[str, Any] = {
        "passed": bool(protocol.get("passed")),
        "protocol": "PASS" if protocol.get("passed") else "FAIL",
        "user_no_login": "NOT_CONFIGURED",
        "admin_no_login": "NOT_CONFIGURED",
        "agent_access": "NOT_CONFIGURED",
        "user_admin_denied": "NOT_CONFIGURED",
        "application_smoke": "NOT_CONFIGURED",
    }
    onboarding = manifest.trusted_access.onboarding
    if onboarding and onboarding.smoke:
        completed = _run_command(onboarding.smoke.command, facts.root)
        result["application_smoke"] = "PASS" if completed.returncode == 0 else "FAIL"
        result["passed"] = result["passed"] and completed.returncode == 0
    return result


def build_onboarding_plan(path: str | Path = ".") -> OnboardingResult:
    facts = _detect_project(path)
    if facts.manifest:
        try:
            manifest = load_manifest(facts.manifest)
            value = _manifest_value(manifest)
            result = OnboardingResult(facts, manifest={"path": str(facts.manifest), "action": "reuse"})
            result.runtime = {"status": "inspect"}
            result.identities = {"status": "inspect", "count": len(_profile_from_manifest(manifest))}
            result.integration = {"status": "inspect", "configured": manifest.trusted_access.enabled}
            result.smoke = {"status": "ready_to_run"}
            result.manifest["trusted_access"] = {
                "enabled": manifest.trusted_access.enabled,
                "environment": manifest.trusted_access.environment,
                "transports": list(manifest.trusted_access.transports),
                "profile": _profile_mapping(_profile_from_manifest(manifest)),
            }
            result.manifest["onboarding"] = {
                "identity_bootstrap": bool(manifest.trusted_access.onboarding and manifest.trusted_access.onboarding.identity_bootstrap),
                "start": bool(manifest.trusted_access.onboarding and manifest.trusted_access.onboarding.start),
                "restart": bool(manifest.trusted_access.onboarding and manifest.trusted_access.onboarding.restart),
                "smoke": bool(manifest.trusted_access.onboarding and manifest.trusted_access.onboarding.smoke),
            }
            return result
        except (OSError, ValueError, TrustedAccessError) as exc:
            raise OnboardingError("INVALID_MANIFEST", str(exc)) from exc
    return OnboardingResult(
        facts,
        manifest={"path": str(facts.root / ".agent-control.yaml"), "action": "create", "value": _fresh_manifest(facts)},
        runtime={"status": "bootstrap"},
        identities={name: {"account": item.account, "status": "adapter_required"} for name, item in DEFAULT_DEV_PROFILE.items()},
        integration={"status": "scaffold_required"},
        smoke={"status": "after_integration"},
    )


def onboard(path: str | Path = ".", *, runtime_dir: str | Path | None = None, plan: bool = False) -> dict[str, Any]:
    facts = _detect_project(path)
    manifest_path = facts.manifest or facts.root / ".agent-control.yaml"
    created_manifest = False
    if facts.manifest is None:
        value = _fresh_manifest(facts)
        if not plan:
            _write_manifest(manifest_path, value)
            created_manifest = True
            # Refresh the facts after creating the manifest so the result
            # reflects the effective DEV policy rather than the pre-onboard
            # project state.
            facts = _detect_project(path)
            manifest = load_manifest(manifest_path) if not plan else None
    else:
        try:
            manifest = load_manifest(manifest_path)
        except (OSError, ValueError, TrustedAccessError) as exc:
            raise OnboardingError("INVALID_MANIFEST", str(exc)) from exc
        value = _manifest_value(manifest)

    if plan:
        result = build_onboarding_plan(path)
        result.manifest["created"] = False
        result.manifest["runtime_dir"] = str(TrustedAccessRuntimePaths.from_dir(runtime_dir).root)
        return result.to_dict()

    assert manifest is not None
    trusted_value = value.setdefault("trusted_access", {})
    changed = False
    if manifest.trusted_access.enabled and "dev_profile" not in trusted_value:
        profile = _profile_from_manifest(manifest) or DEFAULT_DEV_PROFILE
        trusted_value["dev_profile"] = _profile_mapping(profile)
        changed = True
    if manifest.trusted_access.enabled and manifest.trusted_access.adapter is None:
        profile = _profile_from_manifest(manifest)
        if profile:
            trusted_value["adapter"] = {"type": "declarative_mapping", "mappings": {item.principal: item.account for item in profile.values()}}
            changed = True
    if changed:
        _write_manifest(manifest_path, value)
        manifest = load_manifest(manifest_path)

    runtime = TrustedAccessRuntime(TrustedAccessRuntimePaths.from_dir(runtime_dir))
    runtime_status = runtime.status(manifest)
    if not runtime_status.get("runtime_ready"):
        runtime_result = runtime.bootstrap(manifest)
    else:
        runtime_result = runtime_status
    integration = _integration_checks(manifest)
    if integration.get("status") != "PASS":
        raise OnboardingError("APPLICATION_ADAPTER_REQUIRED", str(integration))
    # A consumer may keep identity state in a datastore that is initialized by
    # its explicitly declared DEV start command. Reuse a healthy process or
    # start that command before asking the application adapter to inspect it.
    startup = _start_application(manifest, facts)
    identities = _identity_checks(facts, manifest, execute=True)
    identity_failures = [item for item in identities.values() if item.get("status") != "PASS"]
    if identity_failures:
        raise OnboardingError("IDENTITY_VALIDATION_FAILED", "one or more mapped DEV identities are missing, inactive, or have the wrong role")
    smoke = _smoke(manifest, facts, execute=True)
    if smoke.get("protocol") == "FAIL" or smoke.get("application_smoke") == "FAIL":
        raise OnboardingError("SMOKE_FAILED", "Trusted Access smoke failed")
    return OnboardingResult(
        facts=facts,
        ready=True,
        manifest={"path": str(manifest_path), "created": created_manifest, "updated": changed},
        runtime={"status": "PASS", **runtime_result},
        identities=identities,
        integration=integration,
        smoke={"startup": startup, **smoke},
    ).to_dict()


def format_onboarding(result: Mapping[str, Any]) -> str:
    project = result.get("project", {})
    runtime = result.get("runtime", {})
    identities = result.get("identities", {})
    integration = result.get("integration", {})
    smoke = result.get("smoke", {})
    trusted_access = result.get("manifest", {}).get("trusted_access", {}) if isinstance(result.get("manifest"), Mapping) else {}
    transports = trusted_access.get("transports", []) if isinstance(trusted_access, Mapping) else []
    startup = smoke.get("startup", {}) if isinstance(smoke, Mapping) else {}
    lines = [
        "Trusted Access onboarding",
        f"Project ................. {project.get('framework', 'unknown')}",
        f"Environment ............. {str(result.get('DEV_ENVIRONMENT', 'unknown')).upper()}",
        f"Transport ............... {', '.join(transports) if transports else 'manifest-defined'}",
        f"Runtime ................. {'ready' if runtime.get('status') == 'PASS' or runtime.get('runtime_ready') else runtime.get('status', 'inspect')}",
    ]
    identity_states = [item.get("status") for item in identities.values() if isinstance(item, Mapping)]
    identity_ready = bool(identity_states) and all(status == "PASS" for status in identity_states)
    lines.extend([
        f"DEV identities .......... {'ready' if identity_ready else 'blocked'}",
        f"Integration ............. {'ready' if integration.get('status') == 'PASS' else integration.get('status', 'inspect')}",
        f"Smoke ................... {smoke.get('protocol', smoke.get('status', 'inspect'))}",
        f"TRUSTED_ACCESS_READY={'YES' if result.get('ready') else 'NO'}",
    ])
    if result.get("blocker"):
        lines.append(f"BLOCKER={result['blocker'].get('code', 'ONBOARDING_FAILED')}")
    return "\n".join(lines)
