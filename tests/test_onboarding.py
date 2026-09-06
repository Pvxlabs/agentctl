from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
import yaml

import agentctl.onboarding as onboarding
from agentctl.cli import main
from agentctl.manifest import load_manifest
from agentctl.trusted import TrustedAccessError


def _project(tmp_path: Path, *, kind: str = "python") -> Path:
    root = tmp_path / "project"
    root.mkdir(parents=True)
    (root / ".git").mkdir()
    if kind == "python":
        (root / "pyproject.toml").write_text('[project]\nname = "fixture"\ndependencies = ["fastapi"]\n', encoding="utf-8")
        (root / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    else:
        (root / "package.json").write_text(json.dumps({"dependencies": {"express": "^5"}}), encoding="utf-8")
        (root / "tsconfig.json").write_text("{}", encoding="utf-8")
        (root / "src").mkdir()
        (root / "src" / "server.ts").write_text("export {}\n", encoding="utf-8")
    return root


def _manifest_value(*, environment: str = "dev", onboarding: dict | None = None) -> dict:
    value = {
        "project": "fixture",
        "audiences": {"dev": {"base_url": "http://127.0.0.1:65530", "audience": "fixture-dev"}},
        "actions": {"health.read": {"method": "GET", "path": "/", "scope": "app:read", "audience": "dev"}},
        "trusted_access": {
            "enabled": True,
            "environment": environment,
            "transports": ["localhost"],
            "application": {"identity": "fixture", "audience": "fixture-dev"},
            "adapter": {"type": "declarative_mapping", "mappings": {"dev-user": "fixture-user", "dev-admin": "fixture-admin", "dev-agent": "fixture-agent"}},
            "principals": {
                "user": {"subject": "dev-user", "type": "human", "scopes": ["app:read"]},
                "admin": {"subject": "dev-admin", "type": "human", "scopes": ["app:read", "app:admin"]},
                "agent": {"subject": "dev-agent", "type": "agent", "scopes": ["app:read", "app:test"]},
            },
            "dev_profile": {
                "user": {"principal": "dev-user", "account": "fixture-user", "role": "user"},
                "admin": {"principal": "dev-admin", "account": "fixture-admin", "role": "admin"},
                "agent": {"principal": "dev-agent", "account": "fixture-agent", "role": "user"},
            },
        },
    }
    if onboarding is not None:
        value["trusted_access"]["onboarding"] = onboarding
    return value


def _write_manifest(root: Path, value: dict) -> Path:
    path = root / ".agent-control.yaml"
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    return path


def test_project_detection_supports_fastapi_and_express_typescript(tmp_path: Path) -> None:
    python_root = _project(tmp_path / "python", kind="python")
    facts = onboarding._detect_project(python_root)
    assert facts.language == "python"
    assert facts.framework == "fastapi"
    assert facts.entrypoint == "main.py"

    node_root = _project(tmp_path / "node", kind="node")
    facts = onboarding._detect_project(node_root)
    assert facts.language == "typescript"
    assert facts.framework == "express"
    assert facts.entrypoint == "src/server.ts"


def test_fresh_plan_is_read_only_and_contains_canonical_profile(tmp_path: Path) -> None:
    root = _project(tmp_path)
    before = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
    result = onboarding.build_onboarding_plan(root).to_dict()
    after = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())

    assert before == after
    assert result["manifest"]["action"] == "create"
    profile = result["manifest"]["value"]["trusted_access"]["dev_profile"]
    assert profile["user"]["account"] == "user@test.local"
    assert profile["admin"]["principal"] == "dev-admin"
    assert result["ready"] is False


def test_fresh_manifest_wires_only_explicit_application_adapter_convention(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / "agentctl_trusted_access_adapter.py").write_text("adapter = object()\n", encoding="utf-8")

    result = onboarding.build_onboarding_plan(root).to_dict()

    assert result["manifest"]["value"]["trusted_access"]["onboarding"] == {
        "identity_bootstrap": {
            "type": "adapter",
            "module": "agentctl_trusted_access_adapter:adapter",
        }
    }


def test_fresh_plan_declares_generated_identity_bootstrap_scaffold(tmp_path: Path) -> None:
    root = _project(tmp_path)

    result = onboarding.build_onboarding_plan(root).to_dict()

    assert result["manifest"]["value"]["trusted_access"]["onboarding"] == {
        "identity_bootstrap": {
            "type": "adapter",
            "module": "agentctl_trusted_access_adapter:adapter",
        }
    }
    assert "create agentctl_trusted_access_adapter.py" in result["changes"]


def test_onboard_uses_explicit_adapter_and_reports_effective_dev_state(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / "agentctl_trusted_access_adapter.py").write_text(
        """
class Adapter:
    states = {}
    def inspect_identity(self, account): return self.states.get(account)
    def ensure_identity(self, account, role, **_kwargs): self.states[account] = {"active": True, "role": role}
    def validate_role(self, account, role): return self.states.get(account, {}).get("role") == role
    def validate_active(self, account): return self.states.get(account, {}).get("active") is True
adapter = Adapter()
""",
        encoding="utf-8",
    )

    result = onboarding.onboard(root, runtime_dir=tmp_path / "runtime")

    assert result["ready"] is True
    assert result["DEV_ENVIRONMENT"] == "dev"
    assert all(item["status"] == "PASS" for item in result["identities"].values())


def test_fresh_onboard_generates_adapter_and_second_run_has_no_changes(tmp_path: Path) -> None:
    root = _project(tmp_path)
    runtime_dir = tmp_path / "runtime"

    first = onboarding.onboard(root, runtime_dir=runtime_dir)
    second = onboarding.onboard(root, runtime_dir=runtime_dir)

    assert first["ready"] is True
    assert (root / "agentctl_trusted_access_adapter.py").is_file()
    assert (root / ".agentctl" / "trusted-access-identities.json").is_file()
    assert second["ready"] is True
    assert second["changes"] == []
    assert not list(root.glob("__pycache__/*"))


def test_existing_manifest_is_not_overwritten_by_plan(tmp_path: Path) -> None:
    root = _project(tmp_path)
    path = _write_manifest(root, _manifest_value())
    original = path.read_bytes()
    result = onboarding.build_onboarding_plan(root).to_dict()

    assert path.read_bytes() == original
    assert result["manifest"]["action"] == "reuse"
    assert result["manifest"]["trusted_access"]["profile"]["admin"]["account"] == "fixture-admin"


def test_cli_plan_returns_json_with_stable_fields(tmp_path: Path, capsys) -> None:
    root = _project(tmp_path)
    assert main(["trusted-access", "onboard", "--path", str(root), "--plan", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert {"ready", "PROJECT_ROOT", "LANGUAGE", "FRAMEWORK", "DEV_ENVIRONMENT", "EXISTING_INTEGRATION", "BOOTSTRAP_STRATEGY", "START_STRATEGY", "blocker"} <= result.keys()
    assert result["PROJECT_ROOT"] == str(root.resolve())


def test_adapter_bootstrap_repairs_missing_identity(monkeypatch, tmp_path: Path) -> None:
    root = _project(tmp_path)
    path = _write_manifest(root, _manifest_value(onboarding={"identity_bootstrap": {"type": "adapter", "module": "fixture:adapter"}}))
    manifest = load_manifest(path)
    calls: list[tuple[str, str]] = []

    class Adapter:
        states: dict[str, dict] = {}

        def inspect_identity(self, account: str):
            return self.states.get(account)

        def ensure_identity(self, account: str, role: str, **_kwargs):
            calls.append((account, role))
            self.states[account] = {"active": True, "role": role}

        def validate_role(self, account: str, role: str) -> bool:
            return self.states.get(account, {}).get("role") == role

        def validate_active(self, account: str) -> bool:
            return self.states.get(account, {}).get("active") is True

    adapter = Adapter()
    monkeypatch.setattr(onboarding, "_load_adapter", lambda _spec, _root: adapter)
    result = onboarding._identity_checks(onboarding._detect_project(root), manifest, execute=True)
    assert all(item["status"] == "PASS" for item in result.values())
    assert calls == [("fixture-user", "user"), ("fixture-admin", "admin"), ("fixture-agent", "user")]


@pytest.mark.parametrize(
    ("stdout", "returncode", "code"),
    [("not-json", 0, "IDENTITY_STATUS_UNVERIFIED"), ("{}", 0, "IDENTITY_STATUS_UNVERIFIED"), ("", 1, "IDENTITY_BOOTSTRAP_FAILED")],
)
def test_command_identity_bootstrap_requires_verified_json(monkeypatch, tmp_path: Path, stdout: str, returncode: int, code: str) -> None:
    root = _project(tmp_path)
    path = _write_manifest(root, _manifest_value(onboarding={"identity_bootstrap": {"type": "command", "command": ["fixture-bootstrap"]}}))
    manifest = load_manifest(path)
    completed = subprocess.CompletedProcess(["fixture-bootstrap"], returncode, stdout=stdout, stderr="bootstrap failed")
    monkeypatch.setattr(onboarding, "_run_command", lambda *_args, **_kwargs: completed)
    with pytest.raises(onboarding.OnboardingError) as raised:
        onboarding._identity_checks(onboarding._detect_project(root), manifest, execute=True)
    assert raised.value.code == code


def test_identity_role_or_active_mismatch_fails_closed(monkeypatch, tmp_path: Path) -> None:
    root = _project(tmp_path)
    path = _write_manifest(root, _manifest_value(onboarding={"identity_bootstrap": {"type": "adapter", "module": "fixture:adapter"}}))
    manifest = load_manifest(path)

    class Adapter:
        def inspect_identity(self, _account):
            return {"active": True, "role": "user"}

        def ensure_identity(self, *_args, **_kwargs):
            raise AssertionError("existing identity should not be bootstrapped")

        def validate_role(self, _account, role):
            return role == "user"

        def validate_active(self, _account):
            return True

    monkeypatch.setattr(onboarding, "_load_adapter", lambda _spec, _root: Adapter())
    result = onboarding._identity_checks(onboarding._detect_project(root), manifest, execute=True)
    assert result["admin"]["status"] == "FAIL"


@pytest.mark.parametrize(
    "value",
    [
        {"enabled": True, "environment": "production", "transports": ["localhost"], "principals": {"agent": {"subject": "dev-agent", "scopes": ["app:test"]}}},
        {"enabled": True, "transports": ["localhost"], "principals": {"agent": {"subject": "dev-agent", "scopes": ["app:test"]}}},
        {"enabled": True, "environment": ["dev"], "transports": ["localhost"], "principals": {"agent": {"subject": "dev-agent", "scopes": ["app:test"]}}},
    ],
)
def test_production_missing_or_ambiguous_environment_fails_closed(value: dict) -> None:
    with pytest.raises(TrustedAccessError):
        from agentctl.trusted import TrustedAccessConfig

        TrustedAccessConfig.from_mapping(value)


@pytest.mark.parametrize(
    "bootstrap",
    [
        {"type": "command", "command": ["bootstrap"], "module": "fixture:adapter"},
        {"type": "adapter", "module": "fixture:adapter", "command": ["bootstrap"]},
    ],
)
def test_identity_bootstrap_contract_is_unambiguous(bootstrap: dict) -> None:
    with pytest.raises(TrustedAccessError):
        from agentctl.trusted import TrustedAccessConfig

        TrustedAccessConfig.from_mapping({"enabled": True, "environment": "dev", "transports": ["localhost"], "principals": {"agent": {"subject": "dev-agent", "scopes": ["app:test"]}}, "onboarding": {"identity_bootstrap": bootstrap}})


def test_onboarding_commands_never_use_shell(monkeypatch, tmp_path: Path) -> None:
    root = _project(tmp_path)
    observed: dict = {}

    def fake_run(*args, **kwargs):
        observed["args"] = args
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(args[0], 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    onboarding._run_command(("python", "-c", "pass"), root)
    assert observed["args"][0] == ("python", "-c", "pass")
    assert observed["kwargs"]["shell"] is False
    assert observed["kwargs"]["cwd"] == root


def test_start_reuses_healthy_application_without_running_command(monkeypatch, tmp_path: Path) -> None:
    root = _project(tmp_path)
    path = _write_manifest(root, _manifest_value(onboarding={"start": {"command": ["should-not-run"]}}))
    manifest = load_manifest(path)
    called = False

    def run_command(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("healthy application must be reused")

    monkeypatch.setattr(onboarding, "_health_check", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(onboarding, "_run_command", run_command)
    result = onboarding._start_application(manifest, onboarding._detect_project(root))
    assert result["action"] == "reused"
    assert called is False


def test_start_failure_can_use_explicit_restart_and_reports_stable_result(monkeypatch, tmp_path: Path) -> None:
    root = _project(tmp_path)
    path = _write_manifest(root, _manifest_value(onboarding={"start": {"command": ["start"]}, "restart": {"command": ["restart"]}}))
    manifest = load_manifest(path)
    health = iter([False, True])
    commands: list[tuple[str, ...]] = []

    monkeypatch.setattr(onboarding, "_health_check", lambda *_args, **_kwargs: next(health))
    monkeypatch.setattr(onboarding, "time", type("Clock", (), {"sleep": staticmethod(lambda _seconds: None)}))

    def run_command(command, *_args, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 1 if command == ("start",) else 0, stdout="", stderr="start failed" if command == ("start",) else "")

    monkeypatch.setattr(onboarding, "_run_command", run_command)
    result = onboarding._start_application(manifest, onboarding._detect_project(root))
    assert result["action"] == "restarted"
    assert commands == [("start",), ("restart",)]
