from __future__ import annotations

import json
import socket
from pathlib import Path

from agentctl.cli import main


def test_trusted_access_init_uses_generic_adapter_placeholders(tmp_path: Path, capsys) -> None:
    assert main(["trusted-access", "init", "--path", str(tmp_path)]) == 0
    manifest = (tmp_path / ".agent-control.yaml").read_text(encoding="utf-8")
    assert "user@test.local" not in manifest
    assert "admin@test.local" not in manifest
    assert "app-dev-user" in manifest
    output = json.loads(capsys.readouterr().out)
    assert output["state_created"] is True


def test_trusted_access_init_does_not_overwrite_partial_state(tmp_path: Path, capsys) -> None:
    state = tmp_path / ".agentctl"
    state.mkdir()
    (state / "dev-authority.json").write_text("{}", encoding="utf-8")
    assert main(["trusted-access", "init", "--path", str(tmp_path)]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["result_code"] == "CLI_ERROR"
    assert not (tmp_path / ".agent-control.yaml").exists()


def _init_project(tmp_path: Path, capsys) -> tuple[Path, Path, Path]:
    assert main(["trusted-access", "init", "--path", str(tmp_path)]) == 0
    capsys.readouterr()
    return (
        tmp_path / ".agent-control.yaml",
        tmp_path / ".agentctl" / "dev-authority.json",
        tmp_path / ".agentctl" / "registry.json",
    )


def test_trusted_access_issue_mints_local_assertion_without_echoing_token_for_file_output(tmp_path: Path, capsys) -> None:
    manifest, identity, registry = _init_project(tmp_path, capsys)
    assertion_file = tmp_path / ".agentctl" / "assertion.txt"
    assert main([
        "trusted-access", "issue",
        "--manifest", str(manifest),
        "--identity-file", str(identity),
        "--registry-file", str(registry),
        "--principal", "agent",
        "--scope", "app:test",
        "--now", "1700000000",
        "--out", str(assertion_file),
    ]) == 0
    output = json.loads(capsys.readouterr().out)
    token = assertion_file.read_text(encoding="utf-8").strip()
    assert output["assertion_file"] == str(assertion_file.resolve())
    assert "assertion" not in output
    assert output["subject"] == "dev-agent"
    assert token.startswith("agentctl-tdi1.")


def test_trusted_access_issue_rejects_unknown_principal_and_scope_escalation(tmp_path: Path, capsys) -> None:
    manifest, identity, registry = _init_project(tmp_path, capsys)
    common = [
        "trusted-access", "issue",
        "--manifest", str(manifest),
        "--identity-file", str(identity),
        "--registry-file", str(registry),
        "--now", "1700000000",
    ]
    assert main([*common, "--principal", "unknown", "--scope", "app:read"]) == 2
    assert json.loads(capsys.readouterr().out)["result_code"] == "UNKNOWN_TRUSTED_PRINCIPAL"
    assert main([*common, "--principal", "agent", "--scope", "app:admin"]) == 2
    assert json.loads(capsys.readouterr().out)["result_code"] == "SCOPE_DENIED"


def test_trusted_access_issue_rejects_production_manifest(tmp_path: Path, capsys) -> None:
    manifest, identity, registry = _init_project(tmp_path, capsys)
    manifest.write_text(manifest.read_text(encoding="utf-8").replace("environment: dev", "environment: production"), encoding="utf-8")
    assert main([
        "trusted-access", "issue",
        "--manifest", str(manifest),
        "--identity-file", str(identity),
        "--registry-file", str(registry),
        "--principal", "agent",
        "--scope", "app:test",
        "--now", "1700000000",
    ]) == 2
    assert json.loads(capsys.readouterr().out)["result_code"] == "TRUSTED_ACCESS_NOT_DEV"


def test_trusted_access_doctor_requires_reachable_tailscale_localapi(tmp_path: Path, capsys) -> None:
    manifest, identity, registry = _init_project(tmp_path, capsys)
    socket_path = tmp_path / "tailscaled.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    server.listen(1)
    try:
        assert main([
            "trusted-access", "doctor",
            "--manifest", str(manifest),
            "--identity-file", str(identity),
            "--registry-file", str(registry),
            "--tailscale-socket", str(socket_path),
        ]) == 0
        output = json.loads(capsys.readouterr().out)
        checks = {check["name"]: check for check in output["checks"]}
        assert checks["tailscale_localapi"]["status"] == "PASS"
    finally:
        server.close()


def test_trusted_access_doctor_fails_when_tailscale_localapi_is_missing(tmp_path: Path, capsys) -> None:
    manifest, identity, registry = _init_project(tmp_path, capsys)
    missing = tmp_path / "missing-tailscaled.sock"
    assert main([
        "trusted-access", "doctor",
        "--manifest", str(manifest),
        "--identity-file", str(identity),
        "--registry-file", str(registry),
        "--tailscale-socket", str(missing),
    ]) == 1
    output = json.loads(capsys.readouterr().out)
    checks = {check["name"]: check for check in output["checks"]}
    assert checks["tailscale_localapi"]["status"] == "FAIL"
