from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from agentctl.cli import main
from agentctl.identity import load_identity
from agentctl.manifest import load_manifest
from agentctl.registry import load_registry
from agentctl.runtime import TrustedAccessRuntime, TrustedAccessRuntimePaths
from agentctl.trusted import LocalhostTransportVerifier, TransportObservation, TrustedAccessAuthority, TrustedAccessError, TrustedIdentityVerifier
from agentctl.replay import MemoryReplayStore
from agentctl.audit import verify_audit_file


def _init(tmp_path: Path, capsys) -> Path:
    assert main(["trusted-access", "init", "--path", str(tmp_path)]) == 0
    capsys.readouterr()
    return tmp_path / ".agent-control.yaml"


def _runtime(tmp_path: Path) -> TrustedAccessRuntime:
    return TrustedAccessRuntime(
        TrustedAccessRuntimePaths.from_dir(tmp_path / "runtime"),
        tailscale_socket=str(tmp_path / "tailscaled.sock"),
    )


def test_runtime_bootstrap_is_idempotent_private_and_machine_readable(tmp_path: Path, capsys) -> None:
    manifest = _init(tmp_path, capsys)
    runtime_dir = tmp_path / "runtime"
    first = main([
        "trusted-access", "bootstrap", "--manifest", str(manifest),
        "--runtime-dir", str(runtime_dir), "--tailscale-socket", str(tmp_path / "tailscaled.sock"), "--json",
    ])
    assert first == 0
    first_output = json.loads(capsys.readouterr().out)
    assert first_output["result"] == "CREATED"
    assert first_output["runtime_ready"] is True
    assert "private_key" not in first_output
    assert {"authority_id", "registry_path", "replay_store_path", "audit_path", "tailscale_socket", "environment"} <= first_output.keys()

    identity_before = load_identity(runtime_dir / "authority.json")
    registry_before = (runtime_dir / "registry.json").read_bytes()
    second = main([
        "trusted-access", "bootstrap", "--manifest", str(manifest),
        "--runtime-dir", str(runtime_dir), "--tailscale-socket", str(tmp_path / "tailscaled.sock"), "--json",
    ])
    assert second == 0
    second_output = json.loads(capsys.readouterr().out)
    assert second_output["result"] == "REUSED"
    assert load_identity(runtime_dir / "authority.json").public_key_bytes == identity_before.public_key_bytes
    assert (runtime_dir / "registry.json").read_bytes() == registry_before
    assert stat.S_IMODE(runtime_dir.stat().st_mode) & 0o077 == 0
    for path in runtime_dir.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, path
    assert "private_key" not in (runtime_dir / "runtime.json").read_text(encoding="utf-8")


def test_runtime_issue_and_verifier_consume_canonical_runtime_state(tmp_path: Path, capsys) -> None:
    manifest_path = _init(tmp_path, capsys)
    runtime_dir = tmp_path / "runtime"
    socket_path = tmp_path / "tailscaled.sock"
    assert main([
        "trusted-access", "bootstrap", "--manifest", str(manifest_path),
        "--runtime-dir", str(runtime_dir), "--tailscale-socket", str(socket_path),
    ]) == 0
    capsys.readouterr()

    assert main([
        "trusted-access", "issue", "--manifest", str(manifest_path),
        "--runtime-dir", str(runtime_dir), "--principal", "agent", "--scope", "app:test",
        "--now", "1700000000", "--json",
    ]) == 0
    issued = json.loads(capsys.readouterr().out)
    assertion = issued["assertion"]

    manifest = load_manifest(manifest_path)
    runtime = TrustedAccessRuntime(TrustedAccessRuntimePaths.from_dir(runtime_dir), tailscale_socket=str(socket_path))
    identity, registry, _principal, _key = runtime.load_identity_registry(manifest)
    audience = next(iter(manifest.audiences.values())).audience
    verifier = TrustedIdentityVerifier(
        registry,
        manifest.trusted_access,
        runtime.replay_store(),
        expected_audience=audience,
        audit_sink=runtime.audit_sink(),
        transport_verifiers={"localhost": LocalhostTransportVerifier()},
    )
    del identity
    evidence = verifier.verify(
        assertion,
        observation=TransportObservation("localhost", "127.0.0.1"),
        now=1700000001,
    )
    assert evidence.subject == "dev-agent"
    with pytest.raises(TrustedAccessError, match="already been consumed"):
        verifier.verify(
            assertion,
            observation=TransportObservation("localhost", "127.0.0.1"),
            now=1700000001,
        )
    assert verify_audit_file(runtime.paths.audit)[0] is True


def test_runtime_rejects_unsafe_permissions_when_loaded_by_consumer(tmp_path: Path, capsys) -> None:
    manifest_path = _init(tmp_path, capsys)
    runtime = _runtime(tmp_path)
    manifest = load_manifest(manifest_path)
    runtime.bootstrap(manifest)
    runtime.paths.registry.chmod(0o644)
    status = runtime.status(manifest)
    assert status["runtime_ready"] is False
    assert status["result_code"] == "RUNTIME_PERMISSIONS_UNSAFE"


def test_runtime_rejects_symlinked_runtime_directory(tmp_path: Path, capsys) -> None:
    manifest_path = _init(tmp_path, capsys)
    real = tmp_path / "real-runtime"
    real.mkdir()
    link = tmp_path / "runtime"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(TrustedAccessError) as raised:
        TrustedAccessRuntime(
            TrustedAccessRuntimePaths.from_dir(link),
            tailscale_socket=str(tmp_path / "tailscaled.sock"),
        ).bootstrap(load_manifest(manifest_path))
    assert raised.value.code == "RUNTIME_PATH_INVALID"


def test_runtime_preserves_saved_socket_for_new_process(tmp_path: Path, capsys) -> None:
    manifest_path = _init(tmp_path, capsys)
    manifest = load_manifest(manifest_path)
    runtime_dir = tmp_path / "runtime"
    saved_socket = tmp_path / "saved.sock"
    TrustedAccessRuntime(
        TrustedAccessRuntimePaths.from_dir(runtime_dir),
        tailscale_socket=str(saved_socket),
    ).bootstrap(manifest)
    capsys.readouterr()
    result = TrustedAccessRuntime(TrustedAccessRuntimePaths.from_dir(runtime_dir)).bootstrap(manifest)
    assert result["tailscale_socket"] == str(saved_socket)


def test_runtime_missing_registry_is_recovered_without_replacing_identity(tmp_path: Path, capsys) -> None:
    manifest = _init(tmp_path, capsys)
    runtime = _runtime(tmp_path)
    runtime.bootstrap(load_manifest(manifest))
    identity = load_identity(runtime.paths.identity)
    runtime.paths.registry.unlink()
    result = runtime.bootstrap(load_manifest(manifest))
    assert result["result"] == "RECOVERED"
    assert load_identity(runtime.paths.identity).public_key_bytes == identity.public_key_bytes
    assert load_registry(runtime.paths.registry).keys[identity.key_id].public_key == identity.public_record()["public_key"]


def test_runtime_invalid_identity_and_incomplete_state_fail_closed(tmp_path: Path, capsys) -> None:
    manifest = _init(tmp_path, capsys)
    runtime = _runtime(tmp_path)
    loaded = load_manifest(manifest)
    runtime.bootstrap(loaded)
    value = json.loads(runtime.paths.identity.read_text(encoding="utf-8"))
    value["private_key"] = "A" * 43
    runtime.paths.identity.write_text(json.dumps(value), encoding="utf-8")
    assert main([
        "trusted-access", "bootstrap", "--manifest", str(manifest), "--runtime-dir", str(runtime.paths.root), "--json",
    ]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["result_code"] == "RUNTIME_IDENTITY_INVALID"
    assert "private_key" not in output

    runtime.paths.identity.unlink()
    assert main([
        "trusted-access", "bootstrap", "--manifest", str(manifest), "--runtime-dir", str(runtime.paths.root), "--json",
    ]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["result_code"] == "RUNTIME_STATE_INCOMPLETE"


def test_rotation_preserves_previous_key_until_normal_expiry(tmp_path: Path, capsys) -> None:
    manifest_path = _init(tmp_path, capsys)
    manifest = load_manifest(manifest_path)
    runtime = _runtime(tmp_path)
    runtime.bootstrap(manifest)
    old_identity = load_identity(runtime.paths.identity)
    old_registry = load_registry(runtime.paths.registry)
    authority = TrustedAccessAuthority(old_identity, old_registry, manifest.trusted_access, transport_verifiers={"localhost": LocalhostTransportVerifier()})
    audience = next(iter(manifest.audiences.values())).audience
    assertion = authority.issue(
        requested_principal="agent", audience=audience, scopes=["app:read"],
        observation=TransportObservation("localhost", "127.0.0.1"), now=1_700_000_000,
    )
    rotated = runtime.rotate_authority(manifest)
    assert rotated["previous_key_preserved"] is True
    new_identity = load_identity(runtime.paths.identity)
    registry = load_registry(runtime.paths.registry)
    assert new_identity.key_id != old_identity.key_id
    assert old_identity.key_id in registry.keys
    assert registry.keys[old_identity.key_id].enabled is True
    verifier = TrustedIdentityVerifier(
        registry, manifest.trusted_access, MemoryReplayStore(), expected_audience=audience,
        transport_verifiers={"localhost": LocalhostTransportVerifier()},
    )
    assert verifier.verify(assertion, observation=TransportObservation("localhost", "127.0.0.1"), now=1_700_000_001).subject == "dev-agent"
    capsys.readouterr()


def test_revoke_current_authority_is_explicit_and_bootstrap_does_not_restore_it(tmp_path: Path, capsys) -> None:
    manifest_path = _init(tmp_path, capsys)
    manifest = load_manifest(manifest_path)
    runtime = _runtime(tmp_path)
    runtime.bootstrap(manifest)
    revoked = runtime.revoke_authority(manifest)
    assert revoked["result"] == "REVOKED"
    status = runtime.status(manifest)
    assert status["runtime_ready"] is False
    with pytest.raises(TrustedAccessError, match="disabled or revoked"):
        runtime.bootstrap(manifest)
    capsys.readouterr()

    rotated = runtime.rotate_authority(manifest)
    assert rotated["authority_key_id"] != revoked["revoked_key_id"]
    assert runtime.status(manifest)["runtime_ready"] is True


def test_runtime_doctor_reports_missing_tailscale_and_invalid_metadata(tmp_path: Path, capsys) -> None:
    manifest_path = _init(tmp_path, capsys)
    runtime_dir = tmp_path / "runtime"
    socket_path = tmp_path / "missing.sock"
    assert main([
        "trusted-access", "bootstrap", "--manifest", str(manifest_path), "--runtime-dir", str(runtime_dir),
        "--tailscale-socket", str(socket_path), "--json",
    ]) == 0
    capsys.readouterr()
    assert main([
        "trusted-access", "doctor", "--manifest", str(manifest_path), "--runtime-dir", str(runtime_dir),
        "--tailscale-socket", str(socket_path), "--json",
    ]) == 1
    output = json.loads(capsys.readouterr().out)
    checks = {item["name"]: item for item in output["checks"]}
    assert checks["tailscale_localapi"]["status"] == "FAIL"

    (runtime_dir / "runtime.json").write_text("{}", encoding="utf-8")
    assert main([
        "trusted-access", "status", "--manifest", str(manifest_path), "--runtime-dir", str(runtime_dir), "--json",
    ]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["result_code"] == "RUNTIME_METADATA_INVALID"


def test_runtime_bootstrap_rejects_disabled_or_production_policy(tmp_path: Path) -> None:
    base = """\
project: runtime-test
audiences:
  dev:
    base_url: http://127.0.0.1:8000
    audience: runtime-test-dev
actions:
  health:
    method: GET
    path: /
    scope: app:read
trusted_access:
  enabled: {enabled}
  environment: {environment}
  transports: [localhost]
  principals:
    agent:
      subject: dev-agent
      type: agent
      scopes: [app:read]
"""
    for enabled, environment, code in (("false", "dev", "TRUSTED_ACCESS_DISABLED"), ("true", "production", "TRUSTED_ACCESS_NOT_DEV")):
        path = tmp_path / f"{enabled}-{environment}.yaml"
        path.write_text(base.format(enabled=enabled, environment=environment), encoding="utf-8")
        if code == "TRUSTED_ACCESS_NOT_DEV":
            with pytest.raises(TrustedAccessError) as raised:
                load_manifest(path)
            assert raised.value.code == code
        else:
            manifest = load_manifest(path)
            with pytest.raises(TrustedAccessError) as raised:
                TrustedAccessRuntime(TrustedAccessRuntimePaths.from_dir(tmp_path / f"runtime-{enabled}")).bootstrap(manifest)
            assert raised.value.code == code
