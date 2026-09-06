from __future__ import annotations

import json
from pathlib import Path

import pytest

import agentctl.distribution as distribution
from agentctl.cli import main


def test_version_contract_is_self_consistent() -> None:
    contract = distribution.version_contract()
    assert contract["canonical_release"] == f"v{contract['installed_version']}"
    assert contract["agentctl_min_version"] == contract["installed_version"]
    assert distribution.is_compatible(contract["installed_version"])
    assert not distribution.is_compatible("0.1.0", contract["agentctl_min_version"])
    assert distribution.is_compatible("9.0.0", contract["agentctl_min_version"])


def test_cli_version_includes_compatibility_contract(capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["--version"])
    assert raised.value.code == 0
    output = capsys.readouterr().out
    assert "agentctl 0.1.1" in output
    assert "trusted-access-onboarding 1.1" in output


def test_skill_install_is_user_local_atomic_and_idempotent(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    content = b"---\nname: agentctl\n---\nCanonical skill\n"

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return content

    monkeypatch.setattr(distribution, "urlopen", lambda *_args, **_kwargs: Response())
    first = distribution.install_skill(update=True)
    second = distribution.install_skill(update=True)
    assert first["installed"] is True
    assert first["updated"] is False
    assert second["updated"] is False
    destination = tmp_path / "codex" / "skills" / "agentctl"
    assert (destination / "SKILL.md").read_bytes() == content
    metadata = json.loads((destination / "agentctl-skill.json").read_text(encoding="utf-8"))
    assert metadata["canonical_release"] == "v0.1.1"
    assert distribution.read_skill_status()["content_matches_metadata"] is True


def test_skill_install_rejects_symlink_destination(monkeypatch, tmp_path: Path) -> None:
    codex = tmp_path / "codex"
    destination = codex / "skills" / "agentctl"
    destination.parent.mkdir(parents=True)
    destination.symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    monkeypatch.setenv("CODEX_HOME", str(codex))
    with pytest.raises(ValueError, match="symlinked Skill path"):
        distribution.install_skill(update=True)


def test_skill_status_cli_reports_missing_without_network(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    assert main(["skill", "status"]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["installed"] is False
