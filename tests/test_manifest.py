from __future__ import annotations

from pathlib import Path

import pytest

from agentctl.manifest import load_manifest, render_action_path


ROOT = Path(__file__).resolve().parents[1]


def test_reference_manifest_resolves_exact_action_and_escapes_parameters() -> None:
    manifest = load_manifest(ROOT / "examples/generic-python/.agent-control.yaml")
    action, audience, target = manifest.resolve_action("records.read", params={})
    assert action.method == "GET"
    assert audience.audience == "demo-api"
    assert target == "https://api.example.test/records"
    assert render_action_path("/records/{record_id}", {"record_id": "a/b?c"}) == "/records/a%2Fb%3Fc"


def test_manifest_rejects_sensitive_fields(tmp_path: Path) -> None:
    path = tmp_path / ".agent-control.yaml"
    path.write_text(
        """\
project: unsafe
private_key: should-not-be-here
audiences:
  demo:
    base_url: https://api.example.test
    audience: demo-api
actions:
  records.read:
    method: GET
    path: /records
    scope: records.read
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="sensitive manifest field"):
        load_manifest(path)


def test_manifest_rejects_url_credentials_and_unknown_fields(tmp_path: Path) -> None:
    credentials_path = tmp_path / "credentials.yaml"
    credentials_path.write_text(
        """\
project: unsafe
audiences:
  demo:
    base_url: https://user:password@api.example.test
    audience: demo-api
actions:
  records.read:
    method: GET
    path: /records
    scope: records.read
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="base_url must not contain URL credentials"):
        load_manifest(credentials_path)

    unknown_path = tmp_path / "unknown.yaml"
    unknown_path.write_text(
        """\
project: unsafe
audiences:
  demo:
    base_url: https://api.example.test
    audience: demo-api
actions:
  records.read:
    method: GET
    path: /records
    scope: records.read
unexpected: true
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="cannot load manifest"):
        load_manifest(unknown_path)


def test_manifest_loads_trusted_dev_policy_and_rejects_production_policy(tmp_path: Path) -> None:
    path = tmp_path / "trusted.yaml"
    path.write_text(
        """\
project: trusted
audiences:
  demo:
    base_url: https://api.example.test
    audience: demo-api
actions:
  records.read:
    method: GET
    path: /records
    scope: records.read
trusted_access:
  enabled: true
  environment: dev
  transports: [localhost]
  principals:
    agent:
      subject: dev-agent
      type: agent
      scopes: [app:read]
""",
        encoding="utf-8",
    )
    manifest = load_manifest(path)
    assert manifest.trusted_access.enabled
    assert manifest.trusted_access.principals["agent"].subject == "dev-agent"

    path.write_text(path.read_text(encoding="utf-8").replace("environment: dev", "environment: production"), encoding="utf-8")
    with pytest.raises(ValueError, match="trusted access can only be enabled for DEV"):
        load_manifest(path)
