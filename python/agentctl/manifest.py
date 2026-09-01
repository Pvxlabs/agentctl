"""Project manifest loading and exact action resolution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import jsonschema
import yaml

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_ROOT = Path(__file__).resolve().parents[2]
_FORBIDDEN_KEYS = {
    "private_key", "secret", "password", "cookie", "token", "credential", "database_password", "database_url",
}


@dataclass(frozen=True)
class AudienceConfig:
    name: str
    base_url: str
    audience: str


@dataclass(frozen=True)
class ActionConfig:
    name: str
    method: str
    path: str
    scope: str
    audience: str | None = None
    content_type: str | None = None
    resource: str | None = None


@dataclass(frozen=True)
class ProjectManifest:
    project: str
    audiences: dict[str, AudienceConfig]
    actions: dict[str, ActionConfig]
    source: Path

    def action(self, name: str) -> ActionConfig:
        try:
            return self.actions[name]
        except KeyError as exc:
            raise ValueError(f"manifest action not found: {name}") from exc

    def resolve_action(
        self, name: str, *, params: dict[str, str] | None = None
    ) -> tuple[ActionConfig, AudienceConfig, str]:
        action = self.action(name)
        audience_name = action.audience
        if not audience_name:
            if len(self.audiences) != 1:
                raise ValueError(f"action {name} must select an audience")
            audience_name = next(iter(self.audiences))
        try:
            audience = self.audiences[audience_name]
        except KeyError as exc:
            raise ValueError(f"manifest audience not found: {audience_name}") from exc
        rendered_path = render_action_path(action.path, params or {})
        return action, audience, audience.base_url.rstrip("/") + rendered_path


def find_manifest(start: str | Path = ".") -> Path:
    candidate = Path(start).resolve()
    if candidate.is_file():
        candidate = candidate.parent
    for directory in (candidate, *candidate.parents):
        path = directory / ".agent-control.yaml"
        if path.exists():
            return path
    raise FileNotFoundError(".agent-control.yaml was not found")


def render_action_path(path: str, params: dict[str, str]) -> str:
    missing: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in params:
            missing.append(name)
            return match.group(0)
        from urllib.parse import quote

        return quote(params[name], safe="-._~")

    rendered = _PLACEHOLDER.sub(replace, path)
    if missing:
        raise ValueError(f"missing action path parameters: {', '.join(sorted(set(missing)))}")
    return rendered


def _schema() -> dict[str, Any]:
    import json

    return json.loads((_ROOT / "schemas" / "manifest.schema.json").read_text(encoding="utf-8"))


def _reject_sensitive_fields(value: Any, path: str = "manifest") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in _FORBIDDEN_KEYS:
                raise ValueError(f"sensitive manifest field is not allowed: {path}.{key}")
            _reject_sensitive_fields(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_sensitive_fields(item, f"{path}[{index}]")


def load_manifest(path: str | Path) -> ProjectManifest:
    source = Path(path).resolve()
    try:
        value = yaml.safe_load(source.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("manifest must contain an object")
        _reject_sensitive_fields(value)
        jsonschema.Draft202012Validator(_schema(), format_checker=jsonschema.FormatChecker()).validate(value)
        audiences: dict[str, AudienceConfig] = {}
        for name, config in value["audiences"].items():
            parsed = urlsplit(config["base_url"])
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"audience {name} base_url must be an HTTP(S) URL")
            if parsed.username is not None or parsed.password is not None:
                raise ValueError(f"audience {name} base_url must not contain URL credentials")
            audiences[name] = AudienceConfig(name, config["base_url"], config["audience"])
        actions = {
            name: ActionConfig(
                name=name,
                method=config["method"].upper(),
                path=config["path"],
                scope=config["scope"],
                audience=config.get("audience"),
                content_type=config.get("content_type"),
                resource=config.get("resource"),
            )
            for name, config in value["actions"].items()
        }
        return ProjectManifest(value["project"], audiences, actions, source)
    except (OSError, UnicodeError, yaml.YAMLError, jsonschema.ValidationError, TypeError, ValueError) as exc:
        raise ValueError(f"cannot load manifest {source}: {exc}") from exc
