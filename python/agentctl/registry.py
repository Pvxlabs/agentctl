"""Principal, key, and explicit scope registries."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import KeyRecord, PrincipalRecord, ScopeGrant


@dataclass
class Registry:
    principals: dict[str, PrincipalRecord] = field(default_factory=dict)
    keys: dict[str, KeyRecord] = field(default_factory=dict)
    grants: list[ScopeGrant] = field(default_factory=list)

    def add_principal(self, principal: PrincipalRecord) -> None:
        self.principals[principal.principal_id] = principal

    def add_key(self, key: KeyRecord) -> None:
        self.keys[key.key_id] = key

    def add_grant(self, grant: ScopeGrant) -> None:
        if grant not in self.grants:
            self.grants.append(grant)

    def has_grant(
        self,
        *,
        principal_id: str,
        environment: str,
        audience: str,
        scope: str,
        resource: str | None,
    ) -> bool:
        return any(
            grant.principal_id == principal_id
            and grant.environment == environment
            and grant.audience == audience
            and grant.scope == scope
            and (grant.resource is None or grant.resource == resource)
            for grant in self.grants
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "principals": [item.to_dict() for item in self.principals.values()],
            "keys": [item.to_dict() for item in self.keys.values()],
            "grants": [item.to_dict() for item in self.grants],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Registry":
        registry = cls()
        for item in value.get("principals", []):
            registry.add_principal(PrincipalRecord.from_dict(item))
        for item in value.get("keys", []):
            registry.add_key(KeyRecord.from_dict(item))
        for item in value.get("grants", []):
            registry.add_grant(ScopeGrant.from_dict(item))
        return registry


def load_registry(path: str | Path) -> Registry:
    source = Path(path)
    if not source.exists():
        return Registry()
    try:
        return Registry.from_dict(json.loads(source.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError(f"cannot load registry {source}: {exc}") from exc


def save_registry(path: str | Path, registry: Registry) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(registry.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)


def encode_public_key(key_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(key_bytes).decode("ascii").rstrip("=")


def decode_public_key(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("public key is not valid base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("public key is not valid base64url") from exc
    if encode_public_key(decoded) != value or len(decoded) != 32:
        raise ValueError("Ed25519 public keys must be 32 bytes")
    return decoded
