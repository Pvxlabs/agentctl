"""Typed models shared by registry, verifier, and audit modules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class PrincipalRecord:
    principal_id: str
    display_name: str
    environment: str
    enabled: bool = True
    created_at: str = ""
    updated_at: str = ""
    revoked_at: str | None = None
    revocation_epoch: int = 0

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = utc_now()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "PrincipalRecord":
        return cls(**value)


@dataclass
class KeyRecord:
    key_id: str
    principal_id: str
    algorithm: str
    public_key: str
    enabled: bool = True
    created_at: str = ""
    expires_at: str | None = None
    revoked_at: str | None = None
    key_epoch: int = 0

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = utc_now()

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "KeyRecord":
        return cls(**value)


@dataclass
class ScopeGrant:
    principal_id: str
    environment: str
    audience: str
    scope: str
    resource: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ScopeGrant":
        return cls(**value)


@dataclass(frozen=True)
class RequestContext:
    method: str
    target: str
    body: bytes
    content_type: str | None = None
    request_id: str | None = None
    resource: str | None = None


@dataclass(frozen=True)
class AuthorizationEvidence:
    principal_id: str
    key_id: str
    environment: str
    audience: str
    scope: str
    request_id: str
    jti: str
    canonical_path: str
    body_sha256: str
    resource: str | None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()
