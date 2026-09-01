"""Local-development Ed25519 identity files and signer loading."""

from __future__ import annotations

import base64
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .registry import encode_public_key


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str, label: str) -> bytes:
    if not isinstance(value, str) or not value or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for char in value):
        raise ValueError(f"{label} is not valid base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(f"{label} is not valid base64url") from exc


@dataclass(frozen=True)
class LocalIdentity:
    principal_id: str
    display_name: str
    environment: str
    key_id: str
    algorithm: str
    private_key: Ed25519PrivateKey

    @property
    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def public_record(self) -> dict[str, str]:
        return {
            "principal_id": self.principal_id,
            "display_name": self.display_name,
            "environment": self.environment,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key": encode_public_key(self.public_key_bytes),
        }


def create_identity(
    path: str | Path,
    *,
    principal_id: str,
    display_name: str | None = None,
    environment: str = "development",
    key_id: str | None = None,
) -> LocalIdentity:
    private_key = Ed25519PrivateKey.generate()
    identity = LocalIdentity(
        principal_id=principal_id,
        display_name=display_name or principal_id,
        environment=environment,
        key_id=key_id or f"{principal_id}-key-{uuid.uuid4().hex[:12]}",
        algorithm="Ed25519",
        private_key=private_key,
    )
    save_identity(path, identity)
    return identity


def save_identity(path: str | Path, identity: LocalIdentity) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    raw_private_key = identity.private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    value = {
        "algorithm": identity.algorithm,
        "display_name": identity.display_name,
        "environment": identity.environment,
        "key_id": identity.key_id,
        "private_key": _encode(raw_private_key),
        "principal_id": identity.principal_id,
        "public_key": _encode(identity.public_key_bytes),
    }
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(destination)
    os.chmod(destination, 0o600)


def load_identity(path: str | Path) -> LocalIdentity:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("identity file must contain an object")
        if value.get("algorithm") != "Ed25519":
            raise ValueError("only Ed25519 identities are supported")
        raw_private_key = _decode(value["private_key"], "private key")
        if len(raw_private_key) != 32:
            raise ValueError("Ed25519 private keys must be 32 bytes")
        private_key = Ed25519PrivateKey.from_private_bytes(raw_private_key)
        public_key = value.get("public_key")
        if public_key is not None and _decode(public_key, "public key") != private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ):
            raise ValueError("identity public key does not match private key")
        return LocalIdentity(
            principal_id=value["principal_id"],
            display_name=value.get("display_name", value["principal_id"]),
            environment=value["environment"],
            key_id=value["key_id"],
            algorithm=value["algorithm"],
            private_key=private_key,
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load identity {source}: {exc}") from exc
