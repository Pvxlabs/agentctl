#!/usr/bin/env python3
"""Generate the deterministic Agent Action Assertion v1 conformance vector."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentctl.protocol import build_assertion, canonical_request_target, sha256_hex


ROOT = Path(__file__).resolve().parents[1]
SEED = bytes(range(32))
BODY = b'{"z":3,"a":1}\n'
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(SEED)
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes_raw()
REQUEST = {
    "method": "post",
    "target": "https://vector.example.test/items?b=two&a=one&empty",
    "body": BODY.decode("ascii"),
    "content_type": "Application/JSON; charset=utf-8",
    "request_id": "request-0001",
    "resource": "item:123",
}
ASSERTION = build_assertion(
    principal_id="vector-agent",
    audience="vector-api",
    environment="development",
    scope="items.read",
    http_method=REQUEST["method"],
    target=REQUEST["target"],
    body=BODY,
    key_id="vector-key",
    principal_epoch=0,
    key_epoch=0,
    private_key=PRIVATE_KEY,
    content_type=REQUEST["content_type"],
    resource=REQUEST["resource"],
    project="agentctl-conformance",
    request_id=REQUEST["request_id"],
    jti="vector-jti-0001",
    now=1_700_000_000,
    ttl_seconds=300,
)

value = {
    "private_seed_base64url": base64.urlsafe_b64encode(SEED).decode().rstrip("="),
    "public_key_base64url": base64.urlsafe_b64encode(PUBLIC_KEY).decode().rstrip("="),
    "principal_id": "vector-agent",
    "key_id": "vector-key",
    "audience": "vector-api",
    "environment": "development",
    "scope": "items.read",
    "project": "agentctl-conformance",
    "request": {
        **REQUEST,
        "method": REQUEST["method"].upper(),
        "content_type": REQUEST["content_type"].strip().lower(),
        "body_sha256": sha256_hex(BODY),
        "canonical_path": canonical_request_target(REQUEST["target"]),
    },
    "iat": 1_700_000_000,
    "nbf": 1_700_000_000,
    "exp": 1_700_000_300,
    "jti": "vector-jti-0001",
    "request_id": "request-0001",
    "assertion": ASSERTION,
}
(ROOT / "vectors").mkdir(parents=True, exist_ok=True)
(ROOT / "vectors" / "assertion-v1.json").write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
