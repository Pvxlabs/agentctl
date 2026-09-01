from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentctl.audit import AuditEvent, JsonlAuditSink, verify_audit_file
from agentctl.models import KeyRecord, PrincipalRecord, RequestContext, ScopeGrant
from agentctl.protocol import (
    AssertionErrorCode,
    build_assertion,
    canonical_request_target,
    parse_assertion,
    sha256_hex,
    verify_signature,
)
from agentctl.registry import Registry, decode_public_key, encode_public_key
from agentctl.replay import MemoryReplayStore, SQLiteReplayStore
from agentctl.verifier import VerificationError, Verifier


ROOT = Path(__file__).resolve().parents[1]
VECTOR = json.loads((ROOT / "vectors" / "assertion-v1.json").read_text(encoding="utf-8"))
SEED = base64.urlsafe_b64decode(VECTOR["private_seed_base64url"] + "==")
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(SEED)


def registry(*, grant_scope: str = "items.read") -> Registry:
    value = Registry()
    value.add_principal(PrincipalRecord("vector-agent", "Vector Agent", "development"))
    value.add_key(KeyRecord("vector-key", "vector-agent", "Ed25519", VECTOR["public_key_base64url"]))
    value.add_grant(ScopeGrant("vector-agent", "development", "vector-api", grant_scope, "item:123"))
    return value


def assertion(**overrides: object) -> str:
    values = {
        "principal_id": "vector-agent",
        "audience": "vector-api",
        "environment": "development",
        "scope": "items.read",
        "http_method": "POST",
        "target": "/items?b=two&a=one&empty",
        "body": b'{"z":3,"a":1}\n',
        "key_id": "vector-key",
        "principal_epoch": 0,
        "key_epoch": 0,
        "private_key": PRIVATE_KEY,
        "content_type": "application/json; charset=utf-8",
        "resource": "item:123",
        "project": "agentctl-conformance",
        "request_id": "request-0001",
        "jti": "vector-jti-0001",
        "now": 1_700_000_000,
        "ttl_seconds": 300,
    }
    values.update(overrides)
    return build_assertion(**values)


def request(**overrides: object) -> RequestContext:
    values: dict[str, object] = {
        "method": "POST",
        "target": "/items?a=one&b=two&empty=",
        "body": b'{"z":3,"a":1}\n',
        "content_type": "application/json; charset=utf-8",
        "request_id": "request-0001",
        "resource": "item:123",
    }
    values.update(overrides)
    return RequestContext(**values)


def verifier(value: Registry | None = None, replay: object | None = None) -> Verifier:
    return Verifier(
        value or registry(),
        replay or MemoryReplayStore(),
        expected_audience="vector-api",
        expected_environment="development",
    )


def test_golden_vector_and_signature() -> None:
    compact = assertion()
    assert compact == VECTOR["assertion"]
    parsed = parse_assertion(compact)
    assert parsed.payload["canonical_path"] == "/items?a=one&b=two&empty="
    public = PRIVATE_KEY.public_key()
    verify_signature(parsed, public)


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("/items?b=two&a=one&empty", "/items?a=one&b=two&empty="),
        ("/a/%7e/%2f", "/a/~/ %2F".replace(" ", "")),
        ("https://example.test/items?x=hello+world", "/items?x=hello%20world"),
    ],
)
def test_canonical_request_targets(target: str, expected: str) -> None:
    assert canonical_request_target(target) == expected


@pytest.mark.parametrize("target", ["/a/../b", "/a/%", "/a#fragment", "/a?bad=%FF"])
def test_invalid_request_targets_fail_closed(target: str) -> None:
    with pytest.raises(AssertionErrorCode):
        canonical_request_target(target)


def test_malformed_url_and_non_string_method_fail_with_stable_codes() -> None:
    with pytest.raises(AssertionErrorCode) as raised:
        canonical_request_target("http://[::1")
    assert raised.value.code == "INVALID_PATH"

    with pytest.raises(AssertionErrorCode) as raised:
        assertion(http_method=None)
    assert raised.value.code == "INVALID_METHOD"


def test_explicit_empty_identifiers_are_not_replaced() -> None:
    with pytest.raises(AssertionErrorCode) as raised:
        assertion(jti="")
    assert raised.value.code == "MALFORMED_ASSERTION"

    with pytest.raises(AssertionErrorCode) as raised:
        assertion(request_id="")
    assert raised.value.code == "MALFORMED_ASSERTION"


def test_public_key_decoder_rejects_non_ascii_and_noncanonical_values() -> None:
    with pytest.raises(ValueError):
        decode_public_key("é")
    with pytest.raises(ValueError):
        decode_public_key(VECTOR["public_key_base64url"] + "A")


def test_sqlite_replay_store_is_durable(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite"
    first = SQLiteReplayStore(path)
    assert first.consume("jti-00000001", 1_900_000_000) is True
    second = SQLiteReplayStore(path)
    assert second.consume("jti-00000001", 1_900_000_000) is False


@pytest.mark.parametrize(
    ("name", "assertion_overrides", "request_overrides", "registry_value", "now", "expected"),
    [
        ("expired", {}, {}, None, 1_700_000_300, "EXPIRED"),
        ("not-yet-valid", {"now": 1_700_000_000}, {}, None, 1_699_999_999, "NOT_YET_VALID"),
        ("wrong-issuer", {"principal_id": "other-agent"}, {}, None, 1_700_000_001, "WRONG_ISSUER"),
        ("wrong-audience", {"audience": "other-api"}, {}, None, 1_700_000_001, "WRONG_AUDIENCE"),
        ("wrong-environment", {"environment": "production"}, {}, None, 1_700_000_001, "WRONG_ENVIRONMENT"),
        ("missing-scope", {"scope": "items.write"}, {}, None, 1_700_000_001, "SCOPE_DENIED"),
        ("wrong-method", {}, {"method": "GET"}, None, 1_700_000_001, "METHOD_MISMATCH"),
        ("wrong-path", {}, {"target": "/other"}, None, 1_700_000_001, "PATH_MISMATCH"),
        ("changed-body", {}, {"body": b'{"z":4,"a":1}\n'}, None, 1_700_000_001, "BODY_DIGEST_MISMATCH"),
        ("unknown-key", {"key_id": "unknown-key"}, {}, None, 1_700_000_001, "UNKNOWN_KEY"),
        ("revoked-key", {}, {}, None, 1_700_000_001, "KEY_REVOKED"),
        ("disabled-principal", {}, {}, None, 1_700_000_001, "PRINCIPAL_DISABLED"),
        ("revoked-principal", {}, {}, None, 1_700_000_001, "PRINCIPAL_REVOKED"),
    ],
)
def test_security_matrix(
    name: str,
    assertion_overrides: dict[str, object],
    request_overrides: dict[str, object],
    registry_value: Registry | None,
    now: int,
    expected: str,
) -> None:
    value = registry_value or registry()
    if name == "revoked-key":
        value.keys["vector-key"].revoked_at = "2026-09-01T00:00:00Z"
    if name == "disabled-principal":
        value.principals["vector-agent"].enabled = False
    if name == "revoked-principal":
        value.principals["vector-agent"].revoked_at = "2026-09-01T00:00:00Z"
    with pytest.raises(VerificationError) as raised:
        verifier(value).verify(assertion(**assertion_overrides), request(**request_overrides), now=now)
    assert raised.value.code == expected, name


def test_replayed_jti_is_denied_and_failed_request_does_not_consume() -> None:
    store = MemoryReplayStore()
    instance = verifier(replay=store)
    compact = assertion(jti="replay-jti-0001")
    with pytest.raises(VerificationError) as raised:
        instance.verify(compact, request(body=b"changed"), now=1_700_000_001)
    assert raised.value.code == "BODY_DIGEST_MISMATCH"
    assert instance.verify(compact, request(), now=1_700_000_001).evidence.jti == "replay-jti-0001"
    with pytest.raises(VerificationError) as raised:
        instance.verify(compact, request(), now=1_700_000_001)
    assert raised.value.code == "REPLAYED_JTI"


def test_revocation_epochs_deny_previously_issued_assertions() -> None:
    value = registry()
    value.principals["vector-agent"].revocation_epoch = 1
    with pytest.raises(VerificationError) as raised:
        verifier(value).verify(assertion(jti="principal-epoch-0001"), request(), now=1_700_000_001)
    assert raised.value.code == "PRINCIPAL_EPOCH_MISMATCH"

    value = registry()
    value.keys["vector-key"].key_epoch = 1
    with pytest.raises(VerificationError) as raised:
        verifier(value).verify(assertion(jti="key-epoch-0001"), request(), now=1_700_000_001)
    assert raised.value.code == "KEY_EPOCH_MISMATCH"


def test_malformed_and_bad_signature_are_denied() -> None:
    with pytest.raises(VerificationError) as raised:
        verifier().verify("agentctl-aav1.invalid.invalid", request(), now=1_700_000_001)
    assert raised.value.code == "MALFORMED_ASSERTION"
    compact = assertion()
    parts = compact.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    with pytest.raises(VerificationError) as raised:
        verifier().verify(".".join(parts), request(), now=1_700_000_001)
    assert raised.value.code == "BAD_SIGNATURE"


def test_audit_chain_records_authorization_and_rejection(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(path)
    instance = Verifier(
        registry(),
        MemoryReplayStore(),
        expected_audience="vector-api",
        expected_environment="development",
        audit_sink=sink,
    )
    instance.verify(assertion(jti="audit-jti-0001"), request(), now=1_700_000_001)
    with pytest.raises(VerificationError):
        instance.verify(assertion(jti="audit-jti-0002"), request(method="GET"), now=1_700_000_001)
    valid, message = verify_audit_file(path)
    assert valid, message
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [event["result"] for event in events] == ["AUTHORIZED", "REJECTED"]
    assert all("private_key" not in event and "secret" not in event for event in events)
