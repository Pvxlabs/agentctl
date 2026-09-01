"""Typed append-only audit events and a hash-chained JSONL sink."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal, Protocol

import fcntl

from .protocol import canonical_json_bytes

AuditResult = Literal["AUTHORIZED", "REJECTED", "EXECUTED", "FAILED"]


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    principal_type: str
    principal_id: str
    key_id: str
    environment: str
    audience: str
    scope: str
    action: str
    http_method: str
    canonical_path: str
    body_sha256: str
    resource: str | None
    request_id: str
    jti: str
    result: AuditResult
    result_code: str
    created_at: str
    prev_hash: str = ""
    event_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class AuditSink(Protocol):
    def append(self, event: AuditEvent) -> AuditEvent:
        """Append and return the event with its chain fields populated."""


def _hash_event(event: AuditEvent) -> str:
    body = event.to_dict()
    body.pop("event_hash", None)
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


class JsonlAuditSink:
    """Append-only JSONL sink suitable as a small reference implementation."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, event: AuditEvent) -> AuditEvent:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self.path.open("a+", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                handle.seek(0)
                lines = handle.read().splitlines()
                previous = ""
                if lines:
                    last = json.loads(lines[-1])
                    previous = last.get("event_hash", "")
                    if not isinstance(previous, str):
                        raise ValueError("audit event_hash must be a string")
                chained = replace(event, prev_hash=previous, event_hash="")
                chained = replace(chained, event_hash=_hash_event(chained))
                serialized = json.dumps(
                    chained.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                handle.seek(0, os.SEEK_END)
                handle.write(serialized + "\n")
                handle.flush()
                os.fsync(handle.fileno())
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return chained


def verify_audit_file(path: str | Path) -> tuple[bool, str]:
    source = Path(path)
    if not source.exists():
        return False, "audit file does not exist"
    previous = ""
    try:
        for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                return False, f"line {line_number}: event must be an object"
            if value.get("prev_hash") != previous:
                return False, f"line {line_number}: previous hash mismatch"
            claimed = value.get("event_hash")
            if not isinstance(claimed, str):
                return False, f"line {line_number}: missing event hash"
            event = AuditEvent(**value)
            calculated = _hash_event(event)
            if calculated != claimed:
                return False, f"line {line_number}: event hash mismatch"
            previous = claimed
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return False, f"audit parse failure: {exc}"
    return True, "audit chain valid"
