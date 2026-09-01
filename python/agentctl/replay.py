"""Consume-once replay storage implementations."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Protocol


class ReplayStore(Protocol):
    """Storage contract for atomic JTI consumption."""

    def consume(self, jti: str, expires_at: int, *, now: int | None = None) -> bool:
        """Return True exactly once for a JTI that has not been consumed."""


class MemoryReplayStore:
    """Process-local store for tests and examples only."""

    def __init__(self) -> None:
        self._entries: dict[str, int] = {}
        self._lock = threading.Lock()

    def consume(self, jti: str, expires_at: int, *, now: int | None = None) -> bool:
        current = int(time.time()) if now is None else now
        if expires_at <= current:
            return False
        with self._lock:
            self._entries = {
                entry_jti: expiry
                for entry_jti, expiry in self._entries.items()
                if expiry > current
            }
            if jti in self._entries:
                return False
            self._entries[jti] = expires_at
            return True


class SQLiteReplayStore:
    """Durable SQLite reference store with an atomic unique-JTI insert."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._memory_connection: sqlite3.Connection | None = None
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connection(self) -> sqlite3.Connection:
        if self.path == ":memory:":
            if self._memory_connection is None:
                self._memory_connection = sqlite3.connect(
                    self.path, isolation_level=None, check_same_thread=False
                )
            return self._memory_connection
        return sqlite3.connect(self.path, timeout=30, isolation_level=None)

    def _initialize(self) -> None:
        connection = self._connection()
        try:
            connection.execute("PRAGMA busy_timeout = 30000")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_jti (
                    jti TEXT PRIMARY KEY,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER NOT NULL
                )
                """
            )
        finally:
            if connection is not self._memory_connection:
                connection.close()

    def consume(self, jti: str, expires_at: int, *, now: int | None = None) -> bool:
        current = int(time.time()) if now is None else now
        connection = self._connection()
        try:
            connection.execute("PRAGMA busy_timeout = 30000")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM consumed_jti WHERE expires_at <= ?", (current,))
            try:
                connection.execute(
                    "INSERT INTO consumed_jti(jti, expires_at, consumed_at) VALUES (?, ?, ?)",
                    (jti, expires_at, current),
                )
            except sqlite3.IntegrityError:
                connection.execute("ROLLBACK")
                return False
            connection.execute("COMMIT")
            return True
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            if connection is not self._memory_connection:
                connection.close()
