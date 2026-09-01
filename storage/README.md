# Storage Contracts

Replay storage must provide an atomic consume-once operation keyed by JTI.
The Python reference implementation uses SQLite with a unique primary key and
an immediate transaction. The in-memory implementation is for tests only.

Audit sinks append typed events. The Python JSONL reference sink adds a hash
chain and never writes private keys, secrets, raw credentials, or bearer
tokens.
