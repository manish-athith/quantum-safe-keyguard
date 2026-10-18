"""SQLite connection and deterministic schema initialization."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    status TEXT NOT NULL,
    device_id TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS user_credentials (
    user_id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    iterations INTEGER NOT NULL CHECK (iterations >= 100000),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS session_tokens (
    token_hash TEXT PRIMARY KEY,
    session_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_session_tokens_session
ON session_tokens(session_id);

CREATE TABLE IF NOT EXISTS managed_keys (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    status TEXT NOT NULL,
    owner_role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    rotated_at TEXT
);

CREATE TABLE IF NOT EXISTS policies (
    rule_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    effect TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL,
    acknowledged INTEGER NOT NULL CHECK (acknowledged IN (0, 1))
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    device_id TEXT NOT NULL,
    key_id TEXT,
    algorithm TEXT,
    reason_code TEXT,
    risk_score REAL CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 1)),
    context_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_session_time
ON audit_events(session_id, occurred_at, event_id);

CREATE INDEX IF NOT EXISTS idx_audit_correlation
ON audit_events(correlation_id);

CREATE TRIGGER IF NOT EXISTS audit_events_prevent_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_events_prevent_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;
"""


class Database:
    """Own SQLite connection policy and schema creation."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create the complete schema safely and repeatedly."""
        with self.connect() as connection:
            connection.executescript(SCHEMA_SQL)
            connection.commit()

