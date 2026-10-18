"""Append-only SQLite storage for validated audit events."""

from __future__ import annotations

import json
import sqlite3

from quantum_keyguard.domain.audit import AuditEvent
from quantum_keyguard.persistence.database import Database


class AuditRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def append(self, event: AuditEvent) -> AuditEvent:
        """Append one event; duplicate IDs fail instead of overwriting evidence."""
        with self.database.connect() as connection:
            self.append_to(connection, event)
            connection.commit()
        return event

    def append_to(self, connection: sqlite3.Connection, event: AuditEvent) -> None:
        """Append using an existing transaction for atomic response workflows."""
        payload = event.model_dump(mode="json")
        connection.execute(
            """
            INSERT INTO audit_events (
                event_id, correlation_id, session_id, user_id, role, action,
                outcome, occurred_at, source_ip, device_id, key_id, algorithm,
                reason_code, risk_score, context_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["event_id"],
                payload["correlation_id"],
                payload["session_id"],
                payload["user_id"],
                payload["role"],
                payload["action"],
                payload["outcome"],
                payload["occurred_at"],
                payload["source_ip"],
                payload["device_id"],
                payload["key_id"],
                payload["algorithm"],
                payload["reason_code"],
                payload["risk_score"],
                json.dumps(payload["context"], sort_keys=True, separators=(",", ":")),
            ),
        )

    def list_by_session(self, session_id: str, *, limit: int = 500) -> list[AuditEvent]:
        """Return a bounded, chronological session history."""
        if not 1 <= limit <= 5_000:
            raise ValueError("limit must be between 1 and 5000")

        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM audit_events
                WHERE session_id = ?
                ORDER BY occurred_at ASC, event_id ASC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()

        return [
            AuditEvent.model_validate(
                {
                    "event_id": row["event_id"],
                    "correlation_id": row["correlation_id"],
                    "session_id": row["session_id"],
                    "user_id": row["user_id"],
                    "role": row["role"],
                    "action": row["action"],
                    "outcome": row["outcome"],
                    "occurred_at": row["occurred_at"],
                    "source_ip": row["source_ip"],
                    "device_id": row["device_id"],
                    "key_id": row["key_id"],
                    "algorithm": row["algorithm"],
                    "reason_code": row["reason_code"],
                    "risk_score": row["risk_score"],
                    "context": json.loads(row["context_json"]),
                }
            )
            for row in rows
        ]

    def list_by_user(self, user_id: str, *, limit: int = 200) -> list[AuditEvent]:
        """Return a bounded newest-first evidence feed for one authenticated user."""
        if not 1 <= limit <= 1_000:
            raise ValueError("limit must be between 1 and 1000")

        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM audit_events
                WHERE user_id = ?
                ORDER BY occurred_at DESC, event_id DESC
                LIMIT ?
                """,
                (user_id, limit),
            ).fetchall()

        return [
            AuditEvent.model_validate(
                {
                    "event_id": row["event_id"],
                    "correlation_id": row["correlation_id"],
                    "session_id": row["session_id"],
                    "user_id": row["user_id"],
                    "role": row["role"],
                    "action": row["action"],
                    "outcome": row["outcome"],
                    "occurred_at": row["occurred_at"],
                    "source_ip": row["source_ip"],
                    "device_id": row["device_id"],
                    "key_id": row["key_id"],
                    "algorithm": row["algorithm"],
                    "reason_code": row["reason_code"],
                    "risk_score": row["risk_score"],
                    "context": json.loads(row["context_json"]),
                }
            )
            for row in rows
        ]

    def count(self) -> int:
        with self.database.connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM audit_events").fetchone()
        return int(row["total"])

