"""SQLite repositories for identity, session, and managed-key state."""

from __future__ import annotations

from quantum_keyguard.domain.enums import KeyStatus, SessionStatus
from quantum_keyguard.domain.records import (
    AlertRecord,
    KeyRecord,
    SessionRecord,
    UserRecord,
)
from quantum_keyguard.persistence.database import Database


class SecurityStateRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def save_user(self, user: UserRecord) -> None:
        payload = user.model_dump(mode="json")
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO users(user_id, display_name, role, enabled)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    display_name = excluded.display_name,
                    role = excluded.role,
                    enabled = excluded.enabled
                """,
                (
                    payload["user_id"],
                    payload["display_name"],
                    payload["role"],
                    int(payload["enabled"]),
                ),
            )
            connection.commit()

    def save_session(self, session: SessionRecord) -> None:
        payload = session.model_dump(mode="json")
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO sessions(
                    session_id, user_id, status, device_id, source_ip,
                    created_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    status = excluded.status,
                    device_id = excluded.device_id,
                    source_ip = excluded.source_ip,
                    revoked_at = excluded.revoked_at
                """,
                (
                    payload["session_id"],
                    payload["user_id"],
                    payload["status"],
                    payload["device_id"],
                    payload["source_ip"],
                    payload["created_at"],
                    payload["revoked_at"],
                ),
            )
            connection.commit()

    def save_key(self, key: KeyRecord) -> None:
        payload = key.model_dump(mode="json")
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO managed_keys(
                    key_id, algorithm, status, owner_role, created_at, rotated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(key_id) DO UPDATE SET
                    algorithm = excluded.algorithm,
                    status = excluded.status,
                    owner_role = excluded.owner_role,
                    rotated_at = excluded.rotated_at
                """,
                (
                    payload["key_id"],
                    payload["algorithm"],
                    payload["status"],
                    payload["owner_role"],
                    payload["created_at"],
                    payload["rotated_at"],
                ),
            )
            connection.commit()

    def session_status(self, session_id: str) -> SessionStatus | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT status FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        return SessionStatus(row["status"]) if row else None

    def get_user(self, user_id: str) -> UserRecord | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT user_id, display_name, role, enabled FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()
        return UserRecord.model_validate(dict(row)) if row else None

    def get_session(self, session_id: str) -> SessionRecord | None:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT session_id, user_id, status, device_id, source_ip, created_at, revoked_at
                FROM sessions WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
        return SessionRecord.model_validate(dict(row)) if row else None

    def get_key(self, key_id: str) -> KeyRecord | None:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT key_id, algorithm, status, owner_role, created_at, rotated_at
                FROM managed_keys WHERE key_id = ?
                """,
                (key_id,),
            ).fetchone()
        return KeyRecord.model_validate(dict(row)) if row else None

    def list_keys(self, *, limit: int = 100) -> list[KeyRecord]:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT key_id, algorithm, status, owner_role, created_at, rotated_at
                FROM managed_keys ORDER BY created_at, key_id LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [KeyRecord.model_validate(dict(row)) for row in rows]

    def list_sessions_by_user(
        self, user_id: str, *, limit: int = 20
    ) -> list[SessionRecord]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT session_id, user_id, status, device_id, source_ip,
                       created_at, revoked_at
                FROM sessions
                WHERE user_id = ?
                ORDER BY created_at DESC, session_id DESC
                LIMIT ?
                """,
                (user_id, limit),
            ).fetchall()
        return [SessionRecord.model_validate(dict(row)) for row in rows]

    def list_alerts_by_user(
        self, user_id: str, *, limit: int = 50
    ) -> list[AlertRecord]:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT a.alert_id, a.correlation_id, a.session_id, a.severity,
                       a.summary, a.created_at, a.acknowledged
                FROM alerts AS a
                JOIN sessions AS s ON s.session_id = a.session_id
                WHERE s.user_id = ?
                ORDER BY a.created_at DESC, a.alert_id DESC
                LIMIT ?
                """,
                (user_id, limit),
            ).fetchall()
        return [AlertRecord.model_validate(dict(row)) for row in rows]

    def set_key_status(self, key_id: str, status: KeyStatus) -> bool:
        with self.database.connect() as connection:
            result = connection.execute(
                "UPDATE managed_keys SET status = ? WHERE key_id = ?",
                (status.value, key_id),
            )
            connection.commit()
        return result.rowcount == 1

    def key_status(self, key_id: str) -> KeyStatus | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT status FROM managed_keys WHERE key_id = ?", (key_id,)
            ).fetchone()
        return KeyStatus(row["status"]) if row else None

    def retire_active_ephemeral_keys(self) -> int:
        """Fail closed after restart because this prototype vault is process-local."""
        with self.database.connect() as connection:
            result = connection.execute(
                "UPDATE managed_keys SET status = ? WHERE status = ?",
                (KeyStatus.REVOKED.value, KeyStatus.ACTIVE.value),
            )
            connection.commit()
        return result.rowcount

    def alert_count(self) -> int:
        with self.database.connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM alerts").fetchone()
        return int(row["total"])

