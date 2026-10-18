"""Admin bootstrap, credential verification, and hashed bearer sessions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from pydantic import Field

from quantum_keyguard.domain.common import Identifier, StrictModel, utc_now
from quantum_keyguard.domain.enums import Role, SessionStatus
from quantum_keyguard.domain.records import SessionRecord, UserRecord
from quantum_keyguard.persistence.database import Database
from quantum_keyguard.security.passwords import (
    hash_password,
    new_session_token,
    token_digest,
    verify_password,
)


class AuthenticationError(RuntimeError):
    """Safe authentication failure without identity enumeration details."""


class BootstrapError(RuntimeError):
    """Raised when one-time bootstrap is unavailable."""


class AuthPrincipal(StrictModel):
    user_id: Identifier
    display_name: str
    role: Role
    session_id: Identifier
    status: SessionStatus
    device_id: Identifier
    source_ip: str
    created_at: datetime
    is_new_device: bool


class LoginResult(StrictModel):
    access_token: str = Field(min_length=32)
    token_type: str = "bearer"
    expires_at: datetime
    principal: AuthPrincipal


class AuthService:
    def __init__(self, database: Database, *, token_ttl_minutes: int = 30) -> None:
        if not 5 <= token_ttl_minutes <= 1_440:
            raise ValueError("token TTL must be between 5 and 1440 minutes")
        self.database = database
        self.token_ttl = timedelta(minutes=token_ttl_minutes)

    def bootstrap_admin(self, user_id: str, display_name: str, password: str) -> UserRecord:
        """Create the first admin exactly once; later admins require protected APIs."""
        password_hash, salt, iterations = hash_password(password)
        user = UserRecord(
            user_id=user_id,
            display_name=display_name,
            role=Role.KEY_ADMIN,
            enabled=True,
        )
        payload = user.model_dump(mode="json")
        with self.database.connect() as connection:
            existing = connection.execute(
                "SELECT COUNT(*) AS total FROM user_credentials"
            ).fetchone()
            if int(existing["total"]) != 0:
                raise BootstrapError("initial admin has already been bootstrapped")
            connection.execute(
                "INSERT INTO users(user_id, display_name, role, enabled) VALUES (?, ?, ?, 1)",
                (payload["user_id"], payload["display_name"], payload["role"]),
            )
            connection.execute(
                """
                INSERT INTO user_credentials(user_id, password_hash, salt, iterations)
                VALUES (?, ?, ?, ?)
                """,
                (payload["user_id"], password_hash, salt, iterations),
            )
            connection.commit()
        return user

    def login(self, user_id: str, password: str, device_id: str, source_ip: str) -> LoginResult:
        now = utc_now()
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT u.user_id, u.display_name, u.role, u.enabled,
                       c.password_hash, c.salt, c.iterations
                FROM users AS u
                JOIN user_credentials AS c ON c.user_id = u.user_id
                WHERE u.user_id = ?
                """,
                (user_id,),
            ).fetchone()
            if (
                row is None
                or not bool(row["enabled"])
                or not verify_password(
                    password,
                    row["password_hash"],
                    row["salt"],
                    int(row["iterations"]),
                )
            ):
                raise AuthenticationError("invalid credentials")

            prior_device_use = connection.execute(
                "SELECT COUNT(*) AS total FROM sessions WHERE user_id = ? AND device_id = ?",
                (row["user_id"], device_id),
            ).fetchone()
            is_new_device = int(prior_device_use["total"]) == 0

            session = SessionRecord(
                session_id=f"sess_{uuid4().hex}",
                user_id=row["user_id"],
                device_id=device_id,
                source_ip=source_ip,
                created_at=now,
            )
            token = new_session_token()
            expires_at = now + self.token_ttl
            session_payload = session.model_dump(mode="json")
            connection.execute(
                """
                INSERT INTO sessions(
                    session_id, user_id, status, device_id, source_ip, created_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    session_payload["session_id"],
                    session_payload["user_id"],
                    session_payload["status"],
                    session_payload["device_id"],
                    session_payload["source_ip"],
                    session_payload["created_at"],
                ),
            )
            connection.execute(
                """
                INSERT INTO session_tokens(token_hash, session_id, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (token_digest(token), session.session_id, now.isoformat(), expires_at.isoformat()),
            )
            connection.commit()

        principal = AuthPrincipal(
            user_id=row["user_id"],
            display_name=row["display_name"],
            role=Role(row["role"]),
            session_id=session.session_id,
            status=SessionStatus.ACTIVE,
            device_id=session.device_id,
            source_ip=session.source_ip,
            created_at=session.created_at,
            is_new_device=is_new_device,
        )
        return LoginResult(access_token=token, expires_at=expires_at, principal=principal)

    def authenticate(self, token: str) -> AuthPrincipal:
        now = datetime.now(timezone.utc)
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT u.user_id, u.display_name, u.role, u.enabled,
                       s.session_id, s.status, s.device_id, s.source_ip, s.created_at,
                       t.expires_at,
                       (SELECT COUNT(*) FROM sessions AS prior
                        WHERE prior.user_id = s.user_id
                          AND prior.device_id = s.device_id
                          AND prior.created_at < s.created_at) AS prior_device_uses
                FROM session_tokens AS t
                JOIN sessions AS s ON s.session_id = t.session_id
                JOIN users AS u ON u.user_id = s.user_id
                WHERE t.token_hash = ?
                """,
                (token_digest(token),),
            ).fetchone()
            if row is None or not bool(row["enabled"]):
                raise AuthenticationError("invalid or expired session")
            expires_at = datetime.fromisoformat(row["expires_at"])
            if expires_at <= now:
                connection.execute(
                    "UPDATE sessions SET status = 'expired' WHERE session_id = ?",
                    (row["session_id"],),
                )
                connection.execute(
                    "DELETE FROM session_tokens WHERE token_hash = ?", (token_digest(token),)
                )
                connection.commit()
                raise AuthenticationError("invalid or expired session")
            if SessionStatus(row["status"]) is not SessionStatus.ACTIVE:
                raise AuthenticationError("invalid or expired session")

        return AuthPrincipal(
            user_id=row["user_id"],
            display_name=row["display_name"],
            role=Role(row["role"]),
            session_id=row["session_id"],
            status=SessionStatus(row["status"]),
            device_id=row["device_id"],
            source_ip=row["source_ip"],
            created_at=datetime.fromisoformat(row["created_at"]),
            is_new_device=int(row["prior_device_uses"]) == 0,
        )

    def logout(self, token: str) -> None:
        digest = token_digest(token)
        now = utc_now().isoformat()
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT session_id FROM session_tokens WHERE token_hash = ?", (digest,)
            ).fetchone()
            if row is None:
                raise AuthenticationError("invalid or expired session")
            connection.execute(
                "UPDATE sessions SET status = 'revoked', revoked_at = ? WHERE session_id = ?",
                (now, row["session_id"]),
            )
            connection.execute("DELETE FROM session_tokens WHERE token_hash = ?", (digest,))
            connection.commit()
