"""Standard-library password and opaque-token protection."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

PBKDF2_ITERATIONS = 600_000


def hash_password(password: str, *, salt: bytes | None = None) -> tuple[str, str, int]:
    if len(password) < 12:
        raise ValueError("password must contain at least 12 characters")
    actual_salt = salt or secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), actual_salt, PBKDF2_ITERATIONS
    )
    return (
        base64.b64encode(digest).decode("ascii"),
        base64.b64encode(actual_salt).decode("ascii"),
        PBKDF2_ITERATIONS,
    )


def verify_password(password: str, encoded_hash: str, encoded_salt: str, iterations: int) -> bool:
    try:
        expected = base64.b64decode(encoded_hash, validate=True)
        salt = base64.b64decode(encoded_salt, validate=True)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
