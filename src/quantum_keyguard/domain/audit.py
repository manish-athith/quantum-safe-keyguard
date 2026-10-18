"""Audit-event contract and secret-field protection."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import Field, field_validator

from quantum_keyguard.domain.common import (
    Identifier,
    StrictModel,
    normalize_ip,
    require_aware_utc,
    utc_now,
)
from quantum_keyguard.domain.enums import (
    Algorithm,
    AuditAction,
    EventOutcome,
    Role,
)

FORBIDDEN_CONTEXT_FIELDS = frozenset(
    {
        "access_token",
        "credential",
        "credentials",
        "password",
        "plaintext",
        "private_key",
        "refresh_token",
        "secret",
        "secret_key",
        "seed",
        "seed_material",
        "shared_secret",
        "token",
    }
)


def _normalize_field_name(value: object) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _find_forbidden_field(value: object) -> str | None:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            normalized = _normalize_field_name(key)
            if normalized in FORBIDDEN_CONTEXT_FIELDS:
                return normalized
            found = _find_forbidden_field(nested_value)
            if found:
                return found
    elif isinstance(value, (list, tuple)):
        for item in value:
            found = _find_forbidden_field(item)
            if found:
                return found
    return None


class AuditEvent(StrictModel):
    """Immutable-in-storage metadata for one attempted security operation."""

    event_id: Identifier = Field(default_factory=lambda: f"evt_{uuid4().hex}")
    correlation_id: Identifier
    session_id: Identifier
    user_id: Identifier
    role: Role
    action: AuditAction
    outcome: EventOutcome
    occurred_at: datetime = Field(default_factory=utc_now)
    source_ip: str
    device_id: Identifier
    key_id: Identifier | None = None
    algorithm: Algorithm | None = None
    reason_code: Identifier | None = None
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        return normalize_ip(value)

    @field_validator("context")
    @classmethod
    def reject_sensitive_context(cls, value: dict[str, Any]) -> dict[str, Any]:
        forbidden = _find_forbidden_field(value)
        if forbidden:
            raise ValueError(f"audit context contains forbidden field: {forbidden}")
        return value

