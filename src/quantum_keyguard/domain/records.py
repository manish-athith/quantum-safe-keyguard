"""Validated records for identities, sessions, keys, policies, and alerts."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator

from quantum_keyguard.domain.common import (
    Identifier,
    StrictModel,
    normalize_ip,
    require_aware_utc,
    utc_now,
)
from quantum_keyguard.domain.enums import (
    AlertSeverity,
    Algorithm,
    KeyStatus,
    PolicyEffect,
    Role,
    SessionStatus,
)


class UserRecord(StrictModel):
    user_id: Identifier
    display_name: str = Field(min_length=1, max_length=120)
    role: Role
    enabled: bool = True


class SessionRecord(StrictModel):
    session_id: Identifier
    user_id: Identifier
    status: SessionStatus = SessionStatus.ACTIVE
    device_id: Identifier
    source_ip: str
    created_at: datetime = Field(default_factory=utc_now)
    revoked_at: datetime | None = None

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        return normalize_ip(value)

    @field_validator("created_at", "revoked_at")
    @classmethod
    def validate_timestamps(cls, value: datetime | None) -> datetime | None:
        return require_aware_utc(value) if value is not None else None


class KeyRecord(StrictModel):
    key_id: Identifier
    algorithm: Algorithm
    status: KeyStatus = KeyStatus.ACTIVE
    owner_role: Role
    created_at: datetime = Field(default_factory=utc_now)
    rotated_at: datetime | None = None

    @field_validator("algorithm")
    @classmethod
    def reject_unsafe_key_algorithm(cls, value: Algorithm) -> Algorithm:
        if value is Algorithm.RSA_1024:
            raise ValueError("RSA-1024 is forbidden for managed keys")
        return value

    @field_validator("created_at", "rotated_at")
    @classmethod
    def validate_timestamps(cls, value: datetime | None) -> datetime | None:
        return require_aware_utc(value) if value is not None else None


class PolicyRecord(StrictModel):
    rule_id: Identifier
    description: str = Field(min_length=3, max_length=500)
    effect: PolicyEffect
    enabled: bool = True


class AlertRecord(StrictModel):
    alert_id: Identifier
    correlation_id: Identifier
    session_id: Identifier
    severity: AlertSeverity
    summary: str = Field(min_length=3, max_length=500)
    created_at: datetime = Field(default_factory=utc_now)
    acknowledged: bool = False

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

