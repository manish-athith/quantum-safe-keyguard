"""Contracts for deterministic security policy evaluation."""

from __future__ import annotations

from pydantic import Field

from quantum_keyguard.domain.common import Identifier, StrictModel
from quantum_keyguard.domain.enums import (
    Algorithm,
    AuditAction,
    KeyStatus,
    PolicyEffect,
    Role,
    SessionStatus,
)


class PolicyContext(StrictModel):
    correlation_id: Identifier
    session_id: Identifier
    user_id: Identifier
    role: Role
    action: AuditAction
    session_status: SessionStatus
    source_ip: str
    device_id: Identifier
    key_id: Identifier | None = None
    key_status: KeyStatus | None = None
    algorithm: Algorithm | None = None
    hour: int = Field(ge=0, le=23)
    is_new_device: bool = False
    actions_in_last_minute: int = Field(default=1, ge=0, le=10_000)
    anomaly_score: float | None = Field(default=None, ge=0.0, le=1.0)


class PolicyDecision(StrictModel):
    effect: PolicyEffect
    triggered_rules: tuple[Identifier, ...]
    explanation: str = Field(min_length=3, max_length=1_000)
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)

