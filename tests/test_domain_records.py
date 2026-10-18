"""Validation tests for security-sensitive domain records."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from quantum_keyguard.domain.audit import AuditEvent
from quantum_keyguard.domain.enums import (
    Algorithm,
    AuditAction,
    EventOutcome,
    Role,
)
from quantum_keyguard.domain.records import KeyRecord, SessionRecord


def base_event(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "correlation_id": "corr_001",
        "session_id": "sess_001",
        "user_id": "admin_001",
        "role": Role.KEY_ADMIN,
        "action": AuditAction.LIST_KEYS,
        "outcome": EventOutcome.ALLOWED,
        "occurred_at": datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc),
        "source_ip": "192.0.2.10",
        "device_id": "device_001",
        "context": {"result_count": 4},
    }
    values.update(overrides)
    return values


def test_audit_event_rejects_nested_secret_fields() -> None:
    with pytest.raises(ValidationError, match="private_key"):
        AuditEvent.model_validate(
            base_event(context={"safe": {"private-key": "must-not-be-here"}})
        )


def test_audit_event_rejects_naive_timestamp() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        AuditEvent.model_validate(
            base_event(occurred_at=datetime(2026, 10, 17, 10, 0))
        )


def test_session_normalizes_ip_and_timestamp() -> None:
    session = SessionRecord(
        session_id="sess_001",
        user_id="admin_001",
        device_id="device_001",
        source_ip="2001:0db8:0000:0000:0000:0000:0000:0001",
        created_at=datetime(2026, 10, 17, 15, 30, tzinfo=timezone.utc),
    )

    assert session.source_ip == "2001:db8::1"
    assert session.created_at.tzinfo is timezone.utc


def test_managed_key_rejects_rsa_1024() -> None:
    with pytest.raises(ValidationError, match="forbidden"):
        KeyRecord(
            key_id="key_001",
            algorithm=Algorithm.RSA_1024,
            owner_role=Role.KEY_ADMIN,
        )

