"""Atomic response tests for session revocation, key locking, and evidence."""

from datetime import datetime, timezone
from pathlib import Path

from quantum_keyguard.domain.enums import (
    Algorithm,
    AuditAction,
    EventOutcome,
    KeyStatus,
    PolicyEffect,
    Role,
    SessionStatus,
)
from quantum_keyguard.domain.policy import PolicyDecision
from quantum_keyguard.domain.records import KeyRecord, SessionRecord, UserRecord
from quantum_keyguard.persistence.audit_repository import AuditRepository
from quantum_keyguard.persistence.database import Database
from quantum_keyguard.persistence.state_repository import SecurityStateRepository
from quantum_keyguard.services.response_service import ContainmentRequest, ResponseService


def test_containment_revokes_locks_alerts_and_audits(tmp_path: Path) -> None:
    database = Database(tmp_path / "keyguard.db")
    database.initialize()
    state = SecurityStateRepository(database)
    audit = AuditRepository(database)
    state.save_user(
        UserRecord(user_id="admin_001", display_name="Synthetic Admin", role=Role.KEY_ADMIN)
    )
    state.save_session(
        SessionRecord(
            session_id="sess_001",
            user_id="admin_001",
            device_id="device_001",
            source_ip="192.0.2.10",
        )
    )
    state.save_key(
        KeyRecord(
            key_id="key_001",
            algorithm=Algorithm.ML_DSA_65,
            owner_role=Role.KEY_ADMIN,
        )
    )
    decision = PolicyDecision(
        effect=PolicyEffect.CONTAIN,
        triggered_rules=("rule_private_export",),
        explanation="Private-key export is forbidden.",
        risk_score=0.91,
    )

    result = ResponseService(database, audit).contain(
        ContainmentRequest(
            correlation_id="corr_001",
            session_id="sess_001",
            user_id="admin_001",
            role=Role.KEY_ADMIN,
            source_ip="192.0.2.10",
            device_id="device_001",
            key_id="key_001",
            occurred_at=datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc),
        ),
        decision,
    )

    assert result.session_revoked is True
    assert result.key_locked is True
    assert state.session_status("sess_001") is SessionStatus.REVOKED
    assert state.key_status("key_001") is KeyStatus.LOCKED
    assert state.alert_count() == 1
    timeline = audit.list_by_session("sess_001")
    assert [event.action for event in timeline] == [
        AuditAction.LOCK_KEY,
        AuditAction.REVOKE_SESSION,
    ] or [event.action for event in timeline] == [
        AuditAction.REVOKE_SESSION,
        AuditAction.LOCK_KEY,
    ]
    assert all(event.outcome is EventOutcome.ALLOWED for event in timeline)


def test_response_rejects_non_containment_decision(tmp_path: Path) -> None:
    database = Database(tmp_path / "keyguard.db")
    database.initialize()
    service = ResponseService(database, AuditRepository(database))
    decision = PolicyDecision(
        effect=PolicyEffect.ALLOW,
        triggered_rules=("rule_authorized_operation",),
        explanation="Allowed.",
    )

    try:
        service.contain(
            ContainmentRequest(
                correlation_id="corr_001",
                session_id="sess_001",
                user_id="admin_001",
                role=Role.KEY_ADMIN,
                source_ip="192.0.2.10",
                device_id="device_001",
            ),
            decision,
        )
    except ValueError as error:
        assert "contain" in str(error)
    else:
        raise AssertionError("non-containment decision was accepted")

