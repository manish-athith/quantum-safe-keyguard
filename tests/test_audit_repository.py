"""Persistence and immutability tests for the audit trail."""

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from quantum_keyguard.domain.audit import AuditEvent
from quantum_keyguard.domain.enums import AuditAction, EventOutcome, Role
from quantum_keyguard.persistence.audit_repository import AuditRepository
from quantum_keyguard.persistence.database import Database
from quantum_keyguard.services.audit_service import AuditService


def make_event(event_id: str, minute: int, outcome: EventOutcome) -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        correlation_id="corr_001",
        session_id="sess_001",
        user_id="admin_001",
        role=Role.KEY_ADMIN,
        action=AuditAction.EXPORT_PRIVATE_KEY,
        outcome=outcome,
        occurred_at=datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc)
        + timedelta(minutes=minute),
        source_ip="192.0.2.10",
        device_id="device_001",
        key_id="key_001",
        reason_code="rule_private_export",
        context={"request_method": "POST"},
    )


@pytest.fixture
def database(tmp_path: Path) -> Database:
    db = Database(tmp_path / "keyguard.db")
    db.initialize()
    return db


def test_audit_service_stores_denials_in_chronological_order(database: Database) -> None:
    service = AuditService(AuditRepository(database))
    later = make_event("evt_later", 5, EventOutcome.DENIED)
    earlier = make_event("evt_earlier", 0, EventOutcome.ALLOWED)

    service.record(later)
    service.record(earlier)

    timeline = service.session_timeline("sess_001")
    assert [event.event_id for event in timeline] == ["evt_earlier", "evt_later"]
    assert timeline[1].outcome is EventOutcome.DENIED


def test_database_blocks_audit_update_and_delete(database: Database) -> None:
    repository = AuditRepository(database)
    repository.append(make_event("evt_locked", 0, EventOutcome.DENIED))

    with database.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE audit_events SET outcome = 'allowed' WHERE event_id = ?",
                ("evt_locked",),
            )

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM audit_events WHERE event_id = ?", ("evt_locked",)
            )


def test_schema_initialization_is_repeatable(database: Database) -> None:
    database.initialize()
    repository = AuditRepository(database)
    repository.append(make_event("evt_001", 0, EventOutcome.DENIED))
    assert repository.count() == 1


def test_duplicate_event_id_never_overwrites_evidence(database: Database) -> None:
    repository = AuditRepository(database)
    event = make_event("evt_duplicate", 0, EventOutcome.DENIED)
    repository.append(event)

    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        repository.append(event)

