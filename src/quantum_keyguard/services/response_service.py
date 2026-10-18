"""Atomic containment of dangerous sessions and keys."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from pydantic import Field

from quantum_keyguard.domain.audit import AuditEvent
from quantum_keyguard.domain.common import (
    Identifier,
    StrictModel,
    require_aware_utc,
    utc_now,
)
from quantum_keyguard.domain.enums import (
    AlertSeverity,
    AuditAction,
    EventOutcome,
    PolicyEffect,
    Role,
)
from quantum_keyguard.domain.policy import PolicyDecision
from quantum_keyguard.persistence.audit_repository import AuditRepository
from quantum_keyguard.persistence.database import Database


class ContainmentRequest(StrictModel):
    correlation_id: Identifier
    session_id: Identifier
    user_id: Identifier
    role: Role
    source_ip: str
    device_id: Identifier
    key_id: Identifier | None = None
    occurred_at: datetime = Field(default_factory=utc_now)


class ContainmentResult(StrictModel):
    alert_id: Identifier
    session_revoked: bool
    key_locked: bool
    audit_event_ids: tuple[Identifier, ...]


class ResponseService:
    def __init__(self, database: Database, audit_repository: AuditRepository) -> None:
        self.database = database
        self.audit_repository = audit_repository

    def contain(
        self, request: ContainmentRequest, decision: PolicyDecision
    ) -> ContainmentResult:
        """Atomically revoke, lock, alert, and append containment evidence."""
        if decision.effect is not PolicyEffect.CONTAIN:
            raise ValueError("containment requires a contain policy decision")

        occurred_at = require_aware_utc(request.occurred_at)
        alert_id = f"alert_{uuid4().hex}"
        audit_events = [
            AuditEvent(
                correlation_id=request.correlation_id,
                session_id=request.session_id,
                user_id=request.user_id,
                role=request.role,
                action=AuditAction.REVOKE_SESSION,
                outcome=EventOutcome.ALLOWED,
                occurred_at=occurred_at,
                source_ip=request.source_ip,
                device_id=request.device_id,
                reason_code="containment_policy",
                risk_score=decision.risk_score,
                context={"triggered_rules": list(decision.triggered_rules)},
            )
        ]
        if request.key_id:
            audit_events.append(
                AuditEvent(
                    correlation_id=request.correlation_id,
                    session_id=request.session_id,
                    user_id=request.user_id,
                    role=request.role,
                    action=AuditAction.LOCK_KEY,
                    outcome=EventOutcome.ALLOWED,
                    occurred_at=occurred_at,
                    source_ip=request.source_ip,
                    device_id=request.device_id,
                    key_id=request.key_id,
                    reason_code="containment_policy",
                    risk_score=decision.risk_score,
                    context={"triggered_rules": list(decision.triggered_rules)},
                )
            )

        with self.database.connect() as connection:
            session_result = connection.execute(
                """
                UPDATE sessions
                SET status = 'revoked', revoked_at = ?
                WHERE session_id = ? AND status = 'active'
                """,
                (occurred_at.isoformat(), request.session_id),
            )
            connection.execute(
                "DELETE FROM session_tokens WHERE session_id = ?",
                (request.session_id,),
            )
            key_locked = False
            if request.key_id:
                key_result = connection.execute(
                    """
                    UPDATE managed_keys
                    SET status = 'locked'
                    WHERE key_id = ? AND status = 'active'
                    """,
                    (request.key_id,),
                )
                key_locked = key_result.rowcount == 1

            connection.execute(
                """
                INSERT INTO alerts(
                    alert_id, correlation_id, session_id, severity, summary,
                    created_at, acknowledged
                ) VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    alert_id,
                    request.correlation_id,
                    request.session_id,
                    AlertSeverity.CRITICAL.value,
                    decision.explanation,
                    occurred_at.isoformat(),
                ),
            )
            for event in audit_events:
                self.audit_repository.append_to(connection, event)
            connection.commit()

        return ContainmentResult(
            alert_id=alert_id,
            session_revoked=session_result.rowcount == 1,
            key_locked=key_locked,
            audit_event_ids=tuple(event.event_id for event in audit_events),
        )

