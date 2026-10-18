"""Use-case boundary for validated audit recording and session reconstruction."""

from quantum_keyguard.domain.audit import AuditEvent
from quantum_keyguard.persistence.audit_repository import AuditRepository


class AuditService:
    def __init__(self, repository: AuditRepository) -> None:
        self.repository = repository

    def record(self, event: AuditEvent) -> AuditEvent:
        """Persist already validated, secret-free audit metadata."""
        return self.repository.append(event)

    def session_timeline(self, session_id: str) -> list[AuditEvent]:
        """Return the ordered events consumed later by policy and behavioral AI."""
        return self.repository.list_by_session(session_id)

