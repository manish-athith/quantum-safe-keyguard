"""End-to-end risk, policy, audit, execution, and containment orchestration."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import Field

from quantum_keyguard.detection.contextual_lstm import ContextualLSTMDetector
from quantum_keyguard.domain.audit import AuditEvent
from quantum_keyguard.domain.common import Identifier, StrictModel, utc_now
from quantum_keyguard.domain.enums import (
    Algorithm,
    AuditAction,
    EventOutcome,
    KeyStatus,
    PolicyEffect,
)
from quantum_keyguard.domain.policy import PolicyContext, PolicyDecision
from quantum_keyguard.persistence.audit_repository import AuditRepository
from quantum_keyguard.persistence.state_repository import SecurityStateRepository
from quantum_keyguard.services.auth_service import AuthPrincipal
from quantum_keyguard.services.policy_engine import PolicyEngine
from quantum_keyguard.services.response_service import (
    ContainmentRequest,
    ContainmentResult,
    ResponseService,
)


class OperationNotFoundError(RuntimeError):
    """Requested managed object is absent."""


class OperationResult(StrictModel):
    correlation_id: Identifier
    action: AuditAction
    effect: PolicyEffect
    executed: bool
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    risk_signals: tuple[str, ...] = ()
    triggered_rules: tuple[Identifier, ...]
    explanation: str
    output: dict[str, Any] = Field(default_factory=dict)
    containment: ContainmentResult | None = None


class ProtectedOperationService:
    def __init__(
        self,
        state: SecurityStateRepository,
        audit: AuditRepository,
        policy: PolicyEngine,
        response: ResponseService,
        detector: ContextualLSTMDetector,
    ) -> None:
        self.state = state
        self.audit = audit
        self.policy = policy
        self.response = response
        self.detector = detector

    def _session_features(
        self,
        principal: AuthPrincipal,
        action: AuditAction,
        algorithm: Algorithm | None,
        occurred_at: datetime,
    ) -> dict[str, Any]:
        history = self.audit.list_by_session(principal.session_id)
        actions = [event.action.value for event in history]
        hours = [event.occurred_at.hour for event in history]
        algorithms = [event.algorithm.value if event.algorithm else None for event in history]
        outcomes = [event.outcome.value for event in history]
        devices = [event.device_id != principal.device_id for event in history]
        intervals: list[int] = []
        previous: datetime | None = None
        for event in history:
            intervals.append(
                0 if previous is None else max(0, int((event.occurred_at - previous).total_seconds()))
            )
            previous = event.occurred_at
        pending_interval = (
            0 if previous is None else max(0, int((occurred_at - previous).total_seconds()))
        )
        actions.append(action.value)
        hours.append(occurred_at.hour)
        intervals.append(pending_interval)
        devices.append(principal.is_new_device)
        algorithms.append(algorithm.value if algorithm else None)
        outcomes.append(EventOutcome.ALLOWED.value)  # ignored for the pending step
        return {
            "actions": actions,
            "role": principal.role.value,
            "hours": hours,
            "interval_seconds": intervals,
            "is_new_device": devices,
            "algorithms": algorithms,
            "outcomes": outcomes,
        }

    def run(
        self,
        principal: AuthPrincipal,
        *,
        action: AuditAction,
        key_id: str | None = None,
        algorithm: Algorithm | None = None,
        execute: Callable[[], dict[str, Any]] | None = None,
    ) -> OperationResult:
        occurred_at = utc_now()
        correlation_id = f"corr_{uuid4().hex}"
        session = self.state.get_session(principal.session_id)
        if session is None:
            raise OperationNotFoundError("session not found")
        key = self.state.get_key(key_id) if key_id else None
        if key_id and key is None:
            raise OperationNotFoundError("managed key not found")
        key_status = key.status if key else None
        selected_algorithm = algorithm or (key.algorithm if key else None)

        base_context = {
            "correlation_id": correlation_id,
            "session_id": principal.session_id,
            "user_id": principal.user_id,
            "role": principal.role,
            "action": action,
            "session_status": session.status,
            "source_ip": principal.source_ip,
            "device_id": principal.device_id,
            "key_id": key_id,
            "key_status": key_status,
            "algorithm": selected_algorithm,
            "hour": occurred_at.hour,
            "is_new_device": principal.is_new_device,
        }
        pre_decision = self.policy.evaluate(PolicyContext.model_validate(base_context))
        assessment = self.detector.score_session(
            self._session_features(principal, action, selected_algorithm, occurred_at)
        )
        final_context = dict(base_context)
        final_context["anomaly_score"] = assessment.risk_score
        decision = self.policy.evaluate(PolicyContext.model_validate(final_context))
        if pre_decision.effect in {PolicyEffect.DENY, PolicyEffect.CONTAIN}:
            decision = PolicyDecision(
                effect=pre_decision.effect,
                triggered_rules=pre_decision.triggered_rules,
                explanation=pre_decision.explanation,
                risk_score=assessment.risk_score,
            )

        output: dict[str, Any] = {}
        executed = False
        outcome = EventOutcome.DENIED
        reason_code = decision.triggered_rules[0]
        if decision.effect is PolicyEffect.ALLOW:
            try:
                output = execute() if execute else {}
                executed = True
                outcome = EventOutcome.ALLOWED
            except Exception:
                outcome = EventOutcome.FAILED
                reason_code = "operation_failed"
                self._append_event(
                    principal, action, key_id, selected_algorithm, correlation_id,
                    occurred_at, outcome, reason_code, assessment.risk_score,
                    decision, assessment.signals,
                )
                raise

        self._append_event(
            principal, action, key_id, selected_algorithm, correlation_id,
            occurred_at, outcome, reason_code, assessment.risk_score,
            decision, assessment.signals,
        )
        containment = None
        if decision.effect is PolicyEffect.CONTAIN:
            containment = self.response.contain(
                ContainmentRequest(
                    correlation_id=correlation_id,
                    session_id=principal.session_id,
                    user_id=principal.user_id,
                    role=principal.role,
                    source_ip=principal.source_ip,
                    device_id=principal.device_id,
                    key_id=key_id,
                    occurred_at=occurred_at,
                ),
                decision,
            )
        return OperationResult(
            correlation_id=correlation_id,
            action=action,
            effect=decision.effect,
            executed=executed,
            risk_score=assessment.risk_score,
            risk_signals=assessment.signals,
            triggered_rules=decision.triggered_rules,
            explanation=decision.explanation,
            output=output,
            containment=containment,
        )

    def _append_event(
        self,
        principal: AuthPrincipal,
        action: AuditAction,
        key_id: str | None,
        algorithm: Algorithm | None,
        correlation_id: str,
        occurred_at: datetime,
        outcome: EventOutcome,
        reason_code: str,
        risk_score: float,
        decision: PolicyDecision,
        signals: tuple[str, ...],
    ) -> None:
        self.audit.append(
            AuditEvent(
                correlation_id=correlation_id,
                session_id=principal.session_id,
                user_id=principal.user_id,
                role=principal.role,
                action=action,
                outcome=outcome,
                occurred_at=occurred_at,
                source_ip=principal.source_ip,
                device_id=principal.device_id,
                key_id=key_id,
                algorithm=algorithm,
                reason_code=reason_code,
                risk_score=risk_score,
                context={
                    "policy_effect": decision.effect.value,
                    "triggered_rules": list(decision.triggered_rules),
                    "risk_signals": list(signals),
                },
            )
        )
