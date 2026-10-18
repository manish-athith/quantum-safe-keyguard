"""Tests for deterministic policy precedence and explainability."""

from quantum_keyguard.domain.enums import (
    Algorithm,
    AuditAction,
    KeyStatus,
    PolicyEffect,
    Role,
    SessionStatus,
)
from quantum_keyguard.domain.policy import PolicyContext
from quantum_keyguard.services.policy_engine import PolicyEngine


def context(**overrides: object) -> PolicyContext:
    values: dict[str, object] = {
        "correlation_id": "corr_001",
        "session_id": "sess_001",
        "user_id": "admin_001",
        "role": Role.KEY_ADMIN,
        "action": AuditAction.ROTATE_KEY,
        "session_status": SessionStatus.ACTIVE,
        "source_ip": "192.0.2.10",
        "device_id": "device_001",
        "key_id": "key_001",
        "key_status": KeyStatus.ACTIVE,
        "algorithm": Algorithm.ML_DSA_65,
        "hour": 11,
        "is_new_device": False,
        "anomaly_score": 0.05,
    }
    values.update(overrides)
    return PolicyContext.model_validate(values)


def test_private_key_export_contains_even_with_low_ai_score() -> None:
    decision = PolicyEngine().evaluate(
        context(action=AuditAction.EXPORT_PRIVATE_KEY, anomaly_score=0.0)
    )
    assert decision.effect is PolicyEffect.CONTAIN
    assert decision.triggered_rules == ("rule_private_export",)


def test_high_ai_score_challenges_but_does_not_override_hard_policy() -> None:
    decision = PolicyEngine().evaluate(context(anomaly_score=0.95))
    assert decision.effect is PolicyEffect.CHALLENGE
    assert decision.triggered_rules == ("rule_high_anomaly_score",)


def test_revoked_session_is_denied_before_operation() -> None:
    decision = PolicyEngine().evaluate(context(session_status=SessionStatus.REVOKED))
    assert decision.effect is PolicyEffect.DENY
    assert decision.triggered_rules == ("rule_session_inactive",)


def test_role_permission_is_enforced() -> None:
    decision = PolicyEngine().evaluate(
        context(role=Role.VIEWER, action=AuditAction.SIGN)
    )
    assert decision.effect is PolicyEffect.DENY
    assert decision.triggered_rules == ("rule_role_permission",)


def test_new_device_outside_working_hours_requires_challenge() -> None:
    decision = PolicyEngine().evaluate(
        context(is_new_device=True, hour=23, anomaly_score=0.2)
    )
    assert decision.effect is PolicyEffect.CHALLENGE
    assert decision.triggered_rules == ("rule_new_device_off_hours",)

