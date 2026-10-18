"""Deterministic policy rules that cannot be overridden by behavioral AI."""

from __future__ import annotations

from quantum_keyguard.domain.enums import (
    Algorithm,
    AuditAction,
    KeyStatus,
    PolicyEffect,
    Role,
    SessionStatus,
)
from quantum_keyguard.domain.policy import PolicyContext, PolicyDecision

ROLE_PERMISSIONS: dict[Role, frozenset[AuditAction]] = {
    Role.VIEWER: frozenset({AuditAction.LOGIN, AuditAction.LOGOUT, AuditAction.LIST_KEYS}),
    Role.KEY_OPERATOR: frozenset(
        {
            AuditAction.LOGIN,
            AuditAction.LOGOUT,
            AuditAction.LIST_KEYS,
            AuditAction.SIGN,
            AuditAction.VERIFY,
            AuditAction.KEM_ENCAPSULATE,
            AuditAction.KEM_DECAPSULATE,
        }
    ),
    Role.KEY_ADMIN: frozenset(
        {
            AuditAction.LOGIN,
            AuditAction.LOGOUT,
            AuditAction.LIST_KEYS,
            AuditAction.CREATE_KEY,
            AuditAction.ROTATE_KEY,
            AuditAction.SIGN,
            AuditAction.VERIFY,
            AuditAction.KEM_ENCAPSULATE,
            AuditAction.KEM_DECAPSULATE,
            AuditAction.ACCESS_MASTER_KEY,
            AuditAction.LOCK_KEY,
            AuditAction.REVOKE_KEY,
        }
    ),
    Role.SECURITY_ANALYST: frozenset(
        {
            AuditAction.LOGIN,
            AuditAction.LOGOUT,
            AuditAction.LIST_KEYS,
            AuditAction.LOCK_KEY,
            AuditAction.REVOKE_KEY,
            AuditAction.REVOKE_SESSION,
        }
    ),
    Role.SYSTEM_SERVICE: frozenset(
        {
            AuditAction.LOGIN,
            AuditAction.LOGOUT,
            AuditAction.LIST_KEYS,
            AuditAction.SIGN,
            AuditAction.VERIFY,
            AuditAction.KEM_ENCAPSULATE,
            AuditAction.KEM_DECAPSULATE,
        }
    ),
}

HARD_CONTAINMENT_RULES: dict[AuditAction, tuple[str, str]] = {
    AuditAction.EXPORT_PRIVATE_KEY: (
        "rule_private_export",
        "Private-key export is forbidden.",
    ),
    AuditAction.DOWNGRADE_ALGORITHM: (
        "rule_weak_algorithm",
        "Cryptographic downgrade attempts are forbidden.",
    ),
    AuditAction.DELETE_AUDIT_LOGS: (
        "rule_evidence_tampering",
        "Audit evidence deletion is forbidden.",
    ),
}


class PolicyEngine:
    """Evaluate security invariants before a protected operation executes."""

    def __init__(self, anomaly_challenge_threshold: float = 0.85) -> None:
        if not 0.0 < anomaly_challenge_threshold <= 1.0:
            raise ValueError("anomaly threshold must be in (0, 1]")
        self.anomaly_challenge_threshold = anomaly_challenge_threshold

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        if context.session_status is not SessionStatus.ACTIVE:
            return PolicyDecision(
                effect=PolicyEffect.DENY,
                triggered_rules=("rule_session_inactive",),
                explanation="The session is revoked or expired.",
                risk_score=context.anomaly_score,
            )

        if context.key_status in {KeyStatus.LOCKED, KeyStatus.REVOKED}:
            return PolicyDecision(
                effect=PolicyEffect.DENY,
                triggered_rules=("rule_key_inactive",),
                explanation="The requested key is locked or revoked.",
                risk_score=context.anomaly_score,
            )

        hard_rule = HARD_CONTAINMENT_RULES.get(context.action)
        if hard_rule:
            rule_id, explanation = hard_rule
            return PolicyDecision(
                effect=PolicyEffect.CONTAIN,
                triggered_rules=(rule_id,),
                explanation=explanation,
                risk_score=context.anomaly_score,
            )

        if context.algorithm is Algorithm.RSA_1024:
            return PolicyDecision(
                effect=PolicyEffect.CONTAIN,
                triggered_rules=("rule_weak_algorithm",),
                explanation="RSA-1024 is not an approved algorithm.",
                risk_score=context.anomaly_score,
            )

        if context.action not in ROLE_PERMISSIONS[context.role]:
            return PolicyDecision(
                effect=PolicyEffect.DENY,
                triggered_rules=("rule_role_permission",),
                explanation="The caller's role does not permit this operation.",
                risk_score=context.anomaly_score,
            )

        if (
            context.anomaly_score is not None
            and context.anomaly_score >= self.anomaly_challenge_threshold
        ):
            return PolicyDecision(
                effect=PolicyEffect.CHALLENGE,
                triggered_rules=("rule_high_anomaly_score",),
                explanation="Behavioral risk exceeds the step-up threshold.",
                risk_score=context.anomaly_score,
            )

        if context.is_new_device and (context.hour < 6 or context.hour >= 22):
            return PolicyDecision(
                effect=PolicyEffect.CHALLENGE,
                triggered_rules=("rule_new_device_off_hours",),
                explanation="A new device is operating outside normal hours.",
                risk_score=context.anomaly_score,
            )

        return PolicyDecision(
            effect=PolicyEffect.ALLOW,
            triggered_rules=("rule_authorized_operation",),
            explanation="Session, key state, role, and policy checks passed.",
            risk_score=context.anomaly_score,
        )

