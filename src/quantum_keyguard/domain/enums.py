"""Shared enumerations used across APIs, storage, policy, and AI."""

from enum import Enum


class Role(str, Enum):
    VIEWER = "viewer"
    KEY_OPERATOR = "key_operator"
    KEY_ADMIN = "key_admin"
    SECURITY_ANALYST = "security_analyst"
    SYSTEM_SERVICE = "system_service"


class SessionStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class KeyStatus(str, Enum):
    ACTIVE = "active"
    LOCKED = "locked"
    REVOKED = "revoked"


class Algorithm(str, Enum):
    ML_KEM_768 = "ML-KEM-768"
    ML_DSA_65 = "ML-DSA-65"
    AES_256_GCM = "AES-256-GCM"
    RSA_1024 = "RSA-1024"


class AuditAction(str, Enum):
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    LIST_KEYS = "LIST_KEYS"
    CREATE_KEY = "CREATE_KEY"
    ROTATE_KEY = "ROTATE_KEY"
    SIGN = "SIGN"
    VERIFY = "VERIFY"
    KEM_ENCAPSULATE = "KEM_ENCAPSULATE"
    KEM_DECAPSULATE = "KEM_DECAPSULATE"
    ACCESS_MASTER_KEY = "ACCESS_MASTER_KEY"
    EXPORT_PRIVATE_KEY = "EXPORT_PRIVATE_KEY"
    DOWNGRADE_ALGORITHM = "DOWNGRADE_ALGORITHM"
    DELETE_AUDIT_LOGS = "DELETE_AUDIT_LOGS"
    LOCK_KEY = "LOCK_KEY"
    REVOKE_KEY = "REVOKE_KEY"
    REVOKE_SESSION = "REVOKE_SESSION"


class EventOutcome(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    FAILED = "failed"


class PolicyEffect(str, Enum):
    ALLOW = "allow"
    CHALLENGE = "challenge"
    DENY = "deny"
    CONTAIN = "contain"


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

