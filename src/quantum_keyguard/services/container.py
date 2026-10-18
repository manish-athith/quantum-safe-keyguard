"""Application service composition with replaceable cryptography dependency."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from quantum_keyguard.crypto.oqs_vault import OQSVault
from quantum_keyguard.detection.contextual_lstm import ContextualLSTMDetector
from quantum_keyguard.persistence.audit_repository import AuditRepository
from quantum_keyguard.persistence.database import Database
from quantum_keyguard.persistence.state_repository import SecurityStateRepository
from quantum_keyguard.services.auth_service import AuthService
from quantum_keyguard.services.policy_engine import PolicyEngine
from quantum_keyguard.services.protected_operation_service import ProtectedOperationService
from quantum_keyguard.services.response_service import ResponseService


class ServiceContainer:
    def __init__(
        self,
        database_path: str | Path,
        model_path: str | Path,
        *,
        vault_factory: Callable[[], Any] = OQSVault,
        detector: ContextualLSTMDetector | Any | None = None,
    ) -> None:
        self.database = Database(database_path)
        self.database.initialize()
        self.state = SecurityStateRepository(self.database)
        self.retired_ephemeral_keys = self.state.retire_active_ephemeral_keys()
        self.audit = AuditRepository(self.database)
        self.auth = AuthService(self.database)
        self.policy = PolicyEngine()
        self.response = ResponseService(self.database, self.audit)
        self.detector = detector or ContextualLSTMDetector.from_file(model_path)
        self.operations = ProtectedOperationService(
            self.state, self.audit, self.policy, self.response, self.detector
        )
        self._vault_factory = vault_factory
        self._vault: Any | None = None

    @property
    def vault(self) -> Any:
        if self._vault is None:
            self._vault = self._vault_factory()
        return self._vault

    def close(self) -> None:
        if self._vault is not None and hasattr(self._vault, "close"):
            self._vault.close()
            self._vault = None
