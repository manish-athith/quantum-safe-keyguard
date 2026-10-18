"""Authenticated quantum-safe key and attack-demonstration operations."""

from __future__ import annotations

import base64
import binascii
import hmac
from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import Field, field_validator

from quantum_keyguard.api.auth import current_principal, services
from quantum_keyguard.crypto.oqs_vault import OQSUnavailableError, VaultError
from quantum_keyguard.crypto.payload_cipher import open_payload, seal_payload
from quantum_keyguard.domain.common import Identifier, StrictModel
from quantum_keyguard.domain.enums import Algorithm, AuditAction, KeyStatus, Role
from quantum_keyguard.domain.records import KeyRecord
from quantum_keyguard.services.auth_service import AuthPrincipal
from quantum_keyguard.services.container import ServiceContainer
from quantum_keyguard.services.protected_operation_service import (
    OperationNotFoundError,
    OperationResult,
)

router = APIRouter(tags=["protected operations"])


class CreateKeyRequest(StrictModel):
    key_id: Identifier
    algorithm: Algorithm

    @field_validator("algorithm")
    @classmethod
    def supported_algorithm(cls, value: Algorithm) -> Algorithm:
        if value not in {Algorithm.ML_KEM_768, Algorithm.ML_DSA_65}:
            raise ValueError("only ML-KEM-768 and ML-DSA-65 keys are supported")
        return value


class MessageRequest(StrictModel):
    message: str = Field(min_length=1, max_length=4096)


class VerifyRequest(MessageRequest):
    signature_b64: str = Field(min_length=8, max_length=20_000)


class ProtectRequest(StrictModel):
    plaintext: str = Field(min_length=1, max_length=4096)
    context: str = Field(default="quantum-keyguard-demo", min_length=1, max_length=256)


class RotateKeyRequest(StrictModel):
    new_key_id: Identifier


class DemoAttemptRequest(StrictModel):
    action: AuditAction
    key_id: Identifier | None = None
    algorithm: Algorithm | None = None

    @field_validator("action")
    @classmethod
    def demo_actions_only(cls, value: AuditAction) -> AuditAction:
        allowed = {
            AuditAction.ACCESS_MASTER_KEY,
            AuditAction.EXPORT_PRIVATE_KEY,
            AuditAction.DOWNGRADE_ALGORITHM,
            AuditAction.DELETE_AUDIT_LOGS,
        }
        if value not in allowed:
            raise ValueError("action is not available through the attack simulator")
        return value


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as error:
        raise HTTPException(status_code=422, detail="invalid base64 signature") from error


def _safe_run(operation: Callable[[], OperationResult]) -> OperationResult:
    try:
        return operation()
    except OperationNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except (OQSUnavailableError, VaultError) as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@router.get("/keys", response_model=OperationResult)
def list_keys(
    principal: AuthPrincipal = Depends(current_principal),
    container: ServiceContainer = Depends(services),
) -> OperationResult:
    def execute() -> dict[str, object]:
        keys = [item.model_dump(mode="json") for item in container.state.list_keys()]
        return {"keys": keys}

    return _safe_run(
        lambda: container.operations.run(
            principal, action=AuditAction.LIST_KEYS, execute=execute
        )
    )


@router.post("/keys", response_model=OperationResult)
def create_key(
    payload: CreateKeyRequest,
    principal: AuthPrincipal = Depends(current_principal),
    container: ServiceContainer = Depends(services),
) -> OperationResult:
    def execute() -> dict[str, object]:
        if payload.algorithm is Algorithm.ML_KEM_768:
            public = container.vault.create_kem_key(payload.key_id)
        else:
            public = container.vault.create_signature_key(payload.key_id)
        container.state.save_key(
            KeyRecord(
                key_id=payload.key_id,
                algorithm=payload.algorithm,
                owner_role=Role.KEY_ADMIN,
            )
        )
        return {
            "key_id": public.key_id,
            "algorithm": public.algorithm.value,
            "status": public.status.value,
            "public_key_b64": _encode(public.public_key),
        }

    return _safe_run(
        lambda: container.operations.run(
            principal,
            action=AuditAction.CREATE_KEY,
            algorithm=payload.algorithm,
            execute=execute,
        )
    )


@router.post("/keys/{key_id}/sign", response_model=OperationResult)
def sign(
    key_id: str,
    payload: MessageRequest,
    principal: AuthPrincipal = Depends(current_principal),
    container: ServiceContainer = Depends(services),
) -> OperationResult:
    return _safe_run(
        lambda: container.operations.run(
            principal,
            action=AuditAction.SIGN,
            key_id=key_id,
            execute=lambda: {
                "signature_b64": _encode(
                    container.vault.sign(key_id, payload.message.encode("utf-8"))
                )
            },
        )
    )


@router.post("/keys/{key_id}/verify", response_model=OperationResult)
def verify(
    key_id: str,
    payload: VerifyRequest,
    principal: AuthPrincipal = Depends(current_principal),
    container: ServiceContainer = Depends(services),
) -> OperationResult:
    signature = _decode(payload.signature_b64)

    def execute() -> dict[str, object]:
        public = container.vault.public_info(key_id)
        return {
            "valid": container.vault.verify(
                public.public_key, payload.message.encode("utf-8"), signature
            )
        }

    return _safe_run(
        lambda: container.operations.run(
            principal, action=AuditAction.VERIFY, key_id=key_id, execute=execute
        )
    )


@router.post("/keys/{key_id}/protect", response_model=OperationResult)
def protect(
    key_id: str,
    payload: ProtectRequest,
    principal: AuthPrincipal = Depends(current_principal),
    container: ServiceContainer = Depends(services),
) -> OperationResult:
    def execute() -> dict[str, object]:
        public = container.vault.public_info(key_id)
        ciphertext, client_secret = container.vault.encapsulate(public.public_key)
        server_secret = container.vault.decapsulate(key_id, ciphertext)
        if not hmac.compare_digest(client_secret, server_secret):
            raise VaultError("ML-KEM shared-secret agreement failed")
        associated_data = payload.context.encode("utf-8")
        sealed = seal_payload(client_secret, payload.plaintext.encode("utf-8"), associated_data)
        recovered = open_payload(server_secret, sealed, associated_data)
        return {
            "kem_ciphertext_b64": _encode(ciphertext),
            "sealed_payload": sealed.model_dump(),
            "roundtrip_verified": hmac.compare_digest(
                recovered, payload.plaintext.encode("utf-8")
            ),
        }

    return _safe_run(
        lambda: container.operations.run(
            principal,
            action=AuditAction.KEM_ENCAPSULATE,
            key_id=key_id,
            execute=execute,
        )
    )


@router.post("/keys/{key_id}/rotate", response_model=OperationResult)
def rotate(
    key_id: str,
    payload: RotateKeyRequest,
    principal: AuthPrincipal = Depends(current_principal),
    container: ServiceContainer = Depends(services),
) -> OperationResult:
    existing = container.state.get_key(key_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="managed key not found")

    def execute() -> dict[str, object]:
        container.vault.revoke_key(key_id)
        container.state.set_key_status(key_id, KeyStatus.REVOKED)
        if existing.algorithm is Algorithm.ML_KEM_768:
            public = container.vault.create_kem_key(payload.new_key_id)
        else:
            public = container.vault.create_signature_key(payload.new_key_id)
        container.state.save_key(
            KeyRecord(
                key_id=payload.new_key_id,
                algorithm=existing.algorithm,
                owner_role=existing.owner_role,
            )
        )
        return {
            "old_key_id": key_id,
            "old_status": KeyStatus.REVOKED.value,
            "new_key_id": public.key_id,
            "algorithm": public.algorithm.value,
            "public_key_b64": _encode(public.public_key),
        }

    return _safe_run(
        lambda: container.operations.run(
            principal,
            action=AuditAction.ROTATE_KEY,
            key_id=key_id,
            execute=execute,
        )
    )


@router.post("/keys/{key_id}/lock", response_model=OperationResult)
def lock(
    key_id: str,
    principal: AuthPrincipal = Depends(current_principal),
    container: ServiceContainer = Depends(services),
) -> OperationResult:
    def execute() -> dict[str, object]:
        container.vault.lock_key(key_id)
        container.state.set_key_status(key_id, KeyStatus.LOCKED)
        return {"key_id": key_id, "status": KeyStatus.LOCKED.value}

    return _safe_run(
        lambda: container.operations.run(
            principal, action=AuditAction.LOCK_KEY, key_id=key_id, execute=execute
        )
    )


@router.post("/keys/{key_id}/revoke", response_model=OperationResult)
def revoke(
    key_id: str,
    principal: AuthPrincipal = Depends(current_principal),
    container: ServiceContainer = Depends(services),
) -> OperationResult:
    def execute() -> dict[str, object]:
        container.vault.revoke_key(key_id)
        container.state.set_key_status(key_id, KeyStatus.REVOKED)
        return {"key_id": key_id, "status": KeyStatus.REVOKED.value}

    return _safe_run(
        lambda: container.operations.run(
            principal, action=AuditAction.REVOKE_KEY, key_id=key_id, execute=execute
        )
    )


@router.post("/demo/attempt", response_model=OperationResult)
def demo_attempt(
    payload: DemoAttemptRequest,
    principal: AuthPrincipal = Depends(current_principal),
    container: ServiceContainer = Depends(services),
) -> OperationResult:
    result = _safe_run(
        lambda: container.operations.run(
            principal,
            action=payload.action,
            key_id=payload.key_id,
            algorithm=payload.algorithm,
            execute=lambda: {"simulated": True},
        )
    )
    if result.containment and payload.key_id:
        try:
            container.vault.lock_key(payload.key_id)
        except VaultError:
            pass
    return result
