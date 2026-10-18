"""In-process liboqs vault adapter with non-exportable application behavior."""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from threading import RLock
from types import ModuleType
from typing import Any

from quantum_keyguard.domain.enums import Algorithm, KeyStatus

KEM_NAME = "ML-KEM-768"
SIGNATURE_NAME = "ML-DSA-65"
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")


class VaultError(RuntimeError):
    """Safe public failure for vault operations."""


class OQSUnavailableError(VaultError):
    """Raised when the native liboqs runtime cannot be loaded."""


@dataclass(frozen=True)
class PublicKeyInfo:
    key_id: str
    algorithm: Algorithm
    status: KeyStatus
    public_key: bytes


@dataclass
class _VaultEntry:
    algorithm: Algorithm
    status: KeyStatus
    public_key: bytes
    handler: Any | None


class OQSVault:
    """Keep liboqs secret-key objects behind a narrow operation-only interface."""

    def __init__(self) -> None:
        try:
            self._oqs: ModuleType = importlib.import_module("oqs")
        except (ImportError, OSError) as error:
            raise OQSUnavailableError("liboqs runtime is unavailable") from error
        enabled_kems = set(self._oqs.get_enabled_kem_mechanisms())
        enabled_signatures = set(self._oqs.get_enabled_sig_mechanisms())
        if KEM_NAME not in enabled_kems or SIGNATURE_NAME not in enabled_signatures:
            raise OQSUnavailableError("required ML-KEM or ML-DSA algorithm is unavailable")
        self._entries: dict[str, _VaultEntry] = {}
        self._lock = RLock()

    @staticmethod
    def _validate_key_id(key_id: str) -> str:
        if not KEY_ID_PATTERN.fullmatch(key_id):
            raise ValueError("invalid key identifier")
        return key_id

    def _entry(self, key_id: str, algorithm: Algorithm) -> _VaultEntry:
        self._validate_key_id(key_id)
        entry = self._entries.get(key_id)
        if entry is None or entry.algorithm is not algorithm:
            raise VaultError("requested key is unavailable")
        if entry.status is not KeyStatus.ACTIVE or entry.handler is None:
            raise VaultError("requested key is not active")
        return entry

    def _store(self, key_id: str, entry: _VaultEntry) -> PublicKeyInfo:
        self._validate_key_id(key_id)
        if key_id in self._entries:
            raise VaultError("key identifier already exists")
        self._entries[key_id] = entry
        return PublicKeyInfo(
            key_id=key_id,
            algorithm=entry.algorithm,
            status=entry.status,
            public_key=entry.public_key,
        )

    def create_kem_key(self, key_id: str) -> PublicKeyInfo:
        with self._lock:
            handler = self._oqs.KeyEncapsulation(KEM_NAME)
            try:
                public_key = bytes(handler.generate_keypair())
                return self._store(
                    key_id,
                    _VaultEntry(
                        algorithm=Algorithm.ML_KEM_768,
                        status=KeyStatus.ACTIVE,
                        public_key=public_key,
                        handler=handler,
                    ),
                )
            except Exception:
                handler.free()
                raise

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        handler = self._oqs.KeyEncapsulation(KEM_NAME)
        try:
            ciphertext, shared_secret = handler.encap_secret(public_key)
            return bytes(ciphertext), bytes(shared_secret)
        finally:
            handler.free()

    def decapsulate(self, key_id: str, ciphertext: bytes) -> bytes:
        with self._lock:
            entry = self._entry(key_id, Algorithm.ML_KEM_768)
            return bytes(entry.handler.decap_secret(ciphertext))

    def create_signature_key(self, key_id: str) -> PublicKeyInfo:
        with self._lock:
            handler = self._oqs.Signature(SIGNATURE_NAME)
            try:
                public_key = bytes(handler.generate_keypair())
                return self._store(
                    key_id,
                    _VaultEntry(
                        algorithm=Algorithm.ML_DSA_65,
                        status=KeyStatus.ACTIVE,
                        public_key=public_key,
                        handler=handler,
                    ),
                )
            except Exception:
                handler.free()
                raise

    def sign(self, key_id: str, message: bytes) -> bytes:
        with self._lock:
            entry = self._entry(key_id, Algorithm.ML_DSA_65)
            return bytes(entry.handler.sign(message))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        handler = self._oqs.Signature(SIGNATURE_NAME)
        try:
            return bool(handler.verify(message, signature, public_key))
        finally:
            handler.free()

    def public_info(self, key_id: str) -> PublicKeyInfo:
        with self._lock:
            self._validate_key_id(key_id)
            entry = self._entries.get(key_id)
            if entry is None:
                raise VaultError("requested key is unavailable")
            return PublicKeyInfo(
                key_id=key_id,
                algorithm=entry.algorithm,
                status=entry.status,
                public_key=entry.public_key,
            )

    def lock_key(self, key_id: str) -> None:
        with self._lock:
            entry = self._entries.get(self._validate_key_id(key_id))
            if entry is None:
                raise VaultError("requested key is unavailable")
            if entry.status is KeyStatus.REVOKED:
                raise VaultError("revoked key cannot be locked")
            entry.status = KeyStatus.LOCKED

    def revoke_key(self, key_id: str) -> None:
        with self._lock:
            entry = self._entries.get(self._validate_key_id(key_id))
            if entry is None:
                raise VaultError("requested key is unavailable")
            if entry.handler is not None:
                entry.handler.free()
                entry.handler = None
            entry.status = KeyStatus.REVOKED

    def close(self) -> None:
        with self._lock:
            for entry in self._entries.values():
                if entry.handler is not None:
                    entry.handler.free()
                    entry.handler = None

    def __enter__(self) -> "OQSVault":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

