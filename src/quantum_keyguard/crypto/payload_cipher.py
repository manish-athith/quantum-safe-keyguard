"""AES-256-GCM payload encryption using a KEM-derived shared secret."""

from __future__ import annotations

import base64
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from quantum_keyguard.domain.common import StrictModel

HKDF_INFO = b"quantum-keyguard-payload-v1"


class SealedPayload(StrictModel):
    salt_b64: str
    nonce_b64: str
    ciphertext_b64: str


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
    if len(shared_secret) < 16:
        raise ValueError("shared secret is too short")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=HKDF_INFO,
    ).derive(shared_secret)


def seal_payload(
    shared_secret: bytes, plaintext: bytes, associated_data: bytes = b""
) -> SealedPayload:
    """Encrypt and authenticate bytes without persisting the shared secret."""
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    aes_key = _derive_aes_key(shared_secret, salt)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, associated_data)
    return SealedPayload(
        salt_b64=_encode(salt),
        nonce_b64=_encode(nonce),
        ciphertext_b64=_encode(ciphertext),
    )


def open_payload(
    shared_secret: bytes, sealed: SealedPayload, associated_data: bytes = b""
) -> bytes:
    """Authenticate and decrypt; modified ciphertext or context raises InvalidTag."""
    salt = _decode(sealed.salt_b64)
    nonce = _decode(sealed.nonce_b64)
    ciphertext = _decode(sealed.ciphertext_b64)
    if len(salt) != 16 or len(nonce) != 12:
        raise ValueError("invalid sealed payload parameters")
    aes_key = _derive_aes_key(shared_secret, salt)
    return AESGCM(aes_key).decrypt(nonce, ciphertext, associated_data)

