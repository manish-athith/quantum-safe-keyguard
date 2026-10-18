"""Authenticated payload-encryption tests."""

import base64

import pytest
from cryptography.exceptions import InvalidTag

from quantum_keyguard.crypto.payload_cipher import (
    SealedPayload,
    open_payload,
    seal_payload,
)


def test_aes_gcm_round_trip_with_associated_data() -> None:
    shared_secret = bytes(range(32))
    associated_data = b"corr_001:key_001"
    sealed = seal_payload(shared_secret, b"protected payload", associated_data)

    assert open_payload(shared_secret, sealed, associated_data) == b"protected payload"


def test_modified_ciphertext_is_rejected() -> None:
    shared_secret = bytes(range(32))
    sealed = seal_payload(shared_secret, b"protected payload", b"context")
    ciphertext = bytearray(base64.b64decode(sealed.ciphertext_b64))
    ciphertext[-1] ^= 1
    modified = SealedPayload(
        salt_b64=sealed.salt_b64,
        nonce_b64=sealed.nonce_b64,
        ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
    )

    with pytest.raises(InvalidTag):
        open_payload(shared_secret, modified, b"context")


def test_wrong_associated_data_is_rejected() -> None:
    shared_secret = bytes(range(32))
    sealed = seal_payload(shared_secret, b"protected payload", b"correct")
    with pytest.raises(InvalidTag):
        open_payload(shared_secret, sealed, b"wrong")

