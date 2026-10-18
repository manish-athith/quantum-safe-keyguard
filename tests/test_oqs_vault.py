"""Native ML-KEM and ML-DSA integration tests; run on LinuxONE."""

import hmac

import pytest

pytest.importorskip("oqs")

from quantum_keyguard.crypto.oqs_vault import OQSVault, VaultError
from quantum_keyguard.domain.enums import Algorithm, KeyStatus


def test_ml_kem_establishes_matching_shared_secret() -> None:
    with OQSVault() as vault:
        key = vault.create_kem_key("kem_001")
        ciphertext, client_secret = vault.encapsulate(key.public_key)
        server_secret = vault.decapsulate("kem_001", ciphertext)

        assert key.algorithm is Algorithm.ML_KEM_768
        assert hmac.compare_digest(client_secret, server_secret)


def test_ml_dsa_verifies_original_and_rejects_modified_message() -> None:
    with OQSVault() as vault:
        key = vault.create_signature_key("sig_001")
        message = b"rotate finance key"
        signature = vault.sign("sig_001", message)

        assert vault.verify(key.public_key, message, signature) is True
        assert vault.verify(key.public_key, b"export finance key", signature) is False


def test_locked_key_cannot_operate() -> None:
    with OQSVault() as vault:
        vault.create_signature_key("sig_locked")
        vault.lock_key("sig_locked")

        assert vault.public_info("sig_locked").status is KeyStatus.LOCKED
        with pytest.raises(VaultError, match="not active"):
            vault.sign("sig_locked", b"message")


def test_revoked_key_releases_handler_and_cannot_operate() -> None:
    with OQSVault() as vault:
        vault.create_kem_key("kem_revoked")
        vault.revoke_key("kem_revoked")

        assert vault.public_info("kem_revoked").status is KeyStatus.REVOKED
        with pytest.raises(VaultError, match="not active"):
            vault.decapsulate("kem_revoked", b"invalid ciphertext")


def test_vault_has_no_private_key_export_operation() -> None:
    assert not hasattr(OQSVault, "export_private_key")

